// SPDX-License-Identifier: Apache-2.0
//! `ajar-feed-synthetic`: one shared fixture rendered on every connector's real
//! wire format, for conformance and commissioning. Each generator is tested
//! against the decoder that reads it.

mod adsb;
mod ais;
mod asterix;
mod cot;
mod esm;
mod mavlink;
mod sapient;
mod scenario;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::broadcast;

use scenario::{Aircraft, Emitter, Sensor, Uav, Vessel};

const ASTERIX_GROUP: (Ipv4Addr, u16) = (Ipv4Addr::new(232, 1, 1, 1), 8600);
const COT_GROUP: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 2, 3, 1), 6969);
const ADSB_PORT: u16 = 30003;
const AIS_PORT: u16 = 30160;
const ESM_PORT: u16 = 30155;
const SAPIENT_PORT: u16 = 30335;
const MAVLINK_TO: &str = "127.0.0.1:14550";
/// AIS static and voyage data cadence, per ITU-R M.1371.
const AIS_STATIC_EVERY: Duration = Duration::from_secs(360);
/// Readers one TCP feed serves at most, so held-open sockets cannot exhaust
/// the process.
const MAX_READERS: usize = 64;
/// A reader stalled on a write this long is dropped.
const WRITE_DEADLINE: Duration = Duration::from_secs(10);
/// The unicast target is re-resolved this often, so a peer that restarted on a
/// new address keeps receiving.
const RERESOLVE_EVERY: Duration = Duration::from_secs(30);
/// Pause after a failed accept, so a file-descriptor limit does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(250);

const ALL: [Sensor; 7] = [
    Sensor::Asterix,
    Sensor::Ais,
    Sensor::Adsb,
    Sensor::Mavlink,
    Sensor::Cot,
    Sensor::Esm,
    Sensor::Sapient,
];

struct Options {
    sensors: Vec<Sensor>,
    bind: Ipv4Addr,
    mavlink_to: String,
    ais_static_every: Duration,
    dry_run: bool,
    ticks: Option<u64>,
}

fn usage() -> ! {
    eprintln!(
        "usage: ajar-feed-synthetic [all | ais adsb asterix mavlink cot esm sapient ...] \
         [--bind IP] [--mavlink-to HOST:PORT] [--ais-static-every SECS] [--dry-run] [--ticks N]"
    );
    std::process::exit(2)
}

fn parse_args() -> Options {
    let mut o = Options {
        sensors: Vec::new(),
        bind: Ipv4Addr::UNSPECIFIED,
        mavlink_to: MAVLINK_TO.to_string(),
        ais_static_every: AIS_STATIC_EVERY,
        dry_run: false,
        ticks: None,
    };
    let mut args = std::env::args().skip(1);
    let value = |args: &mut std::iter::Skip<std::env::Args>| args.next().unwrap_or_else(|| usage());
    while let Some(a) = args.next() {
        match a.as_str() {
            "all" => o.sensors.extend(ALL),
            "--bind" => o.bind = value(&mut args).parse().unwrap_or_else(|_| usage()),
            "--mavlink-to" => o.mavlink_to = value(&mut args),
            "--ais-static-every" => {
                let secs: u64 = value(&mut args).parse().unwrap_or_else(|_| usage());
                o.ais_static_every = Duration::from_secs(secs.max(1));
            }
            "--dry-run" => o.dry_run = true,
            "--ticks" => o.ticks = Some(value(&mut args).parse().unwrap_or_else(|_| usage())),
            name => match ALL.iter().find(|s| s.name() == name) {
                Some(s) => o.sensors.push(*s),
                None => usage(),
            },
        }
    }
    if o.sensors.is_empty() {
        o.sensors.extend(ALL);
    }
    let mut seen = Vec::new();
    o.sensors.retain(|s| {
        let new = !seen.contains(s);
        seen.push(*s);
        new
    });
    o
}

/// Where a sensor's bytes go. A TCP server fans one stream out to every
/// attached reader; a datagram sender addresses one group or host.
enum Sink {
    Tcp(broadcast::Sender<Arc<[u8]>>),
    Multicast(UdpSocket, SocketAddr),
    Unicast(Unicast),
    Stdout(&'static str),
}

impl Sink {
    async fn send(&self, bytes: &[u8]) {
        match self {
            Sink::Tcp(tx) => {
                // No reader attached is not an error.
                let _ = tx.send(Arc::from(bytes));
            }
            Sink::Multicast(sock, to) => {
                if let Err(e) = sock.send_to(bytes, to).await {
                    tracing::warn!(error = %e, to = %to, "datagram send failed");
                }
            }
            Sink::Unicast(u) => {
                let to = u.target().await;
                if let Err(e) = u.sock.send_to(bytes, to).await {
                    tracing::warn!(error = %e, to = %to, "datagram send failed");
                }
            }
            Sink::Stdout(name) => {
                let printable = std::str::from_utf8(bytes)
                    .map(|s| s.trim_end().to_string())
                    .unwrap_or_else(|_| bytes.iter().map(|b| format!("{b:02x}")).collect());
                println!("[{name}] {printable}");
            }
        }
    }
}

struct Unicast {
    sock: UdpSocket,
    host: String,
    to: Mutex<(SocketAddr, Instant)>,
}

impl Unicast {
    /// The current address, re-resolved when the last lookup is stale. A
    /// failed lookup keeps the previous address.
    async fn target(&self) -> SocketAddr {
        let (addr, at) = *self.to.lock().expect("target mutex");
        if at.elapsed() < RERESOLVE_EVERY {
            return addr;
        }
        match resolve_v4(&self.host).await {
            Ok(fresh) => {
                if fresh != addr {
                    tracing::info!(from = %addr, to = %fresh, "unicast target moved");
                }
                *self.to.lock().expect("target mutex") = (fresh, Instant::now());
                fresh
            }
            Err(e) => {
                tracing::warn!(error = %e, kept = %addr, "unicast target re-resolve failed");
                self.to.lock().expect("target mutex").1 = Instant::now();
                addr
            }
        }
    }
}

/// The first IPv4 address a name resolves to. The socket is bound v4, and on a
/// dual-stack host a name may list `::1` first.
async fn resolve_v4(host: &str) -> anyhow::Result<SocketAddr> {
    tokio::net::lookup_host(host)
        .await
        .with_context(|| format!("resolving {host}"))?
        .find(SocketAddr::is_ipv4)
        .with_context(|| format!("{host} has no IPv4 address"))
}

/// A TCP server that fans every frame out to each attached reader. A stalled
/// reader is dropped and a slow one skips frames, so none holds the others back.
async fn tcp_fanout(bind: Ipv4Addr, port: u16, name: &'static str) -> anyhow::Result<Sink> {
    let listener = TcpListener::bind((bind, port))
        .await
        .with_context(|| format!("{name}: binding {bind}:{port}"))?;
    tracing::info!(feed = name, addr = %format!("{bind}:{port}"), "tcp feed listening");
    let (tx, _) = broadcast::channel::<Arc<[u8]>>(256);
    let fan = tx.clone();
    let readers = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        loop {
            let (mut conn, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(feed = name, error = %e, "accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            };
            if readers.load(Ordering::Relaxed) >= MAX_READERS {
                tracing::warn!(feed = name, %peer, max = MAX_READERS, "reader limit reached, connection refused");
                continue;
            }
            readers.fetch_add(1, Ordering::Relaxed);
            tracing::info!(feed = name, %peer, "reader attached");
            let mut rx = fan.subscribe();
            let readers = readers.clone();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(bytes) => {
                            match tokio::time::timeout(WRITE_DEADLINE, conn.write_all(&bytes)).await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => break,
                                Err(_) => {
                                    tracing::warn!(feed = name, %peer, "reader stalled, dropped");
                                    break;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(feed = name, %peer, skipped = n, "slow reader skipped frames");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                readers.fetch_sub(1, Ordering::Relaxed);
                tracing::info!(feed = name, %peer, "reader detached");
            });
        }
    });
    Ok(Sink::Tcp(tx))
}

async fn multicast(
    bind: Ipv4Addr,
    group: (Ipv4Addr, u16),
    name: &'static str,
) -> anyhow::Result<Sink> {
    // socket2: tokio does not expose the outgoing multicast interface option.
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .with_context(|| format!("{name}: udp socket"))?;
    sock.bind(&SocketAddr::from((bind, 0)).into())
        .with_context(|| format!("{name}: binding {bind}"))?;
    sock.set_multicast_ttl_v4(2)?;
    // A connector on the same host must hear the group whatever the default.
    sock.set_multicast_loop_v4(true)?;
    if bind != Ipv4Addr::UNSPECIFIED {
        sock.set_multicast_if_v4(&bind)?;
    }
    sock.set_nonblocking(true)?;
    let sock = UdpSocket::from_std(sock.into())?;
    let to = SocketAddr::from(group);
    tracing::info!(feed = name, group = %to, "multicast feed");
    Ok(Sink::Multicast(sock, to))
}

async fn unicast(bind: Ipv4Addr, to: &str, name: &'static str) -> anyhow::Result<Sink> {
    let sock = UdpSocket::bind((bind, 0))
        .await
        .with_context(|| format!("{name}: udp bind"))?;
    let addr = resolve_v4(to).await.with_context(|| name.to_string())?;
    tracing::info!(feed = name, to = %addr, "unicast feed");
    Ok(Sink::Unicast(Unicast {
        sock,
        host: to.to_string(),
        to: Mutex::new((addr, Instant::now())),
    }))
}

/// Run one sensor for `ticks` ticks, or forever.
async fn run(
    sensor: Sensor,
    sink: Sink,
    start: Instant,
    ais_static_every: Duration,
    ticks: Option<u64>,
) {
    let period = Duration::from_secs_f64(sensor.period_s());
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut link = mavlink::Link::default();
    let mut last_static: Option<Instant> = None;
    let mut n: u64 = 0;
    while ticks.map_or(true, |t| n < t) {
        interval.tick().await;
        n += 1;
        let secs = start.elapsed().as_secs_f64();
        let observed = sensor.observed(SystemTime::now());
        match sensor {
            Sensor::Ais => {
                let v = Vessel::at(secs);
                let second = time::OffsetDateTime::from(observed).second();
                sink.send(ais::position_report(&v, second).as_bytes()).await;
                if last_static.map_or(true, |t| t.elapsed() >= ais_static_every) {
                    let seq = (n / 10 % 10) as u8;
                    sink.send(ais::static_report(seq).as_bytes()).await;
                    last_static = Some(Instant::now());
                }
            }
            Sensor::Adsb => {
                sink.send(adsb::report(&Aircraft::at(secs), observed).as_bytes())
                    .await;
            }
            Sensor::Asterix => {
                let [first, second] =
                    asterix::rotation(&Vessel::at(secs), &Aircraft::at(secs), observed);
                sink.send(&first).await;
                sink.send(&second).await;
            }
            Sensor::Mavlink => {
                let u = Uav::at(secs);
                // Autopilot time since boot: elapsed time less the link latency.
                let boot_s = (secs - sensor.latency_s()).max(0.0);
                sink.send(&link.heartbeat()).await;
                sink.send(&link.global_position_int(&u, (boot_s * 1000.0) as u32))
                    .await;
                sink.send(&link.gps_raw_int(&u, (boot_s * 1_000_000.0) as u64))
                    .await;
            }
            Sensor::Cot => {
                sink.send(cot::event(observed).as_bytes()).await;
            }
            Sensor::Esm => {
                sink.send(esm::intercept(&Emitter::at(secs), observed).as_bytes())
                    .await;
            }
            Sensor::Sapient => {
                let registered = n % sapient::REGISTER_EVERY == 1;
                if registered {
                    sink.send(&sapient::registration(observed)).await;
                }
                if n % sapient::STATUS_EVERY == 1 {
                    sink.send(&sapient::status(observed, n, registered)).await;
                }
                sink.send(&sapient::detection(&Uav::at(secs), observed, n))
                    .await;
            }
        }
    }
}

/// Resolves on SIGTERM or SIGINT.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{self, SignalKind};
        let mut term = unix::signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = unix::signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let opts = parse_args();
    let start = Instant::now();
    let mut tasks = Vec::new();
    for s in &opts.sensors {
        let sink = if opts.dry_run {
            Sink::Stdout(s.name())
        } else {
            match s {
                Sensor::Asterix => multicast(opts.bind, ASTERIX_GROUP, "asterix").await?,
                Sensor::Cot => multicast(opts.bind, COT_GROUP, "cot").await?,
                Sensor::Mavlink => unicast(opts.bind, &opts.mavlink_to, "mavlink").await?,
                Sensor::Adsb => tcp_fanout(opts.bind, ADSB_PORT, "adsb").await?,
                Sensor::Ais => tcp_fanout(opts.bind, AIS_PORT, "ais").await?,
                Sensor::Esm => tcp_fanout(opts.bind, ESM_PORT, "esm").await?,
                Sensor::Sapient => tcp_fanout(opts.bind, SAPIENT_PORT, "sapient").await?,
            }
        };
        tasks.push(tokio::spawn(run(
            *s,
            sink,
            start,
            opts.ais_static_every,
            opts.ticks,
        )));
    }
    tracing::info!(
        sensors = ?opts.sensors.iter().map(|s| s.name()).collect::<Vec<_>>(),
        "synthetic feed running"
    );

    // A panicking generator ends the whole process, so no feed goes silently missing.
    let all = async {
        for t in tasks {
            t.await.context("a sensor task failed")?;
        }
        anyhow::Ok(())
    };
    tokio::select! {
        r = all => r?,
        _ = shutdown_signal() => tracing::info!("stopping"),
    }
    Ok(())
}

/// Shared fixtures for the decoder round-trip tests.
#[cfg(test)]
mod fixtures {
    use std::time::{Duration, SystemTime};

    use ajar_connector::Event;

    /// The observation time the generators are given.
    pub fn observed() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_000_000)
    }

    /// `observed()` as RFC 3339.
    pub const OBSERVED: &str = "2026-05-28T20:26:40Z";

    /// The time passed to the decoders' `to_event_at`.
    pub const EVENT_TIME: &str = "2026-06-10T08:00:00Z";

    pub fn attr(ev: &Event, key: &str) -> Option<String> {
        ev.attributes
            .iter()
            .find(|a| a.key == key)
            .map(|a| a.value.clone())
    }

    pub fn meta(ev: &Event, key: &str) -> Option<String> {
        ev.metadata
            .iter()
            .find(|a| a.key == key)
            .map(|a| a.value.clone())
    }

    /// A numeric attribute; panics if it is missing or not a number.
    pub fn num(ev: &Event, key: &str) -> f64 {
        attr(ev, key)
            .unwrap_or_else(|| panic!("no {key}"))
            .parse()
            .unwrap_or_else(|e| panic!("{key}: {e}"))
    }
}
