// SPDX-License-Identifier: Apache-2.0
//! `ajar-feed-synthetic`: one fixture, six sensors, on every connector's real
//! wire format.
//!
//! A conformance and commissioning source. A fusion consumer builds against
//! it before any equipment arrives, and a site commissions its connectors
//! against it before real feeds are switched in. Every sensor here is read by
//! a real connector on its real wire format; only the thing plugged into each
//! connector's input is synthesised, so replacing a generator with actual
//! equipment changes nothing else. The six render one shared fixture (see
//! `scenario`), so the same vessel is seen by AIS and by radar, the same
//! aircraft by ADS-B and by a system track, and an emitter on the vessel by an
//! ESM receiver.
//!
//! Each generator is proven against the decoder that reads it, in this
//! workspace, so the two cannot drift apart without a test failing. Cadences
//! are the protocols' own: an AIS static report every six minutes per ITU-R
//! M.1371, a radar heartbeat once per rotation.
//!
//! ```text
//! ajar-feed-synthetic all                 # every sensor, on its default port
//! ajar-feed-synthetic ais adsb            # a subset
//! ajar-feed-synthetic --dry-run --ticks 2 # print what would go on the wire, open nothing
//! ```
//!
//! Where each feed goes, and which connector transport reads it:
//!
//! | sensor  | wire                         | connector | transport        |
//! |---------|------------------------------|-----------|------------------|
//! | asterix | UDP multicast 232.1.1.1:8600 | asterix   | udp-multicast    |
//! | cot     | UDP multicast 239.2.3.1:6969 | tak-cot   | udp-multicast    |
//! | mavlink | UDP to 127.0.0.1:14550       | mavlink   | udp              |
//! | adsb    | TCP server on :30003         | adsb      | tcp-client, line |
//! | ais     | TCP server on :30160         | ais-nmea  | tcp-client, line |
//! | esm     | TCP server on :30155         | generic   | tcp-client, line |
//!
//! `--bind IP` moves every TCP server and multicast send onto one interface,
//! for a dual-homed box; `--mavlink-to HOST:PORT` retargets the one unicast
//! feed; `--ais-static-every SECS` shortens the static-report cadence for a
//! commissioning run that should not wait six minutes to learn who the ship
//! is. Every synthetic connector's config should carry `[marking] caveats =
//! ["EXERCISE"]`, so each track says what it is inside its signature.

mod adsb;
mod ais;
mod asterix;
mod cot;
mod esm;
mod mavlink;
mod scenario;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::broadcast;

use scenario::{Aircraft, Emitter, Sensor, Uav, Vessel};

const ASTERIX_GROUP: (Ipv4Addr, u16) = (Ipv4Addr::new(232, 1, 1, 1), 8600);
const COT_GROUP: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 2, 3, 1), 6969);
const ADSB_PORT: u16 = 30003;
const AIS_PORT: u16 = 30160;
const ESM_PORT: u16 = 30155;
const MAVLINK_TO: &str = "127.0.0.1:14550";
/// AIS static and voyage data cadence, seconds: every six minutes per ITU-R
/// M.1371.
const AIS_STATIC_EVERY: Duration = Duration::from_secs(360);
/// The most attached readers one TCP feed serves. A scanner or a misconfigured
/// balancer holding sockets open cannot exhaust the process.
const MAX_READERS: usize = 64;
/// How long a reader may stall on a write before it is dropped. A connector
/// that stopped reading, or a box whose cable was pulled, otherwise parks the
/// task forever.
const WRITE_DEADLINE: Duration = Duration::from_secs(10);
/// How often the unicast target is re-resolved, so a connector container that
/// restarted with a new address keeps receiving.
const RERESOLVE_EVERY: Duration = Duration::from_secs(30);
/// Backoff after a failed accept, so a file-descriptor limit does not spin a
/// worker at full load.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(250);

const ALL: [Sensor; 6] = [
    Sensor::Asterix,
    Sensor::Ais,
    Sensor::Adsb,
    Sensor::Mavlink,
    Sensor::Cot,
    Sensor::Esm,
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
        "usage: ajar-feed-synthetic [all | ais adsb asterix mavlink cot esm ...] \
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
    // Keep the first occurrence of each, in the order given.
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

/// A unicast target re-resolved on a timer, so a peer that restarted with a
/// new address keeps receiving.
struct Unicast {
    sock: UdpSocket,
    host: String,
    to: std::sync::Mutex<(SocketAddr, Instant)>,
}

impl Sink {
    async fn send(&self, bytes: &[u8]) {
        match self {
            // No reader attached is not an error: the feed runs whether or not
            // a connector is listening, as equipment does.
            Sink::Tcp(tx) => {
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

impl Unicast {
    /// The current address, re-resolved when the last lookup is stale. A
    /// lookup that fails keeps the previous address rather than stopping.
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
                tracing::warn!(error = %e, "re-resolving unicast target failed; keeping the last address");
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

/// A TCP server that fans every frame out to each attached reader. A reader
/// that stalls on a write is dropped, and one that cannot keep up skips
/// frames, so no single reader can hold the others back.
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
                    tracing::warn!(feed = name, error = %e, "accept failed; backing off");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            };
            if readers.load(Ordering::Relaxed) >= MAX_READERS {
                tracing::warn!(feed = name, %peer, max = MAX_READERS, "reader limit reached; refusing");
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
                                    tracing::warn!(feed = name, %peer, "reader stalled; dropping it");
                                    break;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(feed = name, %peer, skipped = n, "slow reader, skipping");
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
    // socket2 rather than tokio's socket, because the outgoing interface for
    // multicast is a socket option tokio does not expose, and on a dual-homed
    // box the group has to leave on the surveillance network, not the default
    // route.
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .with_context(|| format!("{name}: udp socket"))?;
    sock.bind(&SocketAddr::from((bind, 0)).into())
        .with_context(|| format!("{name}: binding {bind}"))?;
    sock.set_multicast_ttl_v4(2)?;
    // Loopback on explicitly: a connector on the same box must hear the group
    // even where the host's default is off.
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
        to: std::sync::Mutex::new((addr, Instant::now())),
    }))
}

/// Run one sensor until the tick budget runs out (never, in production).
async fn run(
    sensor: Sensor,
    sink: Sink,
    start: Instant,
    ais_static_every: Duration,
    ticks: Option<u64>,
) {
    let period = Duration::from_secs_f64(sensor.period());
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut link = mavlink::Link::new();
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
                // The autopilot's clock: since boot, which is the start less
                // this link's latency, never negative.
                let boot = (secs - sensor.latency()).max(0.0);
                sink.send(&link.heartbeat()).await;
                sink.send(&link.global_position_int(&u, (boot * 1000.0) as u32))
                    .await;
                sink.send(&link.gps_raw_int(&u, (boot * 1_000_000.0) as u64))
                    .await;
            }
            Sensor::Cot => {
                sink.send(cot::event(observed).as_bytes()).await;
            }
            Sensor::Esm => {
                sink.send(esm::intercept(&Emitter::at(secs), observed).as_bytes())
                    .await;
            }
        }
    }
}

/// SIGTERM or SIGINT, so a container stop is clean rather than a timeout.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
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

    // A wrong CRC would look exactly like a dead link, so the encoder proves
    // itself against the connector's reference frame before a packet leaves.
    mavlink::self_check();

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

    // A generator that panics ends the process with an error rather than
    // leaving five feeds up and one silently missing.
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
