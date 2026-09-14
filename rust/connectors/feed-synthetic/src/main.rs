// SPDX-License-Identifier: Apache-2.0
//! `ajar-feed-synthetic`: one scenario, six sensors, on every connector's real
//! wire format.
//!
//! A synthetic multi-sensor feed a fusion partner can build against with no
//! hardware. Every sensor here is read by a real connector on its real wire
//! format; only the thing plugged into each connector's input is simulated, so
//! swapping a generator for actual kit changes nothing else. The world the six
//! render is shared (see `scenario`), so the same vessel is seen by AIS and by
//! radar, the same aircraft by ADS-B and by a system track, and an emitter on
//! the vessel by an ESM receiver: real association work, with a real answer.
//!
//! Each generator is proven against the decoder that will read it, in this
//! workspace, so the two cannot drift apart without a test failing.
//!
//! ```text
//! ajar-feed-synthetic all                 # every sensor, on its default port
//! ajar-feed-synthetic ais adsb            # a subset
//! ajar-feed-synthetic --dry-run --ticks 2 # print what would go on the wire, open nothing
//! ```
//!
//! Where each feed goes, and which connector transport reads it:
//!
//! | sensor  | wire                      | connector  | transport            |
//! |---------|---------------------------|------------|----------------------|
//! | asterix | UDP multicast 232.1.1.1:8600 | asterix | udp-multicast        |
//! | cot     | UDP multicast 239.2.3.1:6969 | tak-cot | udp-multicast        |
//! | mavlink | UDP to 127.0.0.1:14550    | mavlink    | udp                  |
//! | adsb    | TCP server on :30003      | adsb       | tcp-client, line     |
//! | ais     | TCP server on :30160      | ais-nmea   | tcp-client, line     |
//! | esm     | TCP server on :30155      | generic    | tcp-client, line     |
//!
//! `--bind IP` moves every TCP server and multicast send onto one interface,
//! for a dual-homed box; `--mavlink-to HOST:PORT` retargets the one unicast
//! feed, since a connector elsewhere on the network needs it sent there.

mod adsb;
mod ais;
mod asterix;
mod cot;
mod esm;
mod mavlink;
mod scenario;

use std::net::{Ipv4Addr, SocketAddr};
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
/// How often the vessel repeats her static report. Real transponders send it
/// every six minutes; a demonstration should not make a consumer wait that
/// long to learn who she is.
const AIS_STATIC_EVERY: u32 = 15;

struct Options {
    sensors: Vec<Sensor>,
    bind: Ipv4Addr,
    mavlink_to: String,
    dry_run: bool,
    ticks: Option<u64>,
}

fn usage() -> ! {
    eprintln!(
        "usage: ajar-feed-synthetic [all | ais adsb asterix mavlink cot esm ...] \
         [--bind IP] [--mavlink-to HOST:PORT] [--dry-run] [--ticks N]"
    );
    std::process::exit(2)
}

fn parse_args() -> Options {
    let mut o = Options {
        sensors: Vec::new(),
        bind: Ipv4Addr::UNSPECIFIED,
        mavlink_to: MAVLINK_TO.to_string(),
        dry_run: false,
        ticks: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "all" => o.sensors = ALL.to_vec(),
            "ais" => o.sensors.push(Sensor::Ais),
            "adsb" => o.sensors.push(Sensor::Adsb),
            "asterix" => o.sensors.push(Sensor::Asterix),
            "mavlink" => o.sensors.push(Sensor::Mavlink),
            "cot" => o.sensors.push(Sensor::Cot),
            "esm" => o.sensors.push(Sensor::Esm),
            "--bind" => {
                o.bind = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--mavlink-to" => o.mavlink_to = args.next().unwrap_or_else(|| usage()),
            "--dry-run" => o.dry_run = true,
            "--ticks" => o.ticks = args.next().and_then(|v| v.parse().ok()).or_else(|| usage()),
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }
    if o.sensors.is_empty() {
        o.sensors = ALL.to_vec();
    }
    o.sensors.dedup();
    o
}

const ALL: [Sensor; 6] = [
    Sensor::Asterix,
    Sensor::Ais,
    Sensor::Adsb,
    Sensor::Mavlink,
    Sensor::Cot,
    Sensor::Esm,
];

/// The scenario clock: seconds since start, and the source's own observation
/// time for a sensor, which lags by that sensor's latency.
#[derive(Clone)]
struct Clock {
    start: Instant,
}

impl Clock {
    fn secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
    fn observed(&self, s: Sensor) -> SystemTime {
        s.observed(SystemTime::now())
    }
}

/// Where a sensor's bytes go. A TCP server fans one stream out to every
/// attached connector; a datagram sender addresses one group or host.
enum Sink {
    Tcp(broadcast::Sender<Arc<[u8]>>),
    Udp(UdpSocket, SocketAddr),
    Stdout(&'static str),
}

impl Sink {
    async fn send(&self, bytes: Vec<u8>) {
        match self {
            // No receiver attached yet is not an error: the feed runs whether or
            // not a connector is listening, as real kit does.
            Sink::Tcp(tx) => {
                let _ = tx.send(Arc::from(bytes));
            }
            Sink::Udp(sock, to) => {
                if let Err(e) = sock.send_to(&bytes, to).await {
                    tracing::warn!(error = %e, to = %to, "datagram send failed");
                }
            }
            Sink::Stdout(name) => {
                let printable = std::str::from_utf8(&bytes)
                    .map(|s| s.trim_end().to_string())
                    .unwrap_or_else(|_| bytes.iter().map(|b| format!("{b:02x}")).collect());
                println!("[{name}] {printable}");
            }
        }
    }
}

/// A TCP server that fans every frame out to each attached connector, and
/// drops a connection that cannot keep up rather than stalling the others.
async fn tcp_fanout(bind: Ipv4Addr, port: u16, name: &'static str) -> anyhow::Result<Sink> {
    let listener = TcpListener::bind((bind, port))
        .await
        .with_context(|| format!("{name}: binding {bind}:{port}"))?;
    tracing::info!(feed = name, addr = %format!("{bind}:{port}"), "tcp feed listening");
    let (tx, _) = broadcast::channel::<Arc<[u8]>>(256);
    let fan = tx.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, peer)) = listener.accept().await else {
                continue;
            };
            tracing::info!(feed = name, %peer, "connector attached");
            let mut rx = fan.subscribe();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(bytes) => {
                            if conn.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(feed = name, %peer, skipped = n, "slow reader, skipping");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                tracing::info!(feed = name, %peer, "connector detached");
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
    if bind != Ipv4Addr::UNSPECIFIED {
        sock.set_multicast_if_v4(&bind)?;
    }
    sock.set_nonblocking(true)?;
    let sock = UdpSocket::from_std(sock.into())?;
    let to = SocketAddr::from(group);
    tracing::info!(feed = name, group = %to, "multicast feed");
    Ok(Sink::Udp(sock, to))
}

async fn unicast(bind: Ipv4Addr, to: &str, name: &'static str) -> anyhow::Result<Sink> {
    let sock = UdpSocket::bind((bind, 0))
        .await
        .with_context(|| format!("{name}: udp bind"))?;
    let to: SocketAddr = tokio::net::lookup_host(to)
        .await
        .with_context(|| format!("{name}: resolving {to}"))?
        .next()
        .with_context(|| format!("{name}: {to} resolves to nothing"))?;
    tracing::info!(feed = name, %to, "unicast feed");
    Ok(Sink::Udp(sock, to))
}

/// Run one sensor until the tick budget runs out (never, in production).
async fn run(sensor: Sensor, sink: Sink, clock: Clock, ticks: Option<u64>) {
    let period = Duration::from_secs_f64(sensor.period());
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut link = mavlink::Link::new();
    let mut n: u64 = 0;
    loop {
        interval.tick().await;
        if ticks.is_some_and(|t| n >= t) {
            return;
        }
        n += 1;
        let secs = clock.secs();
        let observed = clock.observed(sensor);
        match sensor {
            Sensor::Ais => {
                let v = Vessel::at(secs);
                let second = time::OffsetDateTime::from(observed).second();
                sink.send(ais::position_report(&v, second).into_bytes())
                    .await;
                if n % AIS_STATIC_EVERY as u64 == 1 {
                    sink.send(
                        ais::static_report((n / AIS_STATIC_EVERY as u64 % 10) as u8).into_bytes(),
                    )
                    .await;
                }
            }
            Sensor::Adsb => {
                sink.send(adsb::report(&Aircraft::at(secs), observed).into_bytes())
                    .await;
            }
            Sensor::Asterix => {
                let [first, second] =
                    asterix::rotation(&Vessel::at(secs), &Aircraft::at(secs), observed);
                sink.send(first).await;
                sink.send(second).await;
            }
            Sensor::Mavlink => {
                let u = Uav::at(secs);
                // The autopilot's clock: milliseconds since boot, which is the
                // scenario start less this link's latency, never negative.
                let boot = (secs - sensor.latency()).max(0.0);
                sink.send(link.heartbeat()).await;
                sink.send(link.global_position_int(&u, (boot * 1000.0) as u32))
                    .await;
                sink.send(link.gps_raw_int(&u, (boot * 1_000_000.0) as u64))
                    .await;
            }
            Sensor::Cot => {
                sink.send(cot::event(observed).into_bytes()).await;
            }
            Sensor::Esm => {
                sink.send(esm::intercept(&Emitter::at(secs), observed).into_bytes())
                    .await;
            }
        }
    }
}

fn name(s: Sensor) -> &'static str {
    match s {
        Sensor::Ais => "ais",
        Sensor::Adsb => "adsb",
        Sensor::Asterix => "asterix",
        Sensor::Mavlink => "mavlink",
        Sensor::Cot => "cot",
        Sensor::Esm => "esm",
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let opts = parse_args();

    // A silent CRC bug in the MAVLink encoder would look exactly like a dead
    // link, so the encoder proves itself against the connector's reference
    // frame before a single packet leaves.
    mavlink::self_check();

    let clock = Clock {
        start: Instant::now(),
    };
    let mut tasks = Vec::new();
    for s in &opts.sensors {
        let sink = if opts.dry_run {
            Sink::Stdout(name(*s))
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
        tasks.push(tokio::spawn(run(*s, sink, clock.clone(), opts.ticks)));
    }
    tracing::info!(
        sensors = ?opts.sensors.iter().map(|s| name(*s)).collect::<Vec<_>>(),
        "synthetic feed running: one scenario, seen by each"
    );

    let all = async {
        for t in tasks {
            let _ = t.await;
        }
    };
    tokio::select! {
        _ = all => {}
        _ = tokio::signal::ctrl_c() => tracing::info!("stopping"),
    }
    Ok(())
}
