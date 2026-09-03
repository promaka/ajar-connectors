// SPDX-License-Identifier: Apache-2.0
//! Shared runtime for Ajar connectors.
//!
//! A connector reads a native feed, normalizes each frame into a canonical
//! [`ajar_connector::Event`], seals it with the connector's Ed25519 key, and
//! publishes it to Core's NATS ingest subject. Everything except the parse is the
//! same for every connector, so it lives here: configuration, key loading, the
//! mTLS NATS connection, the field transports, the seal-and-publish loop, the
//! health/metrics endpoint, and graceful shutdown.
//!
//! Writing a new connector is therefore two things:
//! 1. implement [`FrameParser`] for your wire format (the only format-specific work);
//! 2. hand a [`FrameSource`] and the parser to [`run`].
//!
//! ```no_run
//! # use ajar_connector_common as common;
//! # use ajar_connector::Event;
//! # struct MyParser;
//! # impl common::FrameParser for MyParser {
//! #     fn parse(&self, _f: &[u8]) -> Result<Vec<Event>, common::ParseError> { unimplemented!() }
//! # }
//! # async fn go() -> anyhow::Result<()> {
//! let cfg = common::Config::load("connector.toml")?;
//! let source = common::open_source(&cfg.transport).await?;
//! common::run(cfg, source, MyParser).await
//! # }
//! ```

mod config;
pub mod dir;
pub mod exec;
pub mod file;
pub mod health;
pub mod http_server;
pub mod key;
pub mod nats;
pub mod ontology;
pub mod profile;
pub mod replay;
mod runtime;
pub mod spool;
pub mod stdin;
mod stream;
pub mod tcp;
pub mod tcp_server;
pub mod udp;

#[cfg(feature = "mqtt")]
pub mod mqtt;
#[cfg(feature = "rest-poll")]
pub mod rest;
#[cfg(feature = "serial")]
pub mod serial;
#[cfg(feature = "websocket")]
pub mod ws;

/// Largest native frame the runtime will read. A frame beyond this is rejected
/// rather than truncated: half a record parses into a wrong event, which is worse
/// than a missing one. Reported in the connector profile as an advisory ceiling.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

pub use config::{Config, Enrichment, Framing, SensorSite, SpoolSetting, Transport};

/// The seal's signature prefix length (re-exported for the spool drain).
pub(crate) fn seal_signature_len() -> usize {
    ajar_connector::SEAL_SIGNATURE_LEN
}
pub use profile::Profile;
pub use runtime::{run, FrameParser, FrameSource, ParseError};

/// Open the transport named in config, boxed for [`run`]. This is the one line a
/// connector needs to get from a config file to a live feed, whatever the method:
/// the protocol (parsing) never changes when the transport does.
pub async fn open_source(transport: &Transport) -> anyhow::Result<Box<dyn FrameSource>> {
    Ok(match transport {
        Transport::UdpMulticast {
            bind,
            group,
            interface,
        } => Box::new(udp::open(bind, Some(group), interface.as_deref())?),
        Transport::Udp { bind } => Box::new(udp::open(bind, None, None)?),
        Transport::PcapReplay {
            path,
            speed,
            looping,
            port,
            max_gap_ms,
        } => Box::new(replay::open(path, *speed, *looping, *port, *max_gap_ms)?),
        Transport::TcpServer { bind, framing } => Box::new(tcp_server::open(bind, *framing).await?),
        Transport::TcpClient { connect, framing } => Box::new(tcp::open(connect, *framing)?),
        Transport::Dir {
            path,
            process_existing,
        } => Box::new(dir::open(path, *process_existing)?),
        Transport::File { path, from_start } => Box::new(file::open(path, *from_start).await?),
        Transport::Exec { command, args } => Box::new(exec::open(command, args)?),
        Transport::Stdin => Box::new(stdin::open()?),
        Transport::HttpServer {
            bind,
            path,
            token,
            tls_cert,
            tls_key,
            tls_client_ca,
        } => Box::new(
            http_server::open(
                bind,
                path,
                token.clone(),
                http_server::Tls {
                    cert: tls_cert.as_deref(),
                    key: tls_key.as_deref(),
                    client_ca: tls_client_ca.as_deref(),
                },
            )
            .await?,
        ),
        #[cfg(feature = "serial")]
        Transport::Serial { device, baud } => Box::new(serial::open(device, *baud)?),
        #[cfg(feature = "mqtt")]
        Transport::Mqtt { host, topic } => Box::new(mqtt::open(host, topic)?),
        #[cfg(feature = "websocket")]
        Transport::WsClient {
            url,
            subscribe,
            headers,
        } => Box::new(ws::open(url, subscribe.clone(), headers)?),
        #[cfg(feature = "rest-poll")]
        Transport::RestPoll {
            url,
            interval_secs,
            auth_header,
        } => Box::new(rest::open(url, *interval_secs, auth_header.as_deref())?),
    })
}
