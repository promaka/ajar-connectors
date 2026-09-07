// SPDX-License-Identifier: Apache-2.0
//! Interop probe: subscribe to one DDS topic with the connector's own
//! transport and print the first frames it hands a parser. CI runs it against
//! Fast DDS and Cyclone DDS publishers; a person runs it against a ship's or
//! a robot's bus to see what a topic carries before writing a config.
//!
//! dds_probe <domain> <topic> <type_name> <body|octets|string> <timeout_secs> [count]

use ajar_connector_common::dds::{self, Options};
use ajar_connector_common::{DdsPayload, DdsReliability, FrameSource};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 6 {
        eprintln!("usage: dds_probe <domain> <topic> <type_name> <body|octets|string> <timeout_secs> [count]");
        std::process::exit(2);
    }
    let payload = match a[4].as_str() {
        "body" => DdsPayload::Body,
        "octets" => DdsPayload::Octets,
        "string" => DdsPayload::String,
        other => {
            eprintln!("payload {other:?}: expected body, octets or string");
            std::process::exit(2);
        }
    };
    let want: usize = a.get(6).and_then(|s| s.parse().ok()).unwrap_or(1);
    let timeout = Duration::from_secs(a[5].parse().expect("timeout seconds"));
    let mut source = dds::open(&Options {
        domain: a[1].parse().expect("domain id"),
        topic: a[2].clone(),
        type_name: a[3].clone(),
        reliability: DdsReliability::BestEffort,
        payload,
        interface_ip: None,
    })
    .unwrap_or_else(|e| {
        eprintln!("open: {e:#}");
        std::process::exit(1);
    });
    eprintln!("probing {}", source.describe());
    let mut buf = vec![0u8; 65536];
    let mut got = 0;
    let deadline = tokio::time::Instant::now() + timeout;
    while got < want {
        match tokio::time::timeout_at(deadline, source.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                got += 1;
                let text = String::from_utf8_lossy(&buf[..n]);
                println!("frame {got}: {n} bytes: {text}");
            }
            Ok(Err(e)) => {
                eprintln!("recv: {e}");
                std::process::exit(1);
            }
            Err(_) => {
                eprintln!("no frame within {timeout:?}");
                std::process::exit(1);
            }
        }
    }
}
