// SPDX-License-Identifier: Apache-2.0
//! MQTT transport — subscribe to a topic and take each message payload as a frame.
//! Common for IoT and modern sensor buses. Requires the `mqtt` feature. The client
//! reconnects underneath us; one published message is one frame.

use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};

use crate::runtime::FrameSource;

/// Subscribes to an MQTT topic and yields message payloads as frames.
pub struct MqttSource {
    client: AsyncClient,
    eventloop: EventLoop,
    topic: String,
    subscribed: bool,
}

#[async_trait::async_trait]
impl FrameSource for MqttSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.subscribed {
                self.client
                    .subscribe(&self.topic, QoS::AtMostOnce)
                    .await
                    .map_err(std::io::Error::other)?;
                self.subscribed = true;
            }
            match self.eventloop.poll().await {
                Ok(Event::Incoming(Packet::Publish(p))) => {
                    let n = p.payload.len().min(buf.len());
                    buf[..n].copy_from_slice(&p.payload[..n]);
                    return Ok(n);
                }
                // Keep-alives, acks, and the like — not frames.
                Ok(_) => continue,
                Err(e) => {
                    // The event loop reconnects; re-subscribe when it does.
                    tracing::warn!(error = %e, "mqtt connection error, reconnecting");
                    self.subscribed = false;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }

    fn describe(&self) -> String {
        format!("mqtt {}", self.topic)
    }
}

/// Build an MQTT source. `host` is `host:port`; the connection opens lazily on the
/// first read.
pub fn open(host: &str, topic: &str) -> anyhow::Result<MqttSource> {
    let (hostname, port) = match host.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse()
                .map_err(|_| anyhow::anyhow!("mqtt host port '{p}'"))?,
        ),
        None => (host.to_string(), 1883),
    };
    let mut opts = MqttOptions::new("ajar-connector", hostname, port);
    opts.set_keep_alive(std::time::Duration::from_secs(30));
    let (client, eventloop) = AsyncClient::new(opts, 64);
    Ok(MqttSource {
        client,
        eventloop,
        topic: topic.to_string(),
        subscribed: false,
    })
}
