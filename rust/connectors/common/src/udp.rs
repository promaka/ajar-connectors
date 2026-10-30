// SPDX-License-Identifier: Apache-2.0
//! UDP transport, multicast or unicast: one datagram is one frame.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::Context as _;
use socket2::{Domain, Protocol, Socket, Type};

use crate::runtime::FrameSource;

pub struct UdpSource {
    sock: tokio::net::UdpSocket,
    describe: String,
}

#[async_trait::async_trait]
impl FrameSource for UdpSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.sock.recv_from(buf).await.map(|(n, _addr)| n)
    }
    fn describe(&self) -> String {
        self.describe.clone()
    }
}

/// Open a UDP source. With `group`, bind the wildcard address on the bind port
/// (binding the group address is non-portable) and join the group on
/// `interface`, else on the bind IP, else where the kernel chooses: a
/// dual-homed box otherwise joins wherever the routing table points. Without
/// `group`, bind as given. `SO_REUSEADDR`/`SO_REUSEPORT` let several receivers
/// share a group.
pub fn open(bind: &str, group: Option<&str>, interface: Option<&str>) -> anyhow::Result<UdpSource> {
    let bind: SocketAddr = bind
        .parse()
        .with_context(|| format!("transport.bind '{bind}'"))?;
    let bind_v4: Ipv4Addr = match bind.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => anyhow::bail!(
            "transport.bind '{bind}': this transport is IPv4-only today; \
             bind an IPv4 address (e.g. 0.0.0.0:{})",
            bind.port()
        ),
    };
    let port = bind.port();

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating the UDP socket")?;
    sock.set_reuse_address(true)
        .context("setting SO_REUSEADDR")?;
    #[cfg(unix)]
    sock.set_reuse_port(true).context("setting SO_REUSEPORT")?;

    let describe = match group {
        Some(group) => {
            let group: Ipv4Addr = group
                .parse()
                .with_context(|| format!("transport.group '{group}'"))?;
            // 0.0.0.0 leaves the choice to the kernel.
            let iface: Ipv4Addr = match interface {
                Some(i) => i
                    .parse()
                    .with_context(|| format!("transport.interface '{i}'"))?,
                None => bind_v4,
            };
            let listen = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
            sock.bind(&listen.into())
                .with_context(|| format!("binding UDP port {port} for group {group}"))?;
            sock.join_multicast_v4(&group, &iface)
                .with_context(|| format!("joining multicast group {group} on interface {iface}"))?;
            if iface == Ipv4Addr::UNSPECIFIED {
                format!("udp-multicast {group}:{port}")
            } else {
                format!("udp-multicast {group}:{port} via {iface}")
            }
        }
        None => {
            sock.bind(&bind.into())
                .with_context(|| format!("binding UDP {bind}"))?;
            format!("udp {bind}")
        }
    };

    sock.set_nonblocking(true)
        .context("setting the UDP socket non-blocking")?;
    let std_sock: std::net::UdpSocket = sock.into();
    let sock = tokio::net::UdpSocket::from_std(std_sock)
        .context("registering the UDP socket with the runtime")?;
    Ok(UdpSource { sock, describe })
}
