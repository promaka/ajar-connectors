// SPDX-License-Identifier: Apache-2.0
//! UDP frame source — multicast or unicast. This covers the situational-awareness
//! broadcast transports (CoT SA, ASTERIX, MAVLink over UDP); one datagram is one
//! frame.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::Context as _;

use crate::runtime::FrameSource;

/// A UDP socket presented as a [`FrameSource`].
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

/// Open a UDP source. With `group`, join that multicast group: bind the wildcard
/// address on the group's port (binding the group address directly is
/// non-portable) and join ON A SPECIFIC INTERFACE when one is known. A
/// dual-homed box (management NIC plus surveillance LAN — the standard naval
/// build) otherwise joins wherever the routing table points and hears nothing.
/// The joining interface is, in order: the explicit `interface` field, else the
/// bind address's own IP when it names one (so `bind = "10.1.1.5:8600"` means
/// what it looks like it means), else the kernel's choice.
///
/// Without `group`, bind the address as given for unicast. Both paths set
/// `SO_REUSEADDR`/`SO_REUSEPORT` so multiple receivers can share a group and a
/// restart does not wait out `TIME_WAIT`.
pub fn open(bind: &str, group: Option<&str>, interface: Option<&str>) -> anyhow::Result<UdpSource> {
    let bind: SocketAddr = bind
        .parse()
        .map_err(|e| anyhow::anyhow!("transport.bind '{bind}': {e}"))?;
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
                .map_err(|e| anyhow::anyhow!("transport.group '{group}': {e}"))?;
            let iface: Ipv4Addr = match interface {
                Some(i) => i
                    .parse()
                    .map_err(|e| anyhow::anyhow!("transport.interface '{i}': {e}"))?,
                None => bind_v4, // 0.0.0.0 = kernel's choice, an IP = that NIC
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
