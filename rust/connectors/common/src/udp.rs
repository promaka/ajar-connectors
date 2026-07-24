// SPDX-License-Identifier: Apache-2.0
//! UDP frame source — multicast or unicast. This covers the situational-awareness
//! broadcast transports (CoT SA, ASTERIX, MAVLink over UDP); one datagram is one
//! frame.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

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
/// non-portable) and join. Without, bind the address as given for unicast. Both
/// set `SO_REUSEADDR`/`SO_REUSEPORT` so multiple receivers can share a group and a
/// restart doesn't wait out `TIME_WAIT`.
pub fn open(bind: &str, group: Option<&str>) -> anyhow::Result<UdpSource> {
    let bind: SocketAddr = bind
        .parse()
        .map_err(|e| anyhow::anyhow!("transport.bind '{bind}': {e}"))?;
    let port = bind.port();

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;

    let describe = match group {
        Some(group) => {
            let group: Ipv4Addr = group
                .parse()
                .map_err(|e| anyhow::anyhow!("transport.group '{group}': {e}"))?;
            let listen = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
            sock.bind(&listen.into())?;
            sock.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)?;
            format!("udp-multicast {group}:{port}")
        }
        None => {
            sock.bind(&bind.into())?;
            format!("udp {bind}")
        }
    };

    sock.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = sock.into();
    let sock = tokio::net::UdpSocket::from_std(std_sock)?;
    Ok(UdpSource { sock, describe })
}
