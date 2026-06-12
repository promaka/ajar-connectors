// SPDX-License-Identifier: Apache-2.0
//
//! A minimal NATS PUB client over plain TCP — just enough of the (text-based)
//! NATS client protocol to publish messages. It exists so this example needs no
//! NATS client crate; it is NOT a general-purpose client. A production connector
//! should use a maintained library such as `async-nats`.
//!
//! Protocol: on connect the server sends `INFO ...`; the client replies with
//! `CONNECT {...}`. To publish: `PUB <subject> <byte-count>\r\n<payload>\r\n`.
//! The server sends periodic `PING`s; a background reader answers `PONG` so the
//! connection is not dropped.

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::thread;

/// Publishes messages to a NATS server.
pub struct NatsPublisher {
    stream: TcpStream,
}

impl NatsPublisher {
    /// Connects to `addr` (e.g. `127.0.0.1:4222`), performs the CONNECT
    /// handshake, and spawns a reader that answers server PINGs with PONG.
    pub fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;

        // The server greets with an INFO line; read and discard it.
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut info = String::new();
        reader.read_line(&mut info)?;

        // Announce ourselves (verbose:false => the server won't send +OK acks).
        let mut writer = stream.try_clone()?;
        writer.write_all(
            b"CONNECT {\"verbose\":false,\"pedantic\":false,\"name\":\"synthetic-radar\"}\r\n",
        )?;
        writer.flush()?;

        // Keepalive: answer PINGs so the server doesn't drop us.
        let mut ping_writer = stream.try_clone()?;
        thread::spawn(move || {
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break, // connection closed
                    Ok(_) => {
                        if line.starts_with("PING") {
                            if ping_writer.write_all(b"PONG\r\n").is_err() {
                                break;
                            }
                            let _ = ping_writer.flush();
                        }
                        // Other server lines (PONG, +OK, MSG, INFO) are ignored.
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self { stream })
    }

    /// Publishes `payload` to `subject`.
    pub fn publish(&mut self, subject: &str, payload: &[u8]) -> io::Result<()> {
        write!(self.stream, "PUB {} {}\r\n", subject, payload.len())?;
        self.stream.write_all(payload)?;
        self.stream.write_all(b"\r\n")?;
        self.stream.flush()
    }
}
