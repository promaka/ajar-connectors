// SPDX-License-Identifier: Apache-2.0
//! A loopback HTTP/1.1 server for transport tests: it answers each connection with the next
//! scripted reply and records the request.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A JSON reply.
pub struct Reply {
    status: u16,
    body: String,
}

impl Reply {
    pub fn json(status: u16, body: &str) -> Reply {
        Reply {
            status,
            body: body.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Header names lowercased.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

pub struct MockServer {
    port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl MockServer {
    /// Serves `replies` in order, one per connection, then stops accepting.
    pub async fn start(replies: Vec<Reply>) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        tokio::spawn(async move {
            for reply in replies {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let Some(request) = read_request(&mut stream).await else {
                    return;
                };
                seen.lock().unwrap().push(request);
                let head = format!(
                    "HTTP/1.1 {} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    reply.status,
                    reply.body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(reply.body.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        MockServer { port, requests }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Request> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut start = lines.next()?.split(' ');
    let method = start.next()?.to_string();
    let path = start.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    while raw.len() < head_end + length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&raw[head_end..]).into_owned();
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}
