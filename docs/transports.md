<!-- SPDX-License-Identifier: Apache-2.0 -->
# Transports

The `[transport]` table in a connector's config says how native bytes arrive.
`kind` picks the transport. An unknown key is a parse error. Keys without a
default are required.

The runtime reads at most `MAX_FRAME_BYTES` (64 KiB) per frame.

## Framing

`tcp-client`, `tcp-server`, `file` and `stdin` take a `framing` key, `line` by
default. `exec`, `serial` and `dir` are line-only.

| `framing` | Frame |
|---|---|
| `line` | One newline-terminated line, without its line ending |
| `length-delimited` | A 2-byte big-endian length, then the payload. It cannot exceed the frame limit |
| `length-u32le` | A 4-byte little-endian length, then the payload. SAPIENT uses it over TCP |

A line over the limit is dropped and the stream resumes at the next newline.

## Build features

`udp-multicast`, `udp`, `tcp-client`, `tcp-server`, `file`, `dir`, `exec`,
`stdin`, `http-server` and `pcap-replay` are always built. The others need a
feature of `ajar-connector-common`.

| `kind` | Feature | Shipped in |
|---|---|---|
| `dds` | `dds` | Every ingress connector, by default. `--no-default-features` drops it |
| `serial` | `serial` | `ajar-ais-nmea`, by default |
| `mqtt` | `mqtt` | None |
| `rest-poll` | `rest-poll` | None |
| `ws-client` | `websocket` | None |

To add one to another connector, name the dependency's feature:

```bash
cargo build --release -p ajar-asterix --features ajar-connector-common/mqtt
```

## `udp-multicast`

Join a multicast group. One datagram is one frame.

```toml
[transport]
kind = "udp-multicast"
bind = "0.0.0.0:6969"
group = "239.2.3.1"
```

| Key | Default | Meaning |
|---|---|---|
| `bind` | | IPv4 `ip:port`. The socket binds the wildcard address on this port. The IP selects the joining NIC when `interface` is unset; `0.0.0.0` leaves it to the kernel |
| `group` | | IPv4 group address |
| `interface` | unset | IP of the NIC to join on. Set it on a dual-homed box, or the join follows the routing table and may hear nothing |

Several receivers on one host can share a group. There is no authentication:
anything that can reach the group gets frames signed by the connector.

## `udp`

Receive unicast datagrams. One datagram is one frame.

```toml
[transport]
kind = "udp"
bind = "0.0.0.0:8600"
```

| Key | Default | Meaning |
|---|---|---|
| `bind` | | IPv4 `ip:port` |

There is no authentication, as for `udp-multicast`.

## `tcp-client`

Dial a feed and read frames. A failed connection is retried every 2 s, and any
read error reconnects, including an over-long frame.

```toml
[transport]
kind = "tcp-client"
connect = "feed.example.mil:9000"
framing = "line"
```

| Key | Default | Meaning |
|---|---|---|
| `connect` | | `host:port` |
| `framing` | `line` | See [Framing](#framing) |

There is no TLS.

## `tcp-server`

Listen for sources that push their feed. Each connection is framed on its own
and their frames interleave. Frames share a bounded queue, and a full queue
slows the pushers.

```toml
[transport]
kind = "tcp-server"
bind = "0.0.0.0:9000"
framing = "line"
```

| Key | Default | Meaning |
|---|---|---|
| `bind` | | `ip:port`. A bad address stops startup |
| `framing` | `line` | See [Framing](#framing) |

There is no TLS or authentication: anything that can reach the port gets frames
signed by the connector.

## `http-server`

Accept webhook deliveries. Each request body is one frame. HTTP/1.1 only, `POST`
or `PUT`, with `Content-Length` or `chunked` bodies.

```toml
[transport]
kind = "http-server"
bind = "0.0.0.0:8443"
path = "/hook"
tls_cert = "/etc/ajar/webhook.crt"
tls_key = "/etc/ajar/webhook.key"
tls_client_ca = "/etc/ajar/senders-ca.crt"
```

| Key | Default | Meaning |
|---|---|---|
| `bind` | | `ip:port` |
| `path` | `/` | The path a delivery must target. `hook`, `/hook` and `/hook/` are the same |
| `token` | unset | Shared secret the sender puts in the `X-Ajar-Token` header. Needs TLS |
| `tls_cert` | unset | PEM certificate chain. Set with `tls_key`, or neither |
| `tls_key` | unset | PEM private key |
| `tls_client_ca` | unset | PEM CA bundle. Senders must present a certificate chaining to it. Needs TLS |

Prefer `tls_client_ca` where the sender can present a certificate. It
authenticates the sender by key, where `token` is a bearer secret.

Without TLS, deliveries and their contents are readable on the wire, so use
plaintext only on a physically protected segment. The connector logs a warning
at startup.

`token` without TLS refuses to start. The secret would cross the wire in every
delivery, and anyone who captured it could inject events the connector then
signs.

| Answer | When |
|---|---|
| 204 | Queued, or a request with no body, which is treated as a health probe and makes no frame |
| 400 | Malformed request, or a head over 16 KiB or 64 lines |
| 401 | Wrong or missing `token` |
| 404 | Another path |
| 405 | Another method |
| 413 | Body over the frame limit |
| 501 | A `Transfer-Encoding` other than `chunked` |
| 503 | Pipeline saturated, with `Retry-After`. Nothing is shed unseen, so delivery is as durable as the sender's retry policy |

A request must arrive within 30 s. An idle keep-alive connection closes after
60 s.

## `file`

Follow a file a source appends to. The file must exist at startup. Rotation is
noticed when the file becomes shorter than the read position, and reading
restarts from its beginning.

```toml
[transport]
kind = "file"
path = "/var/log/feed.log"
from_start = false
framing = "line"
```

| Key | Default | Meaning |
|---|---|---|
| `path` | | The file |
| `from_start` | `false` | Read existing content before following appends |
| `framing` | `line` | See [Framing](#framing) |

A line that is not valid UTF-8 is a read error. With a length prefix, bytes are
held until the whole frame has arrived.

## `dir`

Read each file dropped into a directory, one line per frame. The directory must
exist at startup. Subdirectories are ignored.

```toml
[transport]
kind = "dir"
path = "/data/drop"
process_existing = false
```

| Key | Default | Meaning |
|---|---|---|
| `path` | | The directory |
| `process_existing` | `false` | Also read files present at startup. Unset, they are skipped |

A file is read once its size is the same on two consecutive polls, about a
second apart, so have the source write elsewhere and rename into the directory
if its transfers can stall.

Read files are remembered by name, in memory, up to 100,000 names. The oldest is
then forgotten, and read again if it is still there. Clean the directory as part
of operations. After a restart, `process_existing = true` reads everything
present again.

## `exec`

Run a command and read its stdout, one line per frame. The command starts on the
first read. It is respawned after 1 s when it exits, and a failed spawn is
retried every 2 s.

```toml
[transport]
kind = "exec"
command = "vendor-cli"
args = ["--stream"]
```

| Key | Default | Meaning |
|---|---|---|
| `command` | | The program |
| `args` | `[]` | Its arguments |

## `stdin`

Read this process's standard input: `producer | ajar-<connector> config.toml`.

```toml
[transport]
kind = "stdin"
framing = "line"
```

| Key | Default | Meaning |
|---|---|---|
| `framing` | `line` | See [Framing](#framing) |

## `pcap-replay`

Replay a recorded capture with its original timing. Each UDP payload is one
frame. The capture is read into memory at startup.

```toml
[transport]
kind = "pcap-replay"
path = "/data/radar.pcap"
port = 8600
speed = 1.0
loop = false
max_gap_ms = 5000
```

| Key | Default | Meaning |
|---|---|---|
| `path` | | A classic pcap, Ethernet link type |
| `speed` | `1.0` | Time scale, above 0. `10` is ten times faster |
| `loop` | `false` | Replay forever |
| `port` | unset | Only datagrams to this UDP port |
| `max_gap_ms` | `5000` | Longest wait between frames, after `speed` is applied, so an idle recorder does not stall the replay |

Convert a pcapng with `tshark -F pcap -r in.pcapng -w out.pcap`. Only IPv4/UDP
is replayed, with or without 802.1Q tags. Other packets are skipped and counted.
A capture with nothing to replay refuses to start.

Without `loop`, the connector stays up after the last frame and does not exit, so
a batch job must stop it with a signal.

## `serial`

Read an RS-232/422/485 device, one line per frame. The device opens on the first
read, and a read error reopens it, so a reseated cable recovers. An open that
fails is retried every 2 s.

```toml
[transport]
kind = "serial"
device = "/dev/ttyUSB0"
baud = 38400
```

| Key | Default | Meaning |
|---|---|---|
| `device` | | Device path |
| `baud` | `38400` | Line speed |

Repeated over-long lines usually mean a baud mismatch.

## `mqtt`

Subscribe to a topic. Each message payload is one frame. The source reconnects
and resubscribes after a connection error.

```toml
[transport]
kind = "mqtt"
host = "broker.example.mil:1883"
topic = "sensors/+/tracks"
```

| Key | Default | Meaning |
|---|---|---|
| `host` | | `host:port`, port 1883 when omitted |
| `topic` | | Wildcards allowed |

It subscribes at QoS 0. There is no TLS and there are no broker credentials.

## `ws-client`

Dial a WebSocket feed. Each text or binary message is one frame. Nothing needs to
reach the connector, so it works behind a firewall with no inbound path.

```toml
[transport]
kind = "ws-client"
url = "wss://feed.example.com/stream"
subscribe = '{"action":"subscribe","channel":"tracks"}'

[transport.headers]
Authorization = "Bearer <token>"
```

| Key | Default | Meaning |
|---|---|---|
| `url` | | `ws://` or `wss://` |
| `subscribe` | unset | Text message sent after every handshake, including reconnects |
| `headers` | none | Extra handshake headers, usually authentication |

Most feeds need `subscribe`. Without it the connection succeeds and then nothing
arrives.

A `wss://` server must chain to a public web root, because a private CA cannot
be configured. A dropped connection is retried with a backoff from 1 s to 30 s.
A message over the frame limit is dropped whole.

## `rest-poll`

GET a URL on an interval. Each response body is one frame. A failed poll or an
error status is logged and retried at the next interval.

```toml
[transport]
kind = "rest-poll"
url = "https://api.example.com/tracks"
interval_secs = 30
auth_header = "Bearer <token>"
```

| Key | Default | Meaning |
|---|---|---|
| `url` | | The URL |
| `interval_secs` | `30` | Seconds between polls, at least 1. The first poll is immediate |
| `auth_header` | unset | `Authorization` header value |

There is no pagination. A larger or paginated API needs a purpose-built
connector.

## `dds`

Subscribe to one topic on a DDS domain. The connector is one more reader, so
nothing changes on the publisher's side.

```toml
[transport]
kind = "dds"
domain = 0
topic = "RadarTracks"
type_name = "Tracks::Track"
reliability = "best-effort"
payload = "body"
```

| Key | Default | Meaning |
|---|---|---|
| `domain` | `0` | 0 to 232 |
| `topic` | | Topic name, exactly as published |
| `type_name` | | The publisher's registered type name, exactly |
| `reliability` | `best-effort` | `best-effort` pairs with any publisher and lost samples are not resent. `reliable` pairs only with reliable publishers |
| `payload` | `body` | What the parser receives, see below |
| `interface_ip` | unset | Use only the NIC holding this IP, for a box with the domain on one LAN |

A mismatch in topic, type name or reliability produces silence, not an error.
`ajar-doctor` says which it is. Only the default partition is joined.

CI runs this transport against ROS 2 Jazzy publishers of `std_msgs/String`, one on
Fast DDS and one on Cyclone DDS.

| `payload` | The parser receives |
|---|---|
| `body` | The serialized CDR body as the publisher wrote it, without the encapsulation header |
| `octets` | The bytes of a struct whose only field is a `sequence<octet>` |
| `string` | The text of a struct whose only field is a `string`, such as ROS 2 `std_msgs/String` |

`octets` and `string` work only on plain CDR, CDR2 and XCDR2 bodies. Delimited and
parameter-list encodings carry headers before the first field. A sample that does
not fit the shape is skipped with a warning. A typed struct wants
`payload = "body"`.

A frame over the limit is dropped whole. The reader holds up to 4,096 samples
and then drops the oldest.
