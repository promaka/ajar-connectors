<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-tak-egress

Egress relay from Ajar Core to TAK. It subscribes to the governed CoT that Core
publishes on NATS and writes each message, byte for byte, to a TAK Server's
streaming input or to ATAK's mesh multicast group. TAK users see the governed
picture on their existing kit. Core has already verified, filtered and rendered
the CoT before it reaches the subject, so the relay does not parse, sign, alter
or filter it.

## Input

NATS subject `egress_subject`, usually `ajar.egress.cot.*` (`*` is the
per-source token). Every message on the subject is accepted and relayed; the
relay does not check that the payload is CoT.

The NATS connection uses the `AJAR_TLS_CA`, `AJAR_TLS_CERT` and `AJAR_TLS_KEY`
environment. The operator gives this identity subscribe-only rights on the
egress subject, with no publish rights.

## Output

The NATS payload, unchanged, to one of two kinds of `target`:

| `target` | Delivery |
|-----------|----------|
| `tls://host:port` | mutual TLS to a TAK Server's streaming input (standard port 8089). Events are written back to back on one stream, which TAK parses as concatenated CoT XML (TAK Protocol v0). |
| `udp://ip:port` | one datagram per event. `udp://239.2.3.1:6969` is ATAK's mesh SA group, read by every ATAK, WinTAK and iTAK on the network with no server. A unicast address also works. |

The relay holds two certificates:

| Certificate | Issued by | Grants |
|---|---|---|
| `AJAR_TLS_*` env | the Ajar operator's PKI | subscribe-only mTLS to Ajar NATS |
| `[tak] tls_cert`, `tls_key` | the TAK Server's enrolment | client authentication on the TAK Server's streaming input |

## Configuration

`ajar-connectors join` writes the config: the first four keys come from the
invite and from `join --target`, and the `[tak]` table from the instance's
`settings.toml`. To run the relay by hand, start from
[`tak-egress.example.toml`](tak-egress.example.toml).

| Key | Default | Meaning |
|-----|---------|---------|
| `nats_url` | required | Ajar NATS, `tls://` in production |
| `egress_subject` | required | subject to subscribe, under `ajar.egress.` |
| `egress_verifying_key` | required | Core's egress key file; not read, since the CoT channel is not signed |
| `target` | required | `tls://host:port` or `udp://ip:port` |
| `[tak] tls_ca` | none | CA that signed the TAK Server certificate; required for `tls://` |
| `[tak] tls_cert`, `tls_key` | none | the relay's enrolled client certificate and key, PEM; required for `tls://` |
| `[tak] server_name` | host in `target` | name verified on the server certificate (SNI) |
| `[tak] interface` | default route | multicast only: IPv4 address of the interface the TAK clients share |
| `[tak] multicast_ttl` | `1` | multicast only: hop limit; 1 keeps the datagrams on the local network |
| `[tak] buffer_max` | `1000` | events held while TAK is unreachable; must be at least 1 |

For ATAK's mesh with no TAK Server:

```toml
target = "udp://239.2.3.1:6969"

[tak]
# interface = "192.168.1.20"
```

No certificates are needed, and ATAK's mesh mode is on by default. A TAK
Server is still the way to reach clients across networks and to control who
may join.

## Behaviour

- The TAK Server connection is made on the first send, so startup never waits
  for TAK. A connect attempt times out after 5 s.
- A connect or write error drops the stream. The event stays queued and the
  next send reconnects, so an event whose write failed is sent again on the new
  connection.
- While TAK is unreachable, events queue in memory, up to `buffer_max`. At the
  cap the oldest event is dropped and `egress_gap_dropped_total` increments. A
  queued buffer retries once a second, or on the next NATS message. Nothing is
  kept across a restart.
- The NATS client reconnects by itself.
- On SIGTERM or SIGINT the relay drains the queue for up to 2 s, then exits.

Metrics, on `/metrics` when `AJAR_HEALTH_ADDR` is set (`/healthz` answers `ok`):

| Metric | Meaning |
|--------|---------|
| `egress_delivered_total` | events written to TAK |
| `egress_gap_dropped_total` | events dropped at the buffer cap |
| `egress_tak_reconnects_total` | successful TAK Server connects, the first included |
| `egress_tak_link_up` | 1 while the TAK link is up; always 1 for `udp://` |

## Limits

- TAK Protocol v0 (XML) only. Protobuf v1 negotiation is not implemented.
- No durable queue: an outage longer than `buffer_max` events leaves a gap.
- A write into a connection the server has just closed can succeed at the TCP
  level. That event is lost, though it is counted as delivered.

## Run

```bash
export AJAR_TLS_CA=/etc/ajar/ca.pem AJAR_TLS_CERT=/etc/ajar/egress-reader.crt AJAR_TLS_KEY=/etc/ajar/egress-reader.key
export AJAR_HEALTH_ADDR=0.0.0.0:9090
ajar-tak-egress /etc/ajar/tak-egress.toml
```

## Tests

`cargo test -p ajar-tak-egress` runs against a mutual-TLS CoT sink with
throwaway certificates minted in the test: byte-identical delivery, and
reconnection after the sink drops. The NATS-to-TAK test runs only when
`AJAR_TEST_NATS_URL` points at a live broker.
