// SPDX-License-Identifier: Apache-2.0
//! Connector configuration. Everything an operator sets is data in a `.toml`
//! file, so adding equipment to a deployment never needs a rebuild — only a new
//! config (and a signing key registered with Core).
//!
//! The [`Transport`] is orthogonal to the protocol: it only decides *how bytes
//! arrive*. Any connector runs on any transport by config alone — a CoT parser
//! can read from UDP multicast in the field or from a tailed log file in a lab,
//! unchanged.

use serde::Deserialize;

/// A connector's configuration, shared across every connector.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// The connector's Ajar identity. Must match the signing key's registered
    /// profile; a native feed carries no Ajar identity, so it comes from here.
    pub source_id: String,
    /// NATS URL Core listens on (`nats://…`, or `tls://…` with the `AJAR_TLS_*`
    /// env for mTLS).
    pub nats_url: String,
    /// Ingest subject prefix; the connector publishes to `<prefix>.<source_id>`.
    #[serde(default = "default_subject_prefix")]
    pub subject_prefix: String,
    /// Path to the connector's 32-byte Ed25519 signing seed (raw bytes, or
    /// 64-char hex). Kept secret; never shared.
    pub signing_key_path: String,
    /// How the native feed reaches the connector.
    pub transport: Transport,
    /// Optional native-type → Ajar-entity overrides. A connector interprets these
    /// against its own type codes; anything unmapped falls back to the
    /// connector's default, so nothing is silently dropped.
    #[serde(default)]
    pub entity_map: std::collections::HashMap<String, String>,
    /// Force-identity hostility for feeds that carry none (AIS, MAVLink, civil
    /// ADS-B). E.g. `"Friend"` for own-force UAS, `"Neutral"` for civil traffic.
    /// Connectors whose wire format encodes it (CoT, STANAG 4676) derive it and
    /// ignore this. Unset resolves to `Unknown`.
    ///
    /// Values are MIM 5.3 `HostilityCodeType`, and the case is exact: `Friend`,
    /// `AssumedFriend`, `Hostile`, `AssumedHostile`, `Suspect`, `Neutral`,
    /// `AssumedNeutral`, `Involved`, `AssumedInvolved`, `Pending`, `Unknown`,
    /// `Faker`, `Joker`. An unrecognised value is quarantined by Core rather than
    /// rejected, so a lower-case `friendly` would silently lose friend/foe
    /// colouring on the map.
    #[serde(default)]
    pub default_hostility: Option<String>,
    /// The sensor's own site, for feeds that report positions relative to it
    /// (ASTERIX CAT048 monoradar reports are range/azimuth from the radar). A
    /// connector that needs it geolocates against this; without it, the relative
    /// measurement rides as metadata. Ignored by connectors that carry absolute
    /// positions.
    #[serde(default)]
    pub sensor: Option<SensorSite>,
}

/// A sensor's fixed geodetic site (WGS-84), used to geolocate sensor-relative
/// measurements. See [`Config::sensor`].
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct SensorSite {
    /// Latitude, degrees.
    pub lat: f64,
    /// Longitude, degrees.
    pub lon: f64,
    /// Height above the WGS-84 ellipsoid, metres (optional).
    #[serde(default)]
    pub alt_m: Option<f64>,
}

/// The enrichment a connector applies, distilled from [`Config`]. Connectors emit
/// every decoded field as an attribute and Core's signed ontology governs which
/// are kept, so the only enrichment left is the operator-asserted hostility for
/// feeds (AIS, MAVLink, civil ADS-B) that carry none of their own.
#[derive(Debug, Clone, Default)]
pub struct Enrichment {
    /// Hostility to stamp on feeds that carry none (`None` → not asserted, so the
    /// connector emits nothing rather than inventing a friend or foe).
    pub hostility: Option<String>,
}

impl Enrichment {
    /// Sets the default hostility (builder-style convenience).
    pub fn with_hostility(mut self, hostility: impl Into<String>) -> Self {
        self.hostility = Some(hostility.into());
        self
    }
}

impl Config {
    /// The enrichment settings for a connector built from this config.
    pub fn enrichment(&self) -> Enrichment {
        Enrichment {
            hostility: self.default_hostility.clone(),
        }
    }
}

fn default_subject_prefix() -> String {
    "ajar.ingest".to_string()
}

fn default_http_path() -> String {
    "/".to_string()
}

/// How a native feed reaches the connector — the integration *method*, distinct
/// from the protocol (which is the parsing). Selected by `kind` in the config's
/// `[transport]` table; each kind names the fields it needs.
///
/// ```toml
/// [transport]
/// kind = "udp-multicast"
/// bind = "0.0.0.0:6969"
/// group = "239.2.3.1"
/// ```
///
/// The feature-gated kinds (`serial`, `mqtt`, `rest-poll`) require the connector
/// to be built with the matching Cargo feature; DDS is reached through an
/// external gateway that re-publishes onto one of these kinds, not natively.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Transport {
    /// UDP multicast — the situational-awareness broadcast default (CoT, ASTERIX).
    UdpMulticast {
        /// Local bind, `ip:port` (e.g. `0.0.0.0:6969`).
        bind: String,
        /// Multicast group to join (e.g. `239.2.3.1`).
        group: String,
    },
    /// UDP unicast to a local bind.
    Udp {
        /// Local bind, `ip:port`.
        bind: String,
    },
    /// TCP server — listen locally and accept connections from sources that
    /// *push* their feed to a configured endpoint (the mirror image of
    /// `tcp-client`; the common legacy "point your output at ip:port" pattern).
    TcpServer {
        /// Local listen address, `ip:port` (e.g. `0.0.0.0:9000`).
        bind: String,
        /// How each connection's byte stream is split into frames.
        #[serde(default)]
        framing: Framing,
    },
    /// TCP client — connect out to a feed and read framed messages, reconnecting
    /// if it drops (AIS aggregators, ship-network NMEA, binary record streams).
    TcpClient {
        /// Remote endpoint, `host:port`.
        connect: String,
        /// How the byte stream is split into frames (default: one line per frame).
        #[serde(default)]
        framing: Framing,
    },
    /// Watch a directory for newly-dropped files (SFTP batch exports, scheduled
    /// dumps); each file is read line-by-line once its size settles.
    Dir {
        /// Directory to watch.
        path: String,
        /// Also read files already present at startup (default: new drops only).
        #[serde(default)]
        process_existing: bool,
    },
    /// Tail a file that a source appends to (a log, a spooled capture), yielding
    /// one line per frame — the ubiquitous "it writes to a file" integration.
    File {
        /// Path to the file to follow.
        path: String,
        /// Replay existing content before following appends (default: appends only).
        #[serde(default)]
        from_start: bool,
    },
    /// Run a command and read its stdout, one line per frame — wraps any CLI tool
    /// or vendor SDK binary that prints records (`some-vendor-cli --stream`).
    Exec {
        /// Program to run.
        command: String,
        /// Arguments passed to it.
        #[serde(default)]
        args: Vec<String>,
    },
    /// Read this process's stdin, one line per frame — pipe from anything
    /// (`producer | ajar-<connector>`).
    Stdin,
    /// HTTP server — accept webhook deliveries from sources that can only *push to
    /// a URL*: IP cameras and VMS event notifications, SDR republishers, SaaS
    /// callbacks. Each request body is one frame.
    ///
    /// Alone among the transports it can answer the sender, so a saturated
    /// pipeline refuses the delivery (503) and a well-behaved client retries,
    /// rather than the event being shed unseen.
    ///
    /// ```toml
    /// [transport]
    /// kind = "http-server"
    /// bind = "0.0.0.0:8443"
    /// path = "/hook"
    /// token = "shared-secret"
    /// tls_cert = "/etc/ajar/webhook.crt"
    /// tls_key = "/etc/ajar/webhook.key"
    /// # tls_client_ca = "/etc/ajar/senders-ca.crt"   # require client certs
    /// ```
    ///
    /// TLS follows the same fail-closed rule as the NATS connection: a `token`
    /// without TLS refuses to start, because a shared secret on a plaintext
    /// listener is on the wire in every delivery.
    HttpServer {
        /// Local listen address, `ip:port` (e.g. `0.0.0.0:8443`).
        bind: String,
        /// Path a delivery must target (default `/`); anything else gets 404.
        #[serde(default = "default_http_path")]
        path: String,
        /// Shared secret required in the `X-Ajar-Token` header. Requires TLS.
        /// Prefer `tls_client_ca` where the sender can present a certificate.
        #[serde(default)]
        token: Option<String>,
        /// PEM certificate chain served to senders. Set with `tls_key` to enable
        /// TLS; leaving both unset serves plaintext (protected segments only).
        #[serde(default)]
        tls_cert: Option<String>,
        /// PEM private key for `tls_cert`.
        #[serde(default)]
        tls_key: Option<String>,
        /// PEM CA bundle senders' client certificates must chain to. Setting it
        /// turns the listener into mutual TLS, which authenticates the sender by
        /// certificate rather than by a shared secret.
        #[serde(default)]
        tls_client_ca: Option<String>,
    },
    /// Serial line (RS-232/422/485) — many sensors emit NMEA or vendor ASCII this
    /// way. Requires the `serial` feature.
    #[cfg(feature = "serial")]
    Serial {
        /// Device path (e.g. `/dev/ttyUSB0`).
        device: String,
        /// Baud rate (e.g. 38400 for AIS, 4800 for GPS NMEA).
        #[serde(default = "default_baud")]
        baud: u32,
    },
    /// Subscribe to an MQTT topic — common for IoT and modern sensor buses.
    /// Requires the `mqtt` feature.
    #[cfg(feature = "mqtt")]
    Mqtt {
        /// Broker, `host:port`.
        host: String,
        /// Topic to subscribe (wildcards allowed).
        topic: String,
    },
    /// Poll an HTTP endpoint on an interval — for REST/JSON APIs with no push.
    /// Requires the `rest-poll` feature.
    #[cfg(feature = "rest-poll")]
    RestPoll {
        /// URL to GET.
        url: String,
        /// Seconds between polls.
        #[serde(default = "default_interval")]
        interval_secs: u64,
        /// Optional `Authorization` header value (e.g. `Bearer …`).
        #[serde(default)]
        auth_header: Option<String>,
    },
}

/// How a byte stream (TCP, serial, exec, stdin, file) is split into frames.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Framing {
    /// One newline-delimited line per frame (text protocols: NMEA, JSON lines).
    #[default]
    Line,
    /// A 2-byte big-endian length prefix, then that many payload bytes per frame
    /// (binary record streams).
    LengthDelimited,
}

#[cfg(feature = "serial")]
fn default_baud() -> u32 {
    38400
}

#[cfg(feature = "rest-poll")]
fn default_interval() -> u64 {
    30
}

impl Config {
    /// Load and validate a config file. Per-transport required fields are enforced
    /// by the config shape itself (a missing `group` on `udp-multicast` is a parse
    /// error), so there is nothing further to check here.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing config {path}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport(toml_str: &str) -> Transport {
        #[derive(Deserialize)]
        struct W {
            transport: Transport,
        }
        toml::from_str::<W>(toml_str).unwrap().transport
    }

    #[test]
    fn each_transport_kind_parses_from_config() {
        assert!(matches!(
            transport("[transport]\nkind='udp-multicast'\nbind='0.0.0.0:6969'\ngroup='239.2.3.1'"),
            Transport::UdpMulticast { .. }
        ));
        assert!(matches!(
            transport("[transport]\nkind='udp'\nbind='0.0.0.0:14550'"),
            Transport::Udp { .. }
        ));
        assert!(matches!(
            transport("[transport]\nkind='tcp-client'\nconnect='h:1'\nframing='length-delimited'"),
            Transport::TcpClient {
                framing: Framing::LengthDelimited,
                ..
            }
        ));
        // TCP framing defaults to line when omitted.
        assert!(matches!(
            transport("[transport]\nkind='tcp-client'\nconnect='h:1'"),
            Transport::TcpClient {
                framing: Framing::Line,
                ..
            }
        ));
        assert!(matches!(
            transport("[transport]\nkind='file'\npath='/var/log/f'"),
            Transport::File { .. }
        ));
        assert!(matches!(
            transport("[transport]\nkind='tcp-server'\nbind='0.0.0.0:9000'"),
            Transport::TcpServer {
                framing: Framing::Line,
                ..
            }
        ));
        assert!(matches!(
            transport("[transport]\nkind='dir'\npath='/data/drop'\nprocess_existing=true"),
            Transport::Dir {
                process_existing: true,
                ..
            }
        ));
        assert!(matches!(
            transport("[transport]\nkind='exec'\ncommand='cli'\nargs=['--stream']"),
            Transport::Exec { .. }
        ));
        assert!(matches!(
            transport("[transport]\nkind='stdin'"),
            Transport::Stdin
        ));
        // http-server: path defaults to "/" and the token is optional.
        assert!(matches!(
            transport("[transport]\nkind='http-server'\nbind='0.0.0.0:8080'"),
            Transport::HttpServer { ref path, token: None, .. } if path == "/"
        ));
        assert!(matches!(
            transport(
                "[transport]\nkind='http-server'\nbind='0.0.0.0:8080'\npath='/hook'\ntoken='s'"
            ),
            Transport::HttpServer { ref path, token: Some(ref t), .. } if path == "/hook" && t == "s"
        ));
    }

    #[test]
    fn a_required_field_is_a_parse_error() {
        #[derive(Deserialize)]
        struct W {
            #[allow(dead_code)]
            transport: Transport,
        }
        // udp-multicast without a group must not parse.
        let bad = "[transport]\nkind='udp-multicast'\nbind='0.0.0.0:6969'";
        assert!(toml::from_str::<W>(bad).is_err());
    }
}
