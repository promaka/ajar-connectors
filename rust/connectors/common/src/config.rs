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
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The connector's Ajar identity. Must match the signing key's registered
    /// profile; a native feed carries no Ajar identity, so it comes from here.
    pub source_id: String,
    /// NATS URL Core listens on (`nats://…`, or `tls://…` with the `AJAR_TLS_*`
    /// env for mTLS). A comma-separated list is a failover set: the connector
    /// uses one endpoint and moves to the next when it dies — the two-box
    /// deployment pattern. Any `tls://` entry demands TLS for the connection.
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
    /// Optional store-and-forward disk spool for intermittent links: when the
    /// publish path stalls, sealed events queue in a bounded directory and a
    /// paced drain replays them when the link returns, byte-identical. Unset
    /// keeps today's behavior (shed with a counter).
    ///
    /// One line enables it with safe defaults:
    /// `spool = "/var/lib/ajar/spool"`; the full `[spool]` table tunes the
    /// bound and drain rate.
    #[serde(default)]
    pub spool: Option<SpoolSetting>,
    /// The one tolerated extension section: the generic connector reads its
    /// `[mapping]` block from the same file with its own loader. Named here so
    /// `deny_unknown_fields` still rejects actual typos everywhere else.
    #[serde(default, rename = "mapping")]
    _mapping_extension: Option<toml::Value>,
}

/// The `spool` setting: a bare directory string (defaults for everything
/// else), or the full table for tuning.
#[derive(Debug, Clone)]
pub enum SpoolSetting {
    /// `spool = "/var/lib/ajar/spool"`
    Dir(String),
    /// `[spool]` with `dir`, `max_bytes`, `drain_rate`.
    Full(crate::spool::SpoolConfig),
}

// Hand-rolled so a typo inside [spool] reports the actual unknown field
// instead of serde's "did not match any variant of untagged enum".
impl<'de> serde::Deserialize<'de> for SpoolSetting {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = SpoolSetting;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(
                    "a spool directory string, or a [spool] table with dir/max_bytes/drain_rate",
                )
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<SpoolSetting, E> {
                Ok(SpoolSetting::Dir(v.to_string()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<SpoolSetting, A::Error> {
                crate::spool::SpoolConfig::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )
                .map(SpoolSetting::Full)
            }
        }
        d.deserialize_any(V)
    }
}

impl Config {
    /// The effective spool configuration, whichever form the config used.
    pub fn spool_config(&self) -> Option<crate::spool::SpoolConfig> {
        match &self.spool {
            None => None,
            Some(SpoolSetting::Full(cfg)) => Some(cfg.clone()),
            Some(SpoolSetting::Dir(dir)) => Some(crate::spool::SpoolConfig::with_dir(dir)),
        }
    }
}

/// A sensor's fixed geodetic site (WGS-84), used to geolocate sensor-relative
/// measurements. See [`Config::sensor`].
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
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

fn default_replay_speed() -> f64 {
    1.0
}

fn default_replay_max_gap_ms() -> u64 {
    5_000
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
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Transport {
    /// UDP multicast — the situational-awareness broadcast default (CoT, ASTERIX).
    UdpMulticast {
        /// Local bind, `ip:port`. `0.0.0.0:6969` joins on the kernel's chosen
        /// interface; naming an IP (e.g. `10.1.1.5:6969`) joins on that NIC.
        bind: String,
        /// Multicast group to join (e.g. `239.2.3.1`).
        group: String,
        /// Interface IP to join on, for dual-homed boxes where the group must
        /// be heard on a specific network. Overrides the bind IP's role.
        #[serde(default)]
        interface: Option<String>,
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
    /// Replay a recorded capture (classic pcap, Ethernet/IPv4/UDP) with its
    /// original timing: any connector runs a recording exactly as it would
    /// have run live. The field-standard way to evaluate against real data.
    PcapReplay {
        /// Path to the .pcap (a .pcapng converts with
        /// `tshark -F pcap -r in.pcapng -w out.pcap`).
        path: String,
        /// Time scale: 1.0 = real time, 10 = ten times faster.
        #[serde(default = "default_replay_speed")]
        speed: f64,
        /// Replay forever (demo loop) instead of once.
        #[serde(default, rename = "loop")]
        looping: bool,
        /// Only datagrams to this UDP port (a busy capture carries more than
        /// the feed).
        #[serde(default)]
        port: Option<u16>,
        /// Longest gap honoured between packets, in milliseconds: a recorder
        /// left idle must not stall the replay. Default 5000.
        #[serde(default = "default_replay_max_gap_ms")]
        max_gap_ms: u64,
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
    /// WebSocket client — connect out to a hosted feed and take each message as a
    /// frame. Requires the `websocket` feature.
    ///
    /// The push counterpart to `rest-poll`, and unlike `http-server` the provider
    /// does not need to reach you, so it works from behind a firewall with no
    /// inbound path.
    ///
    /// ```toml
    /// [transport]
    /// kind = "ws-client"
    /// url = "wss://feed.example.com/stream"
    /// subscribe = '{"action":"subscribe","channel":"tracks"}'
    ///
    /// [transport.headers]
    /// Authorization = "Bearer <token>"
    /// ```
    #[cfg(feature = "websocket")]
    WsClient {
        /// Feed endpoint, `ws://…` or `wss://…`.
        url: String,
        /// Message sent after every handshake, including reconnects. Most feeds
        /// need one; without it you connect and then receive nothing.
        #[serde(default)]
        subscribe: Option<String>,
        /// Extra handshake headers, typically authentication.
        #[serde(default)]
        headers: std::collections::HashMap<String, String>,
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
        let text = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!(
                "reading config {path}: {e}. The example config shipped next to the \
                 connector (*.example.toml) shows every field; copy it and edit."
            )
        })?;
        toml::from_str(&text).map_err(|e| {
            let msg = e.to_string();
            match did_you_mean(&msg) {
                Some(hint) => anyhow::anyhow!("parsing config {path}: {msg}\n{hint}"),
                None => anyhow::anyhow!("parsing config {path}: {msg}"),
            }
        })
    }
}

/// For an unknown-field or unknown-variant parse error, the closest name the
/// config accepts, as a one-line hint. A typo in a config is the most common
/// first-hour failure; the list of every valid name is true but not helpful.
fn did_you_mean(msg: &str) -> Option<String> {
    let (what, rest) = msg
        .split_once("unknown field `")
        .map(|(_, r)| ("field", r))
        .or_else(|| {
            msg.split_once("unknown variant `")
                .map(|(_, r)| ("value", r))
        })?;
    let (typo, rest) = rest.split_once('`')?;
    let (_, list) = rest.split_once("expected one of ")?;
    let candidates: Vec<&str> = list
        .split(',')
        .filter_map(|c| c.trim().trim_matches('`').split('`').next())
        .filter(|c| !c.is_empty())
        .collect();
    let best = candidates
        .iter()
        .map(|c| (edit_distance(typo, c), *c))
        .min()?;
    (best.0 <= 2.max(typo.len() / 3)).then(|| format!("did you mean the {what} `{}`?", best.1))
}

/// Levenshtein distance, for `did_you_mean`.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(name: &str, body: &str) -> String {
        let dir =
            std::env::temp_dir().join(format!("ajar-config-test-{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("c.toml");
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn a_typo_in_a_field_name_is_answered_with_the_right_name() {
        let p = write(
            "typo-field",
            "source_id = \"x\"\nnats_ur = \"nats://h:4222\"\nsigning_key_path = \"k\"\n\
             [transport]\nkind = \"udp\"\nbind = \"0.0.0.0:1\"\n",
        );
        let msg = Config::load(&p).unwrap_err().to_string();
        assert!(msg.contains("unknown field `nats_ur`"), "{msg}");
        assert!(msg.contains("did you mean the field `nats_url`?"), "{msg}");
    }

    #[test]
    fn a_typo_in_a_transport_kind_is_answered_with_the_right_kind() {
        let p = write(
            "typo-kind",
            "source_id = \"x\"\nnats_url = \"nats://h:4222\"\nsigning_key_path = \"k\"\n\
             [transport]\nkind = \"udp-multicst\"\nbind = \"0.0.0.0:1\"\ngroup = \"239.1.1.1\"\n",
        );
        let msg = Config::load(&p).unwrap_err().to_string();
        assert!(
            msg.contains("did you mean the value `udp-multicast`?"),
            "{msg}"
        );
    }

    #[test]
    fn a_missing_config_points_at_the_example() {
        let msg = Config::load("/nonexistent/dir/x.toml")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("reading config /nonexistent/dir/x.toml"),
            "{msg}"
        );
        assert!(msg.contains("*.example.toml"), "{msg}");
    }

    #[test]
    fn far_off_names_get_no_guess() {
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert!(
            did_you_mean("unknown field `zzzzzzzz`, expected one of `source_id`, `nats_url`")
                .is_none()
        );
        assert_eq!(
            did_you_mean("unknown field `sorce_id`, expected one of `source_id`, `nats_url`")
                .as_deref(),
            Some("did you mean the field `source_id`?")
        );
    }

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

    #[test]
    fn a_typo_is_an_error_naming_the_field_not_a_silent_default() {
        let base = "source_id='s'\nnats_url='nats://x:4222'\nsigning_key_path='k'\n";
        // Top level.
        let bad = format!("{base}defaut_hostility='Friend'\n[transport]\nkind='stdin'\n");
        let err = toml::from_str::<Config>(&bad).unwrap_err().to_string();
        assert!(err.contains("defaut_hostility"), "{err}");
        // Inside [transport].
        let bad = format!("{base}[transport]\nkind='udp'\nbindd='0.0.0.0:1'\n");
        let err = toml::from_str::<Config>(&bad).unwrap_err().to_string();
        assert!(err.contains("bindd"), "{err}");
        // Inside [spool]: the classic max_byte slip, named, not defaulted.
        let bad = format!("{base}[transport]\nkind='stdin'\n[spool]\ndir='/d'\nmax_byte=1\n");
        let err = toml::from_str::<Config>(&bad).unwrap_err().to_string();
        assert!(err.contains("max_byte"), "{err}");
        // Inside [sensor].
        let bad = format!("{base}[transport]\nkind='stdin'\n[sensor]\nlat=1.0\nlonn=2.0\n");
        let err = toml::from_str::<Config>(&bad).unwrap_err().to_string();
        assert!(err.contains("lonn"), "{err}");
        // The generic connector's [mapping] block is the one tolerated
        // extension: same file, its own loader.
        let ok = format!("{base}[transport]\nkind='stdin'\n[mapping]\nentity_type='mim:vessel'\n");
        assert!(toml::from_str::<Config>(&ok).is_ok());
    }

    #[test]
    fn the_spool_takes_one_line_or_a_full_table() {
        let base = "source_id='s'\nnats_url='nats://x:4222'\nsigning_key_path='k'\n\
                    [transport]\nkind='stdin'\n";

        // No spool: none configured, today's behavior.
        let cfg: Config = toml::from_str(base).unwrap();
        assert!(cfg.spool_config().is_none());

        // The one-liner: a bare path, everything else defaulted.
        let cfg: Config =
            toml::from_str(&format!("spool = '/var/lib/ajar/spool'\n{base}")).unwrap();
        let spool = cfg.spool_config().unwrap();
        assert_eq!(spool.dir, "/var/lib/ajar/spool");
        assert_eq!(spool.max_bytes, 256 * 1024 * 1024);
        assert!((spool.drain_rate - 50.0).abs() < f64::EPSILON);

        // The full table tunes the bound and the pace.
        let cfg: Config = toml::from_str(&format!(
            "{base}[spool]\ndir='/data/spool'\nmax_bytes=1024\ndrain_rate=7.5\n"
        ))
        .unwrap();
        let spool = cfg.spool_config().unwrap();
        assert_eq!(spool.dir, "/data/spool");
        assert_eq!(spool.max_bytes, 1024);
        assert!((spool.drain_rate - 7.5).abs() < f64::EPSILON);
    }
}
