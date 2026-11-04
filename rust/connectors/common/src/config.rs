// SPDX-License-Identifier: Apache-2.0
//! Connector configuration, loaded from the operator's `.toml`. The
//! [`Transport`] only decides how bytes arrive; any connector runs on any
//! transport.

use std::collections::HashMap;

use anyhow::Context;
use serde::Deserialize;

use crate::marking::{Marking, MarkingConfig, MarkingError};
use crate::spool::SpoolConfig;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub source_id: String,
    /// A comma-separated list is a failover set; any `tls://` entry demands TLS.
    pub nats_url: String,
    /// The connector publishes to `<subject_prefix>.<source_id>`.
    #[serde(default = "default_subject_prefix")]
    pub subject_prefix: String,
    pub signing_key_path: String,
    pub transport: Transport,
    /// Native type to entity type overrides; unmapped types keep the
    /// connector's default.
    #[serde(default)]
    pub entity_map: HashMap<String, String>,
    /// MIM `HostilityCodeType`, case exact, for feeds that carry none. Unset,
    /// the connector asserts nothing.
    #[serde(default)]
    pub default_hostility: Option<String>,
    #[serde(default)]
    pub marking: Option<MarkingConfig>,
    /// The sensor's own site, for feeds that report positions relative to it.
    #[serde(default)]
    pub sensor: Option<SensorSite>,
    #[serde(default)]
    pub spool: Option<SpoolSetting>,
    /// Connector-specific settings; each connector deserializes its own keys.
    #[serde(default)]
    pub options: toml::Table,
    /// The generic connector reads `[mapping]` from the same file with its own
    /// loader. Named here so `deny_unknown_fields` still rejects typos.
    #[serde(default, rename = "mapping")]
    _mapping_extension: Option<toml::Value>,
}

impl Config {
    /// Load a config file and validate its marking, the one rule the config
    /// shape cannot express.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| {
            format!("reading config {path} (start from the connector's *.example.toml)")
        })?;
        let cfg: Config = toml::from_str(&text).map_err(|e| {
            let msg = e.to_string();
            match did_you_mean(&msg) {
                Some(hint) => anyhow::anyhow!("parsing config {path}: {msg}\n{hint}"),
                None => anyhow::anyhow!("parsing config {path}: {msg}"),
            }
        })?;
        cfg.marking()
            .map_err(|e| anyhow::anyhow!("parsing config {path}: {e}"))?;
        Ok(cfg)
    }

    /// The validated marking, if the config declares one. Core ignores a tag it
    /// does not recognise, so a bad marking is an error here.
    pub fn marking(&self) -> Result<Option<Marking>, MarkingError> {
        self.marking.as_ref().map(Marking::from_config).transpose()
    }

    /// The spool configuration, whichever form the config used.
    pub fn spool_config(&self) -> Option<SpoolConfig> {
        match &self.spool {
            None => None,
            Some(SpoolSetting::Full(cfg)) => Some(cfg.clone()),
            Some(SpoolSetting::Dir(dir)) => Some(SpoolConfig::with_dir(dir)),
        }
    }

    pub fn enrichment(&self) -> Enrichment {
        Enrichment {
            hostility: self.default_hostility.clone(),
        }
    }
}

/// `Transport::Dds` settings, passed unchanged to the runtime, the doctor and
/// the probe. The type name must match the publisher's, or DDS does not pair
/// the two. Only the default partition is joined.
#[cfg(feature = "dds")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdsOptions {
    /// 0 to [`crate::dds::MAX_DOMAIN`].
    #[serde(default)]
    pub domain: u16,
    pub topic: String,
    /// The publisher's registered type name, e.g. `HelloWorldData::Msg`.
    pub type_name: String,
    #[serde(default)]
    pub reliability: DdsReliability,
    #[serde(default)]
    pub payload: DdsPayload,
    /// Join only on the interface holding this IP.
    #[serde(default)]
    pub interface_ip: Option<String>,
}

#[cfg(feature = "dds")]
impl std::fmt::Display for DdsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dds domain {} topic {} ({})",
            self.domain, self.topic, self.type_name
        )
    }
}

#[cfg(feature = "dds")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DdsReliability {
    /// Pairs with any publisher; samples lost on the wire are not resent.
    #[default]
    BestEffort,
    /// Asks for retransmission; pairs only with reliable publishers.
    Reliable,
}

/// What a DDS sample hands the parser.
#[cfg(feature = "dds")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DdsPayload {
    /// The serialized body as the publisher wrote it.
    #[default]
    Body,
    /// The bytes of a single `sequence<octet>` field, without its length prefix.
    Octets,
    /// The text of a single `string` field, without its length prefix or NUL.
    String,
}

/// `spool = "<dir>"` with defaults, or a full `[spool]` table.
#[derive(Debug, Clone)]
pub enum SpoolSetting {
    Dir(String),
    Full(SpoolConfig),
}

// Hand-rolled so a typo inside [spool] reports the unknown field instead of
// serde's "did not match any variant of untagged enum".
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
                SpoolConfig::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(SpoolSetting::Full)
            }
        }
        d.deserialize_any(V)
    }
}

/// A sensor's fixed WGS-84 site, used to geolocate sensor-relative measurements.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorSite {
    pub lat: f64,
    pub lon: f64,
    /// Height above the WGS-84 ellipsoid.
    #[serde(default)]
    pub alt_m: Option<f64>,
}

/// The enrichment a connector applies: the operator-asserted hostility for
/// feeds that carry none of their own.
#[derive(Debug, Clone, Default)]
pub struct Enrichment {
    /// `None`: not asserted, so the connector emits no hostility.
    pub hostility: Option<String>,
}

impl Enrichment {
    pub fn with_hostility(mut self, hostility: impl Into<String>) -> Self {
        self.hostility = Some(hostility.into());
        self
    }
}

// serde has no container default for enum variants or for structs with
// required fields, so these defaults are per field.
fn default_subject_prefix() -> String {
    "ajar.ingest".to_string()
}

fn default_http_path() -> String {
    "/".to_string()
}

fn default_replay_speed() -> f64 {
    1.0
}

fn default_replay_max_gap_ms() -> u64 {
    5_000
}

#[cfg(feature = "serial")]
fn default_baud() -> u32 {
    38400
}

#[cfg(feature = "rest-poll")]
fn default_interval() -> u64 {
    30
}

/// How a native feed reaches the connector, selected by `kind` in the
/// `[transport]` table. The feature-gated kinds need the matching Cargo feature.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Transport {
    UdpMulticast {
        bind: String,
        group: String,
        /// Interface IP to join on; overrides the bind IP.
        #[serde(default)]
        interface: Option<String>,
    },
    Udp {
        bind: String,
    },
    /// Listen and accept sources that push their feed.
    TcpServer {
        bind: String,
        #[serde(default)]
        framing: Framing,
    },
    /// Connect out to a feed, reconnecting if it drops.
    TcpClient {
        connect: String,
        #[serde(default)]
        framing: Framing,
    },
    /// Read each file dropped into a directory once its size settles.
    Dir {
        path: String,
        /// Also read files present at startup.
        #[serde(default)]
        process_existing: bool,
    },
    /// Follow a file a source appends to.
    File {
        path: String,
        /// Read existing content before following appends.
        #[serde(default)]
        from_start: bool,
        #[serde(default)]
        framing: Framing,
    },
    /// Run a command and read its stdout, one line per frame.
    Exec {
        command: String,
        #[serde(default)]
        args: Vec<String>,
    },
    Stdin {
        #[serde(default)]
        framing: Framing,
    },
    /// Accept webhook deliveries; each request body is one frame. A `token`
    /// without TLS refuses to start.
    HttpServer {
        bind: String,
        /// Path a delivery must target; anything else gets 404.
        #[serde(default = "default_http_path")]
        path: String,
        /// Shared secret required in the `X-Ajar-Token` header.
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        tls_cert: Option<String>,
        #[serde(default)]
        tls_key: Option<String>,
        /// CA bundle client certificates must chain to; enables mutual TLS.
        #[serde(default)]
        tls_client_ca: Option<String>,
    },
    /// Replay a classic pcap (Ethernet/IPv4/UDP) with its original timing.
    PcapReplay {
        path: String,
        /// Time scale: 1.0 is real time.
        #[serde(default = "default_replay_speed")]
        speed: f64,
        #[serde(default, rename = "loop")]
        looping: bool,
        /// Only datagrams to this UDP port.
        #[serde(default)]
        port: Option<u16>,
        /// Longest gap honoured between packets.
        #[serde(default = "default_replay_max_gap_ms")]
        max_gap_ms: u64,
    },
    #[cfg(feature = "serial")]
    Serial {
        device: String,
        #[serde(default = "default_baud")]
        baud: u32,
    },
    #[cfg(feature = "dds")]
    Dds(DdsOptions),
    #[cfg(feature = "mqtt")]
    Mqtt {
        /// `host:port`.
        host: String,
        /// Wildcards allowed.
        topic: String,
    },
    /// Connect out to a WebSocket feed; each message is one frame.
    #[cfg(feature = "websocket")]
    WsClient {
        url: String,
        /// Sent after every handshake, including reconnects.
        #[serde(default)]
        subscribe: Option<String>,
        /// Extra handshake headers, typically authentication.
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    /// GET a URL on an interval; each response body is one frame.
    #[cfg(feature = "rest-poll")]
    RestPoll {
        url: String,
        #[serde(default = "default_interval")]
        interval_secs: u64,
        /// `Authorization` header value.
        #[serde(default)]
        auth_header: Option<String>,
    },
}

/// How a byte stream is split into frames.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Framing {
    /// One newline-delimited line per frame.
    #[default]
    Line,
    /// A 2-byte big-endian length prefix, then the payload.
    LengthDelimited,
    /// A 4-byte little-endian length prefix, then the payload: BSI Flex 335
    /// (SAPIENT) over TCP.
    LengthU32le,
}

/// For an unknown-field or unknown-variant parse error, the closest name the
/// config accepts, as a one-line hint.
fn did_you_mean(msg: &str) -> Option<String> {
    let (what, rest) = msg
        .split_once("unknown field `")
        .map(|(_, r)| ("field", r))
        .or_else(|| {
            msg.split_once("unknown variant `")
                .map(|(_, r)| ("value", r))
        })?;
    let (typo, rest) = rest.split_once('`')?;
    // A transport kind left out of this build is not a typo; the nearest name
    // would point the wrong way.
    if what == "value" {
        if let Some((kind, feature)) = FEATURE_GATED_KINDS.iter().find(|(k, _)| *k == typo) {
            return Some(format!(
                "the {kind:?} transport exists but this binary was built without the \
                 `{feature}` feature; rebuild with --features {feature}, or use a build \
                 that ships it"
            ));
        }
    }
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

/// Transport kinds behind Cargo features, with the feature that provides each.
const FEATURE_GATED_KINDS: &[(&str, &str)] = &[
    ("dds", "dds"),
    ("serial", "serial"),
    ("mqtt", "mqtt"),
    ("rest-poll", "rest-poll"),
    ("ws-client", "websocket"),
];

/// Levenshtein distance.
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

    const BASE: &str =
        "source_id = \"x\"\nnats_url = \"nats://h:4222\"\nsigning_key_path = \"k\"\n\
                        [transport]\nkind = \"udp\"\nbind = \"0.0.0.0:1\"\n";
    const STDIN_BASE: &str = "source_id='s'\nnats_url='nats://x:4222'\nsigning_key_path='k'\n\
                              [transport]\nkind='stdin'\n";

    fn load(body: &str) -> anyhow::Result<Config> {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), body).unwrap();
        Config::load(file.path().to_str().unwrap())
    }

    fn transport(toml_str: &str) -> Transport {
        #[derive(Deserialize)]
        struct W {
            transport: Transport,
        }
        toml::from_str::<W>(toml_str).unwrap().transport
    }

    #[test]
    fn field_typo_suggests_the_right_name() {
        let msg = load(&BASE.replace("nats_url", "nats_ur"))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("unknown field `nats_ur`"), "{msg}");
        assert!(msg.contains("did you mean the field `nats_url`?"), "{msg}");
    }

    #[test]
    fn kind_typo_suggests_the_right_kind() {
        let msg = load(
            "source_id = \"x\"\nnats_url = \"nats://h:4222\"\nsigning_key_path = \"k\"\n\
             [transport]\nkind = \"udp-multicst\"\nbind = \"0.0.0.0:1\"\ngroup = \"239.1.1.1\"\n",
        )
        .unwrap_err()
        .to_string();
        assert!(
            msg.contains("did you mean the value `udp-multicast`?"),
            "{msg}"
        );
    }

    #[test]
    fn marking_block_is_validated_at_load() {
        let m = load(&format!(
            "{BASE}[marking]\nclassification = \"Restricted\"\nreleasable_to = [\"GBR\", \"ITA\"]\n\
             policy = \"NATO\"\ncaveats = [\"EXERCISE\"]\n"
        ))
        .unwrap()
        .marking()
        .unwrap()
        .unwrap();
        assert_eq!(
            m.to_string(),
            "class:restricted policy:NATO rel:GBR rel:ITA caveat:EXERCISE"
        );

        let msg = load(&format!(
            "{BASE}[marking]\nclassification = \"official-sensitive\"\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(msg.contains("parsing config"), "{msg}");
        assert!(msg.contains("official-sensitive"), "{msg}");
        assert!(msg.contains("top-secret"), "{msg}");

        let msg = load(&format!("{BASE}[marking]\nclasification = \"secret\"\n"))
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("did you mean the field `classification`?"),
            "{msg}"
        );

        assert!(load(BASE).unwrap().marking().unwrap().is_none());
    }

    #[test]
    fn missing_config_points_at_the_example() {
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
    fn uncompiled_kind_is_named_not_corrected() {
        let hint =
            did_you_mean("unknown variant `dds`, expected one of `udp-multicast`, `udp`, `dir`")
                .unwrap();
        assert!(hint.contains("built without the `dds` feature"), "{hint}");
        assert!(!hint.contains("did you mean"), "{hint}");
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

    #[test]
    fn each_transport_kind_parses() {
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
            Transport::Stdin {
                framing: Framing::Line
            }
        ));
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
    fn missing_required_field_is_a_parse_error() {
        #[derive(Deserialize)]
        struct W {
            #[allow(dead_code)] // only parsed
            transport: Transport,
        }
        let bad = "[transport]\nkind='udp-multicast'\nbind='0.0.0.0:6969'";
        assert!(toml::from_str::<W>(bad).is_err());
    }

    #[test]
    fn typo_in_any_table_names_the_field() {
        let base = "source_id='s'\nnats_url='nats://x:4222'\nsigning_key_path='k'\n";
        for (bad, field) in [
            (
                format!("{base}defaut_hostility='Friend'\n[transport]\nkind='stdin'\n"),
                "defaut_hostility",
            ),
            (
                format!("{base}[transport]\nkind='udp'\nbindd='0.0.0.0:1'\n"),
                "bindd",
            ),
            (
                format!("{STDIN_BASE}[spool]\ndir='/d'\nmax_byte=1\n"),
                "max_byte",
            ),
            (format!("{STDIN_BASE}[sensor]\nlat=1.0\nlonn=2.0\n"), "lonn"),
        ] {
            let err = toml::from_str::<Config>(&bad).unwrap_err().to_string();
            assert!(err.contains(field), "{err}");
        }
        let ok = format!("{STDIN_BASE}[mapping]\nentity_type='mim:vessel'\n");
        assert!(
            toml::from_str::<Config>(&ok).is_ok(),
            "[mapping] is the tolerated extension"
        );
    }

    #[test]
    fn spool_takes_a_path_or_a_table() {
        let cfg: Config = toml::from_str(STDIN_BASE).unwrap();
        assert!(cfg.spool_config().is_none());

        let cfg: Config =
            toml::from_str(&format!("spool = '/var/lib/ajar/spool'\n{STDIN_BASE}")).unwrap();
        let spool = cfg.spool_config().unwrap();
        assert_eq!(spool.dir, "/var/lib/ajar/spool");
        assert_eq!(spool.max_bytes, 256 * 1024 * 1024);
        assert!((spool.drain_rate - 50.0).abs() < f64::EPSILON);

        let cfg: Config = toml::from_str(&format!(
            "{STDIN_BASE}[spool]\ndir='/data/spool'\nmax_bytes=1024\ndrain_rate=7.5\n"
        ))
        .unwrap();
        let spool = cfg.spool_config().unwrap();
        assert_eq!(spool.dir, "/data/spool");
        assert_eq!(spool.max_bytes, 1024);
        assert!((spool.drain_rate - 7.5).abs() < f64::EPSILON);
    }
}
