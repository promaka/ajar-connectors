// SPDX-License-Identifier: Apache-2.0
//! The parser: one SAPIENT message in, zero or one canonical event out.
//!
//! BSI Flex 335 carries nine message kinds in one envelope. Four describe the
//! world and become events: a detection report (`sapient:detection`, or
//! `sapient:track` when the node is following the object), a status report
//! and a registration (`sapient:sensor-status`), and an alert
//! (`sapient:alert`). The rest are the fusion node's side of the conversation
//! (tasks, acknowledgements, errors); they are counted and publish nothing.
//!
//! Every event seals the message's protobuf bytes verbatim in `payload`, so a
//! field this parser does not map survives for a later ontology. Positions
//! come out as WGS-84 degrees and metres; a range-and-bearing report is
//! geolocated against the node's last reported position when there is one, and
//! rides as metadata when there is not. Velocity becomes speed, course and
//! vertical rate in the contract's units.

use std::collections::HashMap;
use std::f64::consts::PI;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, GovernedAttribute, ParseError};
use ajar_sapient_wire::v2::sapient_message::Content;
use ajar_sapient_wire::v2::{self, detection_report, registration, status_report};

/// Mean Earth radius, metres (IUGG), for geolocating range and bearing.
const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// Entity types this connector emits. Registered with Core from
/// `sapient.types.json`.
pub const TYPE_DETECTION: &str = "sapient:detection";
pub const TYPE_TRACK: &str = "sapient:track";
pub const TYPE_SENSOR_STATUS: &str = "sapient:sensor-status";
pub const TYPE_ALERT: &str = "sapient:alert";

/// Which side of the interface this connector plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// The fusion node's message handler: edge nodes connect in, register and
    /// are acknowledged. Needs the `tcp-server` transport.
    Dmm,
    /// A listener on a fusion node's output, or a capture. Any transport.
    Subscriber,
}

/// The connector's `[options]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub role: Role,
    /// This node's identity, carried in every acknowledgement the `dmm` role
    /// sends. Made fresh at start-up when the config does not set it.
    pub node_id: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionsTable {
    #[serde(default = "default_role")]
    role: Role,
    #[serde(default)]
    node_id: Option<String>,
}

fn default_role() -> Role {
    Role::Dmm
}

impl Options {
    /// Read the `[options]` table. An unknown key is refused, since a typo
    /// there would silently leave a default in force.
    pub fn from_table(table: &toml::Table) -> anyhow::Result<Self> {
        let t: OptionsTable = table.clone().try_into()?;
        let node_id = match t.node_id {
            Some(id) if !id.trim().is_empty() => id,
            _ => uuid::Uuid::new_v4().to_string(),
        };
        Ok(Self {
            role: t.role,
            node_id,
        })
    }
}

/// Every way a message can be refused. None of them is a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SapientError {
    /// The bytes are not a SAPIENT message.
    Decode(String),
    /// The envelope carries no content.
    Empty,
    /// The SDK refused the event.
    Build(String),
}

impl fmt::Display for SapientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "not a SAPIENT message: {e}"),
            Self::Empty => write!(f, "SAPIENT envelope carries no content"),
            Self::Build(e) => write!(f, "event rejected by the SDK: {e}"),
        }
    }
}

impl std::error::Error for SapientError {}

/// What the connector remembers about each node, from its registration and
/// status reports, to make sense of its detections.
#[derive(Debug, Clone, Default)]
struct Node {
    name: Option<String>,
    node_type: Option<String>,
    /// The node's last reported position, WGS-84 degrees and metres.
    location: Option<(f64, f64, f64)>,
    /// The node declared its velocities in km/h rather than m/s.
    velocity_kph: bool,
}

/// Nodes remembered at once. A fusion node's whole fleet is far below this;
/// the bound exists so a hostile stream of node ids cannot grow memory.
const MAX_NODES: usize = 4096;

#[derive(Default)]
struct Counters {
    /// Messages of a kind that publishes nothing (task, ack, error).
    unmapped: Arc<AtomicU64>,
    /// Range-and-bearing reports published without a position, because the
    /// node's own position was not known or its bearing datum was magnetic.
    unlocated: Arc<AtomicU64>,
    /// Registrations seen.
    registrations: Arc<AtomicU64>,
}

/// The connector: holds its Ajar identity, the operator's choices and what it
/// has learnt about each node.
pub struct SapientParser {
    source_id: String,
    enrichment: Enrichment,
    /// SAPIENT classification type (lower-cased) to the entity type it becomes.
    entity_map: HashMap<String, String>,
    nodes: Mutex<HashMap<String, Node>>,
    counters: Counters,
    /// The acceptor's counters, when this connector is the fusion node, so
    /// they reach `/metrics` with the parser's.
    dmm: Option<Arc<crate::dmm::DmmCounters>>,
}

impl SapientParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
            entity_map: HashMap::new(),
            nodes: Mutex::new(HashMap::new()),
            counters: Counters::default(),
            dmm: None,
        }
    }

    /// Publish the fusion-node acceptor's counters alongside the parser's.
    pub fn with_dmm_counters(mut self, counters: Arc<crate::dmm::DmmCounters>) -> Self {
        self.dmm = Some(counters);
        self
    }

    /// Apply the operator's `[entity_map]`: a SAPIENT classification type to
    /// the Ajar entity type a detection of it becomes. Each target must be a
    /// namespaced type.
    pub fn with_entity_map(mut self, map: &HashMap<String, String>) -> anyhow::Result<Self> {
        for (class, entity_type) in map {
            if !entity_type.contains(':') {
                anyhow::bail!(
                    "[entity_map] {class:?} = {entity_type:?}: an entity type is namespaced, \
                     e.g. mim:aircraft or sapient:detection"
                );
            }
            self.entity_map
                .insert(class.trim().to_lowercase(), entity_type.clone());
        }
        Ok(self)
    }

    /// Decode one message and build its event, if its kind publishes one.
    pub fn parse_message(&self, frame: &[u8]) -> Result<Option<Event>, SapientError> {
        let message =
            ajar_sapient_wire::decode(frame).map_err(|e| SapientError::Decode(e.to_string()))?;
        let observed = message
            .timestamp
            .as_ref()
            .and_then(ajar_sapient_wire::rfc3339);
        let node_id = message.node_id.clone().unwrap_or_default();
        let content = message.content.ok_or(SapientError::Empty)?;
        let built = match content {
            Content::DetectionReport(report) => {
                Some(self.detection(&node_id, &report, observed.as_deref(), frame))
            }
            Content::StatusReport(report) => {
                Some(self.status(&node_id, &report, observed.as_deref(), frame))
            }
            Content::Registration(reg) => {
                self.counters.registrations.fetch_add(1, Ordering::Relaxed);
                Some(self.registration(&node_id, &reg, observed.as_deref(), frame))
            }
            Content::Alert(alert) => Some(self.alert(&node_id, &alert, observed.as_deref(), frame)),
            Content::RegistrationAck(_)
            | Content::Task(_)
            | Content::TaskAck(_)
            | Content::AlertAck(_)
            | Content::Error(_) => {
                self.counters.unmapped.fetch_add(1, Ordering::Relaxed);
                None
            }
        };
        built
            .transpose()
            .map_err(|e| SapientError::Build(e.to_string()))
    }

    fn node(&self, node_id: &str) -> Node {
        self.nodes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(node_id)
            .cloned()
            .unwrap_or_default()
    }

    fn update_node(&self, node_id: &str, f: impl FnOnce(&mut Node)) {
        let mut nodes = self.nodes.lock().unwrap_or_else(|p| p.into_inner());
        if !nodes.contains_key(node_id) && nodes.len() >= MAX_NODES {
            // Drop one so the newcomer fits; the fleet is nowhere near this.
            if let Some(victim) = nodes.keys().next().cloned() {
                nodes.remove(&victim);
            }
        }
        f(nodes.entry(node_id.to_string()).or_default());
    }

    /// Common start of every event: identity, time, the raw message, and the
    /// operator's hostility if any.
    fn builder(
        &self,
        entity_type: &str,
        node_id: &str,
        observed: Option<&str>,
        raw: &[u8],
    ) -> EventBuilder {
        let mut b = EventBuilder::new(&self.source_id, entity_type)
            .allow_unnamespaced_entity_type()
            .new_id()
            .payload(raw.to_vec())
            .metadata("node_id", node_id)
            .metadata("sapient_version", ajar_sapient_wire::ICD_VERSION_V2);
        b = match observed {
            Some(ts) => b.timestamp(ts),
            None => b.now(),
        };
        if let Some(h) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", h);
        }
        b
    }

    fn detection(
        &self,
        node_id: &str,
        r: &v2::DetectionReport,
        observed: Option<&str>,
        raw: &[u8],
    ) -> Result<Event, ajar_connector::BuildError> {
        let node = self.node(node_id);
        let top = top_classification(&r.classification);
        let entity_type = top
            .and_then(|(class, _)| self.entity_map.get(&class.to_lowercase()))
            .map(String::as_str)
            .unwrap_or(if r.track_info.is_empty() {
                TYPE_DETECTION
            } else {
                TYPE_TRACK
            })
            .to_string();
        let mut b = self.builder(&entity_type, node_id, observed, raw);
        // The object's identifier keeps it its own track across reports.
        let object_id = r.object_id.clone().unwrap_or_default();
        b = b.metadata("source_uid", format!("{node_id}:{object_id}"));
        b = b.metadata("object_id", object_id);
        if let Some(id) = &r.report_id {
            b = b.metadata("report_id", id);
        }
        if let Some(id) = &r.task_id {
            b = b.metadata("task_id", id);
        }
        if let Some(c) = r.detection_confidence {
            if (0.0..=1.0).contains(&c) {
                b = b.confidence(f64::from(c));
            }
        }

        // Position, in whichever form the node reported it.
        match &r.location_oneof {
            Some(detection_report::LocationOneof::Location(loc)) => {
                b = self.place(b, &entity_type, loc, "location");
            }
            Some(detection_report::LocationOneof::RangeBearing(rb)) => {
                b = self.place_relative(b, &entity_type, node.location, rb);
            }
            None => {}
        }

        // Velocity: ENU components in the node's declared units.
        if let Some(detection_report::VelocityOneof::EnuVelocity(v)) = &r.velocity_oneof {
            let scale = if node.velocity_kph {
                1000.0 / 3600.0
            } else {
                1.0
            };
            if let (Some(e), Some(n)) = (v.east_rate, v.north_rate) {
                let (e, n) = (e * scale, n * scale);
                let speed = (e * e + n * n).sqrt();
                let course = (e.atan2(n).to_degrees() + 360.0) % 360.0;
                b = b.governed(&entity_type, "speed", fixed(speed, 2));
                b = b.governed(&entity_type, "course", fixed(course, 1));
            }
            if let Some(up) = v.up_rate {
                b = b.governed(&entity_type, "vertical_rate", fixed(up * scale, 2));
            }
            if node.velocity_kph {
                b = b.metadata("velocity_units", "km/h");
            }
        }

        if let Some((class, confidence)) = top {
            b = b.governed(&entity_type, "sapient_classification", class);
            b = b.governed(&entity_type, "object_class", class);
            if let Some(c) = confidence {
                b = b.governed(
                    &entity_type,
                    "sapient_classification_confidence",
                    fixed(f64::from(c), 3),
                );
            }
        }
        for (i, c) in r.classification.iter().enumerate().skip(1) {
            if let Some(t) = &c.r#type {
                b = b.metadata(format!("classification_{i}"), t);
            }
        }
        if let Some(behaviour) = r.behaviour.iter().find_map(|x| x.r#type.as_deref()) {
            b = b.governed(&entity_type, "sapient_behaviour", behaviour);
        }
        if let Some(state) = &r.state {
            b = b.governed(&entity_type, "sapient_state", state);
        }
        if let Some(id) = &r.id {
            b = b.metadata("native_id", id);
        }
        if let Some(colour) = &r.colour {
            b = b.metadata("colour", colour);
        }
        for info in r.track_info.iter().chain(r.object_info.iter()) {
            if let (Some(t), Some(v)) = (&info.r#type, &info.value) {
                b = b.metadata(format!("info_{}", key_safe(t)), v);
            }
        }
        for (i, s) in r.signal.iter().enumerate() {
            if let Some(f) = s.centre_frequency {
                b = b.metadata(
                    format!("signal_{i}_centre_frequency"),
                    fixed(f64::from(f), 1),
                );
            }
            if let Some(a) = s.amplitude {
                b = b.metadata(format!("signal_{i}_amplitude"), fixed(f64::from(a), 1));
            }
        }
        for (i, f) in r.associated_file.iter().enumerate() {
            if let Some(url) = &f.url {
                b = b.metadata(format!("file_{i}_url"), url);
            }
        }
        if let Some(name) = &node.name {
            b = b.metadata("node_name", name);
        }
        b.build()
    }

    /// A WGS-84 position from a `Location`, when its units say it is one.
    fn place(
        &self,
        b: EventBuilder,
        entity_type: &str,
        loc: &v2::Location,
        prefix: &str,
    ) -> EventBuilder {
        match wgs84(loc) {
            Some((lat, lon, alt)) => {
                let mut b = b.location(lat, lon, alt);
                if loc.z.is_none() {
                    b = b.metadata("altitude_known", "false");
                }
                if let (Some(xe), Some(ye)) = (loc.x_error, loc.y_error) {
                    // Errors come in the coordinate's own units; only metres
                    // are a position accuracy the contract understands.
                    if loc.coordinate_system == Some(v2::LocationCoordinateSystem::UtmM as i32) {
                        b = b.governed(
                            entity_type,
                            "position_accuracy_h_m",
                            fixed((xe * xe + ye * ye).sqrt(), 1),
                        );
                    } else {
                        b = b.metadata(format!("{prefix}_x_error"), fixed(xe, 6));
                        b = b.metadata(format!("{prefix}_y_error"), fixed(ye, 6));
                    }
                }
                b
            }
            None => {
                // UTM or unspecified units: kept as the node sent them.
                let mut b = b;
                if let Some(x) = loc.x {
                    b = b.metadata(format!("{prefix}_x"), fixed(x, 3));
                }
                if let Some(y) = loc.y {
                    b = b.metadata(format!("{prefix}_y"), fixed(y, 3));
                }
                if let Some(z) = loc.z {
                    b = b.metadata(format!("{prefix}_z"), fixed(z, 3));
                }
                if let Some(zone) = &loc.utm_zone {
                    b = b.metadata(format!("{prefix}_utm_zone"), zone);
                }
                b = b.metadata(
                    format!("{prefix}_coordinate_system"),
                    coordinate_system_name(loc.coordinate_system),
                );
                b
            }
        }
    }

    /// A position from range and bearing, against the node's last position.
    fn place_relative(
        &self,
        mut b: EventBuilder,
        entity_type: &str,
        node_location: Option<(f64, f64, f64)>,
        rb: &v2::RangeBearing,
    ) -> EventBuilder {
        let (angle_scale, range_scale) = match rb
            .coordinate_system
            .and_then(|c| v2::RangeBearingCoordinateSystem::try_from(c).ok())
        {
            Some(v2::RangeBearingCoordinateSystem::DegreesM) => (1.0, 1.0),
            Some(v2::RangeBearingCoordinateSystem::RadiansM) => (180.0 / PI, 1.0),
            Some(v2::RangeBearingCoordinateSystem::DegreesKm) => (1.0, 1000.0),
            Some(v2::RangeBearingCoordinateSystem::RadiansKm) => (180.0 / PI, 1000.0),
            _ => (f64::NAN, f64::NAN),
        };
        let azimuth = rb.azimuth.map(|a| a * angle_scale);
        let elevation = rb.elevation.map(|e| e * angle_scale).unwrap_or(0.0);
        let range = rb.range.map(|r| r * range_scale);
        if let Some(a) = azimuth {
            if a.is_finite() {
                b = b.metadata("bearing_deg", fixed(a, 2));
            }
        }
        if let Some(r) = range {
            if r.is_finite() {
                b = b.metadata("range_m", fixed(r, 1));
            }
        }
        let true_north = rb.datum == Some(v2::RangeBearingDatum::True as i32);
        match (node_location, azimuth, range) {
            (Some((lat0, lon0, alt0)), Some(az), Some(r))
                if true_north && az.is_finite() && r.is_finite() && r >= 0.0 =>
            {
                let horizontal = r * elevation.to_radians().cos();
                let (lat, lon) = destination(lat0, lon0, az, horizontal);
                let alt = alt0 + r * elevation.to_radians().sin();
                b = b.location(lat, lon, alt);
                if let Some(re) = rb.range_error {
                    b = b.governed(
                        entity_type,
                        "position_accuracy_h_m",
                        fixed(re * range_scale, 1),
                    );
                }
                b
            }
            _ => {
                self.counters.unlocated.fetch_add(1, Ordering::Relaxed);
                let reason = if !true_north {
                    "bearing datum is not true north"
                } else if node_location.is_none() {
                    "node position not yet reported"
                } else {
                    "range or bearing missing"
                };
                b.metadata("unlocated_reason", reason)
            }
        }
    }

    fn status(
        &self,
        node_id: &str,
        r: &v2::StatusReport,
        observed: Option<&str>,
        raw: &[u8],
    ) -> Result<Event, ajar_connector::BuildError> {
        if let Some(loc) = &r.node_location {
            if let Some(pos) = wgs84(loc) {
                self.update_node(node_id, |n| n.location = Some(pos));
            }
        }
        let node = self.node(node_id);
        let t = TYPE_SENSOR_STATUS;
        let mut b = self.builder(t, node_id, observed, raw);
        b = b.metadata("source_uid", node_id);
        if let Some(id) = &r.report_id {
            b = b.metadata("report_id", id);
        }
        if let Some(loc) = &r.node_location {
            b = self.place(b, t, loc, "node");
        }
        if let Some(system) = r
            .system
            .and_then(|s| status_report::System::try_from(s).ok())
        {
            let name = match system {
                status_report::System::Ok => Some("OK"),
                status_report::System::Warning => Some("WARNING"),
                status_report::System::Error => Some("ERROR"),
                status_report::System::Goodbye => Some("GOODBYE"),
                status_report::System::Unspecified => None,
            };
            if let Some(name) = name {
                b = b.governed(t, "sapient_system", name);
            }
        }
        if let Some(mode) = &r.mode {
            b = b.governed(t, "sapient_mode", mode);
        }
        if let Some(power) = &r.power {
            if let Some(level) = power.level {
                if (0..=100).contains(&level) {
                    b = b.governed(t, "sapient_power_level", level.to_string());
                }
            }
            b = b.metadata(
                "power_source",
                enum_name(
                    status_report::PowerSource::try_from(power.source)
                        .ok()
                        .map(|s| s.as_str_name()),
                    "POWERSOURCE_",
                ),
            );
            b = b.metadata(
                "power_status",
                enum_name(
                    status_report::PowerStatus::try_from(power.status)
                        .ok()
                        .map(|s| s.as_str_name()),
                    "POWERSTATUS_",
                ),
            );
        }
        if let Some(task) = &r.active_task_id {
            b = b.metadata("active_task_id", task);
        }
        for s in &r.status {
            let kind = enum_name(
                s.status_type
                    .and_then(|t| status_report::StatusType::try_from(t).ok())
                    .map(|t| t.as_str_name()),
                "STATUS_TYPE_",
            );
            let level = enum_name(
                s.status_level
                    .and_then(|l| status_report::StatusLevel::try_from(l).ok())
                    .map(|l| l.as_str_name()),
                "STATUS_LEVEL_",
            );
            let value = s.status_value.clone().unwrap_or_default();
            b = b.metadata(
                format!("status_{}", kind.to_lowercase()),
                format!("{level}: {value}"),
            );
        }
        if let Some(nt) = &node.node_type {
            b = b.governed(t, "sapient_node_type", nt);
        }
        if let Some(name) = &node.name {
            b = b.metadata("node_name", name);
        }
        b.build()
    }

    fn registration(
        &self,
        node_id: &str,
        reg: &v2::Registration,
        observed: Option<&str>,
        raw: &[u8],
    ) -> Result<Event, ajar_connector::BuildError> {
        let node_type = reg
            .node_definition
            .first()
            .and_then(|d| d.node_type)
            .and_then(|t| registration::NodeType::try_from(t).ok())
            .map(|t| enum_name(Some(t.as_str_name()), "NODE_TYPE_"));
        let velocity_kph = reg.mode_definition.iter().any(|m| {
            m.detection_definition.iter().any(|d| {
                d.velocity_type
                    .as_ref()
                    .and_then(|v| v.velocity_units_oneof.as_ref())
                    .map(|u| match u {
                        registration::velocity_type::VelocityUnitsOneof::EnuVelocityUnits(e) => {
                            e.east_north_rate_units == Some(v2::SpeedUnits::Kph as i32)
                        }
                    })
                    .unwrap_or(false)
            })
        });
        self.update_node(node_id, |n| {
            n.name = reg.name.clone();
            n.node_type = node_type.clone();
            n.velocity_kph = velocity_kph;
        });
        let t = TYPE_SENSOR_STATUS;
        let mut b = self.builder(t, node_id, observed, raw);
        b = b.metadata("source_uid", node_id);
        b = b.metadata("sapient_message", "registration");
        if let Some(nt) = &node_type {
            b = b.governed(t, "sapient_node_type", nt);
        }
        if let Some(name) = &reg.name {
            b = b.metadata("node_name", name);
        }
        if let Some(short) = &reg.short_name {
            b = b.metadata("node_short_name", short);
        }
        if let Some(v) = &reg.icd_version {
            b = b.metadata("icd_version", v);
        }
        if let Some(interval) = reg
            .status_definition
            .as_ref()
            .and_then(|s| s.status_interval.as_ref())
            .and_then(duration_seconds)
        {
            b = b.governed(t, "update_interval_s", fixed(interval, 1));
        }
        for sub in reg
            .node_definition
            .iter()
            .flat_map(|d| d.node_sub_type.iter())
        {
            b = b.metadata("node_sub_type", sub);
        }
        for (i, c) in reg.capabilities.iter().enumerate() {
            let text = [
                c.category.as_deref(),
                c.r#type.as_deref(),
                c.value.as_deref(),
                c.units.as_deref(),
            ]
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
            b = b.metadata(format!("capability_{i}"), text);
        }
        if let Some(c) = reg.config_data.first() {
            if !c.manufacturer.is_empty() {
                b = b.metadata("manufacturer", &c.manufacturer);
            }
            if !c.model.is_empty() {
                b = b.metadata("model", &c.model);
            }
            if let Some(serial) = &c.serial_number {
                b = b.metadata("serial_number", serial);
            }
        }
        b.build()
    }

    fn alert(
        &self,
        node_id: &str,
        a: &v2::Alert,
        observed: Option<&str>,
        raw: &[u8],
    ) -> Result<Event, ajar_connector::BuildError> {
        let node = self.node(node_id);
        let t = TYPE_ALERT;
        let mut b = self.builder(t, node_id, observed, raw);
        let alert_id = a.alert_id.clone().unwrap_or_default();
        b = b.metadata("source_uid", format!("{node_id}:{alert_id}"));
        b = b.metadata("alert_id", alert_id);
        if let Some(kind) = a
            .alert_type
            .and_then(|x| v2::alert::AlertType::try_from(x).ok())
        {
            if kind != v2::alert::AlertType::Unspecified {
                b = b.governed(
                    t,
                    "sapient_alert_type",
                    enum_name(Some(kind.as_str_name()), "ALERT_TYPE_"),
                );
            }
        }
        if let Some(status) = a
            .status
            .and_then(|x| v2::alert::AlertStatus::try_from(x).ok())
        {
            if status != v2::alert::AlertStatus::Unspecified {
                b = b.governed(
                    t,
                    "sapient_alert_status",
                    enum_name(Some(status.as_str_name()), "ALERT_STATUS_"),
                );
            }
        }
        if let Some(p) = a
            .priority
            .and_then(|x| v2::alert::DiscretePriority::try_from(x).ok())
        {
            if p != v2::alert::DiscretePriority::Unspecified {
                b = b.governed(
                    t,
                    "sapient_priority",
                    enum_name(Some(p.as_str_name()), "DISCRETE_PRIORITY_"),
                );
            }
        }
        if let Some(r) = a.ranking {
            if (0.0..=1.0).contains(&r) {
                b = b.governed(t, "sapient_ranking", fixed(f64::from(r), 3));
            }
        }
        if let Some(c) = a.confidence {
            if (0.0..=1.0).contains(&c) {
                b = b.confidence(f64::from(c));
            }
        }
        if let Some(d) = &a.description {
            b = b.metadata("description", d);
        }
        if let Some(region) = &a.region_id {
            b = b.metadata("region_id", region);
        }
        match &a.location_oneof {
            Some(v2::alert::LocationOneof::Location(loc)) => b = self.place(b, t, loc, "location"),
            Some(v2::alert::LocationOneof::RangeBearing(rb)) => {
                b = self.place_relative(b, t, node.location, rb)
            }
            None => {}
        }
        b.build()
    }
}

/// The one piece of glue that plugs this format into the shared runtime.
impl FrameParser for SapientParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        match self.parse_message(frame) {
            Ok(Some(event)) => Ok(vec![event]),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(Box::new(e) as ParseError),
        }
    }

    fn counters(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
        let mut all = vec![
            ("sapient_unmapped_total", self.counters.unmapped.clone()),
            ("sapient_unlocated_total", self.counters.unlocated.clone()),
            (
                "sapient_registrations_total",
                self.counters.registrations.clone(),
            ),
        ];
        if let Some(dmm) = &self.dmm {
            all.push(("sapient_acknowledged_total", dmm.registrations.clone()));
            all.push(("sapient_bad_framing_total", dmm.bad_framing.clone()));
        }
        all
    }
}

/// The classification with the highest confidence, and that confidence.
fn top_classification(
    classes: &[detection_report::DetectionReportClassification],
) -> Option<(&str, Option<f32>)> {
    classes
        .iter()
        .filter_map(|c| c.r#type.as_deref().map(|t| (t, c.confidence)))
        .max_by(|a, b| {
            a.1.unwrap_or(-1.0)
                .partial_cmp(&b.1.unwrap_or(-1.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

/// A `Location` as WGS-84 degrees and metres, when its units say it is one.
fn wgs84(loc: &v2::Location) -> Option<(f64, f64, f64)> {
    let system = v2::LocationCoordinateSystem::try_from(loc.coordinate_system?).ok()?;
    let (x, y) = (loc.x?, loc.y?);
    let (lat, lon) = match system {
        v2::LocationCoordinateSystem::LatLngDegM => (y, x),
        v2::LocationCoordinateSystem::LatLngRadM => (y.to_degrees(), x.to_degrees()),
        _ => return None,
    };
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    let alt = loc.z.unwrap_or(0.0);
    (lat.is_finite() && lon.is_finite() && alt.is_finite()).then_some((lat, lon, alt))
}

/// The point `distance_m` along `bearing_deg` (true) from a start, on a
/// sphere of mean radius: better than a metre at counter-UAS ranges.
fn destination(lat_deg: f64, lon_deg: f64, bearing_deg: f64, distance_m: f64) -> (f64, f64) {
    let (lat1, lon1, brg) = (
        lat_deg.to_radians(),
        lon_deg.to_radians(),
        bearing_deg.to_radians(),
    );
    let d = distance_m / EARTH_RADIUS_M;
    let lat2 = (lat1.sin() * d.cos() + lat1.cos() * d.sin() * brg.cos()).asin();
    let lon2 = lon1 + (brg.sin() * d.sin() * lat1.cos()).atan2(d.cos() - lat1.sin() * lat2.sin());
    let lon2 = (lon2.to_degrees() + 540.0) % 360.0 - 180.0;
    (lat2.to_degrees(), lon2)
}

fn duration_seconds(d: &registration::Duration) -> Option<f64> {
    let value = f64::from(d.value?);
    let scale = match registration::TimeUnits::try_from(d.units?).ok()? {
        registration::TimeUnits::Nanoseconds => 1e-9,
        registration::TimeUnits::Microseconds => 1e-6,
        registration::TimeUnits::Milliseconds => 1e-3,
        registration::TimeUnits::Seconds => 1.0,
        registration::TimeUnits::Minutes => 60.0,
        registration::TimeUnits::Hours => 3600.0,
        registration::TimeUnits::Days => 86_400.0,
        registration::TimeUnits::Unspecified => return None,
    };
    let s = value * scale;
    (s.is_finite() && s >= 0.0).then_some(s)
}

fn coordinate_system_name(system: Option<i32>) -> String {
    enum_name(
        system
            .and_then(|s| v2::LocationCoordinateSystem::try_from(s).ok())
            .map(|s| s.as_str_name()),
        "LOCATION_COORDINATE_SYSTEM_",
    )
}

/// A protobuf enum name without its prefix: `STATUS_TYPE_WEATHER` -> `WEATHER`.
fn enum_name(name: Option<&str>, prefix: &str) -> String {
    name.map(|n| n.strip_prefix(prefix).unwrap_or(n))
        .unwrap_or("UNSPECIFIED")
        .to_string()
}

/// A metadata key from free text: lower case, one underscore between words.
fn key_safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut gap = false;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            gap = false;
        } else if !gap && !out.is_empty() {
            out.push('_');
            gap = true;
        }
    }
    out.trim_end_matches('_').to_string()
}

/// A number with fixed decimals; never prints a negative zero.
fn fixed(value: f64, decimals: usize) -> String {
    let s = format!("{value:.decimals$}");
    if s.starts_with('-') && s[1..].chars().all(|c| c == '0' || c == '.') {
        s[1..].to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_sapient_wire::v2::sapient_message::Content;

    const NODE: &str = "2f1c6a1e-4a5e-4b7e-9b1a-0d3f2e6c7a11";

    fn parser() -> SapientParser {
        SapientParser::new("sapient-fusion-1", Enrichment::default())
    }

    fn envelope(content: Content) -> Vec<u8> {
        ajar_sapient_wire::encode(&v2::SapientMessage {
            timestamp: Some(prost_types::Timestamp {
                seconds: 1_780_000_000,
                nanos: 0,
            }),
            node_id: Some(NODE.into()),
            destination_id: None,
            content: Some(content),
            additional_information: None,
        })
    }

    fn latlng(lat: f64, lon: f64, alt: Option<f64>) -> v2::Location {
        v2::Location {
            x: Some(lon),
            y: Some(lat),
            z: alt,
            coordinate_system: Some(v2::LocationCoordinateSystem::LatLngDegM as i32),
            datum: Some(v2::LocationDatum::Wgs84E as i32),
            ..Default::default()
        }
    }

    fn detection_at(lat: f64, lon: f64) -> Vec<u8> {
        envelope(Content::DetectionReport(v2::DetectionReport {
            report_id: Some("01J8Z1V4Q8K6T2N3S4W5X6Y7Z8".into()),
            object_id: Some("01J8Z1V4Q8K6T2N3S4W5X6Y7A1".into()),
            location_oneof: Some(detection_report::LocationOneof::Location(latlng(
                lat,
                lon,
                Some(120.0),
            ))),
            detection_confidence: Some(0.9),
            velocity_oneof: Some(detection_report::VelocityOneof::EnuVelocity(
                v2::EnuVelocity {
                    east_rate: Some(3.0),
                    north_rate: Some(4.0),
                    up_rate: Some(-1.0),
                    ..Default::default()
                },
            )),
            classification: vec![
                detection_report::DetectionReportClassification {
                    r#type: Some("Bird".into()),
                    confidence: Some(0.2),
                    sub_class: vec![],
                },
                detection_report::DetectionReportClassification {
                    r#type: Some("UAV".into()),
                    confidence: Some(0.8),
                    sub_class: vec![],
                },
            ],
            ..Default::default()
        }))
    }

    fn attribute<'a>(e: &'a Event, key: &str) -> Option<&'a str> {
        e.attributes
            .iter()
            .find(|a| a.key == key)
            .map(|a| a.value.as_str())
    }

    fn metadata<'a>(e: &'a Event, key: &str) -> Option<&'a str> {
        e.metadata
            .iter()
            .find(|m| m.key == key)
            .map(|m| m.value.as_str())
    }

    #[test]
    fn a_located_detection_becomes_one_event_in_contract_units() {
        let raw = detection_at(51.5074, -0.1278);
        let events = parser().parse(&raw).unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.entity_type, TYPE_DETECTION);
        let loc = e.location.as_ref().unwrap();
        assert!((loc.latitude - 51.5074).abs() < 1e-9);
        assert!((loc.longitude + 0.1278).abs() < 1e-9);
        assert!((loc.altitude_m - 120.0).abs() < 1e-9);
        assert_eq!(attribute(e, "speed"), Some("5.00"));
        assert_eq!(attribute(e, "course"), Some("36.9"));
        assert_eq!(attribute(e, "vertical_rate"), Some("-1.00"));
        assert_eq!(attribute(e, "sapient_classification"), Some("UAV"));
        assert_eq!(
            attribute(e, "sapient_classification_confidence"),
            Some("0.800")
        );
        assert_eq!(metadata(e, "classification_1"), Some("UAV"));
        assert_eq!(e.timestamp, "2026-05-28T20:26:40Z");
        assert_eq!(
            metadata(e, "source_uid"),
            Some(&format!("{NODE}:01J8Z1V4Q8K6T2N3S4W5X6Y7A1")[..])
        );
        assert_eq!(e.payload, raw);
        assert!((e.confidence - 0.9).abs() < 1e-6);
    }

    #[test]
    fn track_info_makes_it_a_track_and_the_entity_map_can_override() {
        let mut report = v2::DetectionReport {
            object_id: Some("x".into()),
            location_oneof: Some(detection_report::LocationOneof::Location(latlng(
                1.0, 2.0, None,
            ))),
            track_info: vec![detection_report::TrackObjectInfo {
                r#type: Some("Track Quality".into()),
                value: Some("good".into()),
                error: None,
            }],
            ..Default::default()
        };
        let raw = envelope(Content::DetectionReport(report.clone()));
        let e = &parser().parse(&raw).unwrap()[0];
        assert_eq!(e.entity_type, TYPE_TRACK);
        assert_eq!(metadata(e, "info_track_quality"), Some("good"));
        assert_eq!(metadata(e, "altitude_known"), Some("false"));

        report.classification = vec![detection_report::DetectionReportClassification {
            r#type: Some("UAV".into()),
            confidence: None,
            sub_class: vec![],
        }];
        let raw = envelope(Content::DetectionReport(report));
        let mut map = HashMap::new();
        map.insert("uav".to_string(), "mim:aircraft".to_string());
        let p = parser().with_entity_map(&map).unwrap();
        let e = &p.parse(&raw).unwrap()[0];
        assert_eq!(e.entity_type, "mim:aircraft");
        // A MIM type does not govern the SAPIENT names, so they ride as metadata.
        assert_eq!(attribute(e, "sapient_classification"), None);
        assert_eq!(metadata(e, "sapient_classification"), Some("UAV"));
    }

    #[test]
    fn range_and_bearing_is_geolocated_once_the_node_has_reported_where_it_is() {
        let p = parser();
        let rb = detection_report::LocationOneof::RangeBearing(v2::RangeBearing {
            azimuth: Some(90.0),
            range: Some(1000.0),
            elevation: Some(0.0),
            coordinate_system: Some(v2::RangeBearingCoordinateSystem::DegreesM as i32),
            datum: Some(v2::RangeBearingDatum::True as i32),
            range_error: Some(15.0),
            ..Default::default()
        });
        let report = v2::DetectionReport {
            object_id: Some("y".into()),
            location_oneof: Some(rb),
            ..Default::default()
        };
        let raw = envelope(Content::DetectionReport(report.clone()));
        let e = &p.parse(&raw).unwrap()[0];
        assert!(e.location.is_none());
        assert_eq!(
            metadata(e, "unlocated_reason"),
            Some("node position not yet reported")
        );
        assert_eq!(metadata(e, "range_m"), Some("1000.0"));

        let status = envelope(Content::StatusReport(v2::StatusReport {
            node_location: Some(latlng(51.0, 0.0, Some(10.0))),
            system: Some(status_report::System::Ok as i32),
            ..Default::default()
        }));
        let s = &p.parse(&status).unwrap()[0];
        assert_eq!(s.entity_type, TYPE_SENSOR_STATUS);
        assert_eq!(attribute(s, "sapient_system"), Some("OK"));

        let e = &p.parse(&raw).unwrap()[0];
        let loc = e.location.as_ref().expect("geolocated against the node");
        assert!((loc.latitude - 51.0).abs() < 1e-4);
        // 1 km due east at 51 N is about 0.0143 degrees of longitude.
        assert!((loc.longitude - 0.01427).abs() < 2e-4, "{}", loc.longitude);
        assert!((loc.altitude_m - 10.0).abs() < 1e-6);
        assert_eq!(attribute(e, "position_accuracy_h_m"), Some("15.0"));
        assert_eq!(p.counters.unlocated.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_registration_is_a_sensor_status_event_and_sets_the_velocity_units() {
        let p = parser();
        let reg = v2::Registration {
            node_definition: vec![registration::NodeDefinition {
                node_type: Some(registration::NodeType::Radar as i32),
                node_sub_type: vec!["holographic".into()],
            }],
            icd_version: Some(ajar_sapient_wire::ICD_VERSION_V2.into()),
            name: Some("Bench radar".into()),
            status_definition: Some(registration::StatusDefinition {
                status_interval: Some(registration::Duration {
                    units: Some(registration::TimeUnits::Seconds as i32),
                    value: Some(5.0),
                }),
                ..Default::default()
            }),
            mode_definition: vec![registration::ModeDefinition {
                detection_definition: vec![registration::DetectionDefinition {
                    velocity_type: Some(registration::VelocityType {
                        velocity_units_oneof: Some(
                            registration::velocity_type::VelocityUnitsOneof::EnuVelocityUnits(
                                v2::EnuVelocityUnits {
                                    east_north_rate_units: Some(v2::SpeedUnits::Kph as i32),
                                    up_rate_units: None,
                                },
                            ),
                        ),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let e = &p.parse(&envelope(Content::Registration(reg))).unwrap()[0];
        assert_eq!(e.entity_type, TYPE_SENSOR_STATUS);
        assert_eq!(attribute(e, "sapient_node_type"), Some("RADAR"));
        assert_eq!(attribute(e, "update_interval_s"), Some("5.0"));
        assert_eq!(metadata(e, "node_name"), Some("Bench radar"));
        assert_eq!(metadata(e, "node_sub_type"), Some("holographic"));
        assert_eq!(p.counters.registrations.load(Ordering::Relaxed), 1);

        // 36 km/h east is 10 m/s.
        let d = &p
            .parse(&envelope(Content::DetectionReport(v2::DetectionReport {
                object_id: Some("z".into()),
                location_oneof: Some(detection_report::LocationOneof::Location(latlng(
                    0.0, 0.0, None,
                ))),
                velocity_oneof: Some(detection_report::VelocityOneof::EnuVelocity(
                    v2::EnuVelocity {
                        east_rate: Some(36.0),
                        north_rate: Some(0.0),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            })))
            .unwrap()[0];
        assert_eq!(attribute(d, "speed"), Some("10.00"));
        assert_eq!(attribute(d, "course"), Some("90.0"));
        assert_eq!(metadata(d, "velocity_units"), Some("km/h"));
    }

    #[test]
    fn an_alert_becomes_an_alert_event_with_its_priority() {
        let raw = envelope(Content::Alert(v2::Alert {
            alert_id: Some("01J8ZALERT".into()),
            alert_type: Some(v2::alert::AlertType::Critical as i32),
            status: Some(v2::alert::AlertStatus::Active as i32),
            priority: Some(v2::alert::DiscretePriority::High as i32),
            description: Some("UAV over the fence".into()),
            location_oneof: Some(v2::alert::LocationOneof::Location(latlng(51.0, 1.0, None))),
            ..Default::default()
        }));
        let e = &parser().parse(&raw).unwrap()[0];
        assert_eq!(e.entity_type, TYPE_ALERT);
        assert_eq!(attribute(e, "sapient_alert_type"), Some("CRITICAL"));
        assert_eq!(attribute(e, "sapient_alert_status"), Some("ACTIVE"));
        assert_eq!(attribute(e, "sapient_priority"), Some("HIGH"));
        assert_eq!(metadata(e, "description"), Some("UAV over the fence"));
        assert!(e.location.is_some());
    }

    #[test]
    fn fusion_side_messages_publish_nothing_and_are_counted() {
        let p = parser();
        let raw = envelope(Content::Task(v2::Task::default()));
        assert!(p.parse(&raw).unwrap().is_empty());
        let raw = envelope(Content::RegistrationAck(v2::RegistrationAck::default()));
        assert!(p.parse(&raw).unwrap().is_empty());
        assert_eq!(p.counters.unmapped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn hostility_is_only_stamped_when_the_operator_set_it() {
        let raw = detection_at(0.0, 0.0);
        let plain = &parser().parse(&raw).unwrap()[0];
        assert_eq!(attribute(plain, "hostility"), None);
        let p = SapientParser::new("s", Enrichment::default().with_hostility("Suspect"));
        let e = &p.parse(&raw).unwrap()[0];
        assert_eq!(attribute(e, "hostility"), Some("Suspect"));
    }

    #[test]
    fn malformed_and_hostile_bytes_are_refused_with_a_reason_and_never_panic() {
        let p = parser();
        assert!(matches!(
            p.parse_message(b"\xff\xff\xff"),
            Err(SapientError::Decode(_))
        ));
        let empty = ajar_sapient_wire::encode(&v2::SapientMessage::default());
        assert_eq!(p.parse_message(&empty), Err(SapientError::Empty));
        let raw = detection_at(1.0, 2.0);
        for cut in 0..raw.len() {
            let _ = p.parse_message(&raw[..cut]);
        }
        let mut seed: u32 = 0x1234_5678;
        for _ in 0..2_000 {
            let len = (seed % 96) as usize;
            let frame: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (seed >> 24) as u8
                })
                .collect();
            let _ = p.parse_message(&frame);
        }
    }

    #[test]
    fn options_refuse_a_typo_and_mint_a_node_id_when_unset() {
        let t: toml::Table = toml::from_str("role = \"subscriber\"").unwrap();
        let o = Options::from_table(&t).unwrap();
        assert_eq!(o.role, Role::Subscriber);
        assert!(uuid::Uuid::parse_str(&o.node_id).is_ok());
        let t: toml::Table = toml::from_str("rol = \"dmm\"").unwrap();
        assert!(Options::from_table(&t).is_err());
        let t: toml::Table = toml::from_str("node_id = \"fusion-1\"").unwrap();
        let o = Options::from_table(&t).unwrap();
        assert_eq!(o.role, Role::Dmm);
        assert_eq!(o.node_id, "fusion-1");
    }

    #[test]
    fn destination_matches_a_known_bearing() {
        // 100 km due north from the equator is 0.899 degrees of latitude.
        let (lat, lon) = destination(0.0, 0.0, 0.0, 100_000.0);
        assert!((lat - 0.8993).abs() < 1e-3, "{lat}");
        assert!(lon.abs() < 1e-9);
        // Crossing the antimeridian wraps.
        let (_, lon) = destination(0.0, 179.9, 90.0, 50_000.0);
        assert!(lon < -179.0, "{lon}");
    }
}
