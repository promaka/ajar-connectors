// SPDX-License-Identifier: Apache-2.0
//! What this node says to the fusion node: its registration, its status
//! reports, its refusals of tasks, and a detection report for each governed
//! event.
//!
//! The registration declares exactly what a fusion node needs to accept a
//! sensor under BSI Flex 335: a node definition, the ICD version, a
//! capability, a status definition with the heartbeat interval, one
//! permanent mode whose detection definition states the coordinate and
//! velocity units every report uses, a task definition, and the node's make
//! and model. A fusion node product may ask for more; the fields are in one
//! place so that is a small change.

use std::collections::HashMap;

use ajar_connector::Event;
use ajar_sapient_wire::v2::sapient_message::Content;
use ajar_sapient_wire::v2::{self, detection_report, registration, status_report};

use crate::config::{EgressConfig, Site};
use crate::ulid;

/// How this node presents itself.
#[derive(Debug, Clone)]
pub struct Node {
    pub node_id: String,
    pub name: String,
    pub short_name: String,
    pub status_interval_s: f64,
    pub location: Option<Site>,
}

impl Node {
    pub fn from_config(cfg: &EgressConfig) -> Node {
        Node {
            node_id: cfg.node_id(),
            name: cfg.sapient.name.clone(),
            short_name: cfg.sapient.short_name.clone(),
            status_interval_s: cfg.sapient.status_interval_s,
            location: cfg.sapient.location,
        }
    }

    fn envelope(&self, content: Content) -> v2::SapientMessage {
        v2::SapientMessage {
            timestamp: Some(ajar_sapient_wire::now()),
            node_id: Some(self.node_id.clone()),
            destination_id: None,
            content: Some(content),
            additional_information: None,
        }
    }

    /// The registration a fusion node accepts this node on.
    pub fn registration(&self) -> v2::SapientMessage {
        let seconds = |value: f64| registration::Duration {
            units: Some(registration::TimeUnits::Seconds as i32),
            value: Some(value as f32),
        };
        let latlng = registration::LocationType {
            coordinates_oneof: Some(
                registration::location_type::CoordinatesOneof::LocationUnits(
                    v2::LocationCoordinateSystem::LatLngDegM as i32,
                ),
            ),
            datum_oneof: Some(registration::location_type::DatumOneof::LocationDatum(
                v2::LocationDatum::Wgs84E as i32,
            )),
            zone: None,
        };
        let reg = v2::Registration {
            node_definition: vec![registration::NodeDefinition {
                node_type: Some(registration::NodeType::Other as i32),
                node_sub_type: vec!["Ajar governed relay".into()],
            }],
            icd_version: Some(ajar_sapient_wire::ICD_VERSION_V2.into()),
            name: Some(self.name.clone()),
            short_name: Some(self.short_name.clone()),
            capabilities: vec![registration::Capability {
                category: Some("Fusion".into()),
                r#type: Some("Governed track relay".into()),
                value: Some("Ajar".into()),
                units: None,
            }],
            status_definition: Some(registration::StatusDefinition {
                status_interval: Some(seconds(self.status_interval_s)),
                location_definition: Some(latlng.clone()),
                ..Default::default()
            }),
            mode_definition: vec![registration::ModeDefinition {
                mode_name: Some("Default".into()),
                mode_type: Some(registration::ModeType::Permanent as i32),
                mode_description: Some("Relays governed events as detection reports".into()),
                settle_time: Some(seconds(0.0)),
                detection_definition: vec![registration::DetectionDefinition {
                    location_type: Some(latlng.clone()),
                    velocity_type: Some(registration::VelocityType {
                        velocity_units_oneof: Some(
                            registration::velocity_type::VelocityUnitsOneof::EnuVelocityUnits(
                                v2::EnuVelocityUnits {
                                    east_north_rate_units: Some(v2::SpeedUnits::Ms as i32),
                                    up_rate_units: Some(v2::SpeedUnits::Ms as i32),
                                },
                            ),
                        ),
                        datum_oneof: Some(registration::velocity_type::DatumOneof::LocationDatum(
                            v2::LocationDatum::Wgs84E as i32,
                        )),
                        zone: None,
                    }),
                    detection_report: vec![registration::DetectionReport {
                        category: Some(registration::DetectionReportCategory::Detection as i32),
                        r#type: Some("detection_confidence".into()),
                        units: Some("0-1".into()),
                        on_change: None,
                    }],
                    detection_class_definition: vec![registration::DetectionClassDefinition {
                        confidence_definition: Some(
                            registration::ConfidenceDefinition::SingleClass as i32,
                        ),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                task: Some(registration::TaskDefinition {
                    concurrent_tasks: Some(0),
                    region_definition: Some(registration::RegionDefinition {
                        region_type: vec![registration::RegionType::AreaOfInterest as i32],
                        region_area: vec![latlng],
                        ..Default::default()
                    }),
                    command: vec![],
                }),
                ..Default::default()
            }],
            config_data: vec![registration::ConfigurationData {
                manufacturer: "Ajar".into(),
                model: "ajar-sapient-egress".into(),
                software_version: Some(env!("CARGO_PKG_VERSION").into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        self.envelope(Content::Registration(reg))
    }

    /// A status report. `first` marks new information, as after a
    /// registration; later ones say the information is unchanged.
    pub fn status(&self, first: bool) -> v2::SapientMessage {
        let node_location = self.location.map(|s| v2::Location {
            x: Some(s.lon),
            y: Some(s.lat),
            z: Some(s.alt_m),
            coordinate_system: Some(v2::LocationCoordinateSystem::LatLngDegM as i32),
            datum: Some(v2::LocationDatum::Wgs84E as i32),
            ..Default::default()
        });
        self.envelope(Content::StatusReport(v2::StatusReport {
            report_id: Some(ulid::new()),
            system: Some(status_report::System::Ok as i32),
            info: Some(if first {
                status_report::Info::New
            } else {
                status_report::Info::Unchanged
            } as i32),
            mode: Some("Default".into()),
            node_location,
            ..Default::default()
        }))
    }

    /// The refusal of a task: this node relays governed events and cannot be
    /// pointed, moved or re-thresholded.
    pub fn task_rejected(&self, task_id: &str, from: Option<&str>) -> v2::SapientMessage {
        let mut m = self.envelope(Content::TaskAck(v2::TaskAck {
            task_id: Some(task_id.to_string()),
            task_status: Some(v2::task_ack::TaskStatus::Rejected as i32),
            associated_file: None,
            reason: vec!["this node relays governed events and takes no tasks".into()],
        }));
        m.destination_id = from.map(str::to_string);
        m
    }
}

/// Why an event produced no report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// A SAPIENT detection report must place its object; the event had no
    /// position.
    NoLocation,
}

/// Objects remembered at once, so an object keeps its identifier across
/// reports. Beyond this the least recently added is forgotten and the
/// object gets a new identifier, which a fusion node treats as a new track.
const MAX_OBJECTS: usize = 10_000;

/// Turns governed events into detection reports.
pub struct Mapper {
    classification: HashMap<String, String>,
    default_classification: String,
    objects: HashMap<String, String>,
    order: std::collections::VecDeque<String>,
}

impl Mapper {
    pub fn new(cfg: &EgressConfig) -> Mapper {
        let mut classification: HashMap<String, String> = [
            ("mim:aircraft", "Aircraft"),
            ("mim:vessel", "Vessel"),
            ("mim:surface-vessel", "Vessel"),
            ("mim:subsurface-vessel", "Submarine"),
            ("mim:land-vehicle", "Vehicle"),
            ("mim:person", "Person"),
            ("mim:unit", "Unit"),
            ("mim:facility", "Facility"),
            ("mim:weapon", "Weapon"),
            ("mim:sensor", "Sensor"),
            ("mim:object", "Unknown"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        for (k, v) in &cfg.sapient.classification {
            classification.insert(k.clone(), v.clone());
        }
        Mapper {
            classification,
            default_classification: cfg.sapient.default_classification.clone(),
            objects: HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// The stable SAPIENT object identifier for a track.
    fn object_id(&mut self, key: &str) -> String {
        if let Some(id) = self.objects.get(key) {
            return id.clone();
        }
        if self.objects.len() >= MAX_OBJECTS {
            if let Some(old) = self.order.pop_front() {
                self.objects.remove(&old);
            }
        }
        let id = ulid::new();
        self.objects.insert(key.to_string(), id.clone());
        self.order.push_back(key.to_string());
        id
    }

    fn classification_for(&self, event: &Event) -> String {
        attribute(event, "sapient_classification")
            .or_else(|| attribute(event, "object_class"))
            .map(str::to_string)
            .or_else(|| self.classification.get(&event.entity_type).cloned())
            .unwrap_or_else(|| self.default_classification.clone())
    }

    /// One detection report for a governed event, or why there is none.
    pub fn detection(&mut self, node: &Node, event: &Event) -> Result<v2::SapientMessage, Skip> {
        let loc = event.location.as_ref().ok_or(Skip::NoLocation)?;
        let native = metadata(event, "source_uid")
            .map(str::to_string)
            .unwrap_or_else(|| event.id.clone());
        let key = format!("{}:{}", event.source_id, native);
        let object_id = self.object_id(&key);

        let velocity = match (
            number(attribute(event, "speed")),
            number(attribute(event, "course")),
        ) {
            (Some(speed), Some(course)) if speed >= 0.0 => {
                let c = course.to_radians();
                Some(detection_report::VelocityOneof::EnuVelocity(
                    v2::EnuVelocity {
                        east_rate: Some(speed * c.sin()),
                        north_rate: Some(speed * c.cos()),
                        up_rate: number(attribute(event, "vertical_rate")),
                        ..Default::default()
                    },
                ))
            }
            _ => None,
        };

        let classification = self.classification_for(event);
        let class_confidence = number(attribute(event, "sapient_classification_confidence"))
            .filter(|c| (0.0..=1.0).contains(c))
            .map(|c| c as f32);
        let detection_confidence =
            (event.confidence > 0.0 && event.confidence <= 1.0).then_some(event.confidence as f32);

        let mut object_info = vec![
            info("Ajar Source", &event.source_id),
            info("Ajar Event", &event.id),
            info("Ajar Type", &event.entity_type),
        ];
        if let Some(h) = attribute(event, "hostility") {
            object_info.push(info("Hostility", h));
        }

        let report = v2::DetectionReport {
            report_id: Some(ulid::new()),
            object_id: Some(object_id),
            location_oneof: Some(detection_report::LocationOneof::Location(v2::Location {
                x: Some(loc.longitude),
                y: Some(loc.latitude),
                z: Some(loc.altitude_m),
                x_error: None,
                y_error: None,
                z_error: None,
                coordinate_system: Some(v2::LocationCoordinateSystem::LatLngDegM as i32),
                datum: Some(v2::LocationDatum::Wgs84E as i32),
                utm_zone: None,
            })),
            detection_confidence,
            classification: vec![detection_report::DetectionReportClassification {
                r#type: Some(classification),
                confidence: class_confidence,
                sub_class: vec![],
            }],
            velocity_oneof: velocity,
            id: Some(native),
            object_info,
            ..Default::default()
        };

        let mut m = node.envelope(Content::DetectionReport(report));
        m.timestamp = parse_rfc3339(&event.timestamp).or(m.timestamp);
        Ok(m)
    }
}

fn info(kind: &str, value: &str) -> detection_report::TrackObjectInfo {
    detection_report::TrackObjectInfo {
        r#type: Some(kind.to_string()),
        value: Some(value.to_string()),
        error: None,
    }
}

fn attribute<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
    event
        .attributes
        .iter()
        .find(|a| a.key == key)
        .map(|a| a.value.as_str())
}

fn metadata<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
    event
        .metadata
        .iter()
        .find(|m| m.key == key)
        .map(|m| m.value.as_str())
}

fn number(s: Option<&str>) -> Option<f64> {
    s.and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
}

/// An event's RFC 3339 time as a protobuf timestamp.
pub fn parse_rfc3339(s: &str) -> Option<prost_types::Timestamp> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    Some(prost_types::Timestamp {
        seconds: t.unix_timestamp(),
        nanos: t.nanosecond() as i32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector::EventBuilder;

    const KEY: &str = "e28a89f1c0d2b3a4958677665544332211ffeeddccbbaa99887766554433221100";

    fn config(extra: &str) -> EgressConfig {
        toml::from_str(&format!(
            "nats_url = \"nats://127.0.0.1:4222\"\negress_verifying_key = \"{KEY}\"\n[sapient]\nfusion_node = \"fusion:7777\"\nnode_id = \"7d2e0b1c-1111-4222-8333-444455556666\"\n{extra}"
        ))
        .unwrap()
    }

    fn event() -> Event {
        EventBuilder::new("mavlink-1", "mim:aircraft")
            .new_id()
            .timestamp("2026-05-28T20:26:42Z")
            .location(51.5, -0.12, 120.0)
            .attribute("speed", "10.00")
            .attribute("course", "90.0")
            .attribute("vertical_rate", "-1.50")
            .attribute("hostility", "Suspect")
            .confidence(0.9)
            .metadata("source_uid", "7")
            .build()
            .unwrap()
    }

    fn report_of(m: &v2::SapientMessage) -> &v2::DetectionReport {
        match &m.content {
            Some(Content::DetectionReport(r)) => r,
            other => panic!("not a detection report: {other:?}"),
        }
    }

    #[test]
    fn a_governed_event_becomes_a_located_classified_detection() {
        let cfg = config("");
        let node = Node::from_config(&cfg);
        let mut mapper = Mapper::new(&cfg);
        let m = mapper.detection(&node, &event()).unwrap();
        assert_eq!(
            m.node_id.as_deref(),
            Some("7d2e0b1c-1111-4222-8333-444455556666")
        );
        assert_eq!(m.timestamp.as_ref().map(|t| t.seconds), Some(1_780_000_002));
        let r = report_of(&m);
        assert!(ulid::is_valid(r.report_id.as_deref().unwrap()));
        assert!(ulid::is_valid(r.object_id.as_deref().unwrap()));
        match &r.location_oneof {
            Some(detection_report::LocationOneof::Location(l)) => {
                assert_eq!(l.x, Some(-0.12));
                assert_eq!(l.y, Some(51.5));
                assert_eq!(l.z, Some(120.0));
                assert_eq!(
                    l.coordinate_system,
                    Some(v2::LocationCoordinateSystem::LatLngDegM as i32)
                );
            }
            other => panic!("{other:?}"),
        }
        match &r.velocity_oneof {
            Some(detection_report::VelocityOneof::EnuVelocity(v)) => {
                assert!((v.east_rate.unwrap() - 10.0).abs() < 1e-9);
                assert!(v.north_rate.unwrap().abs() < 1e-9);
                assert_eq!(v.up_rate, Some(-1.5));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(r.classification[0].r#type.as_deref(), Some("Aircraft"));
        assert_eq!(r.detection_confidence, Some(0.9));
        assert_eq!(r.id.as_deref(), Some("7"));
        assert!(r
            .object_info
            .iter()
            .any(|i| i.r#type.as_deref() == Some("Hostility")
                && i.value.as_deref() == Some("Suspect")));
        assert!(r
            .object_info
            .iter()
            .any(|i| i.r#type.as_deref() == Some("Ajar Source")
                && i.value.as_deref() == Some("mavlink-1")));
    }

    #[test]
    fn the_same_track_keeps_its_object_id_and_a_new_one_gets_another() {
        let cfg = config("");
        let node = Node::from_config(&cfg);
        let mut mapper = Mapper::new(&cfg);
        let first = report_of(&mapper.detection(&node, &event()).unwrap())
            .object_id
            .clone();
        let again = report_of(&mapper.detection(&node, &event()).unwrap())
            .object_id
            .clone();
        assert_eq!(first, again);
        let other = EventBuilder::new("mavlink-1", "mim:aircraft")
            .new_id()
            .now()
            .location(1.0, 2.0, 3.0)
            .metadata("source_uid", "8")
            .build()
            .unwrap();
        let third = report_of(&mapper.detection(&node, &other).unwrap())
            .object_id
            .clone();
        assert_ne!(first, third);
    }

    #[test]
    fn classification_comes_from_the_event_then_the_table_then_the_default() {
        let cfg = config("default_classification = \"Thing\"\n[sapient.classification]\n\"x:acme:drone\" = \"UAV\"");
        let node = Node::from_config(&cfg);
        let mut mapper = Mapper::new(&cfg);
        let drone = EventBuilder::new("s", "x:acme:drone")
            .new_id()
            .now()
            .location(1.0, 2.0, 0.0)
            .build()
            .unwrap();
        assert_eq!(
            report_of(&mapper.detection(&node, &drone).unwrap()).classification[0]
                .r#type
                .as_deref(),
            Some("UAV")
        );
        let labelled = EventBuilder::new("s", "x:acme:drone")
            .new_id()
            .now()
            .location(1.0, 2.0, 0.0)
            .attribute("object_class", "Quadcopter")
            .build()
            .unwrap();
        assert_eq!(
            report_of(&mapper.detection(&node, &labelled).unwrap()).classification[0]
                .r#type
                .as_deref(),
            Some("Quadcopter")
        );
        let unknown = EventBuilder::new("s", "x:acme:blob")
            .new_id()
            .now()
            .location(1.0, 2.0, 0.0)
            .build()
            .unwrap();
        assert_eq!(
            report_of(&mapper.detection(&node, &unknown).unwrap()).classification[0]
                .r#type
                .as_deref(),
            Some("Thing")
        );
    }

    #[test]
    fn an_event_without_a_position_is_skipped_not_invented() {
        let cfg = config("");
        let node = Node::from_config(&cfg);
        let mut mapper = Mapper::new(&cfg);
        let bare = EventBuilder::new("s", "mim:sensor")
            .new_id()
            .now()
            .build()
            .unwrap();
        assert_eq!(mapper.detection(&node, &bare), Err(Skip::NoLocation));
    }

    #[test]
    fn the_registration_declares_everything_a_fusion_node_requires() {
        let cfg = config(
            "status_interval_s = 2.5\n[sapient.location]\nlat = 51.0\nlon = 0.5\nalt_m = 30",
        );
        let node = Node::from_config(&cfg);
        let m = node.registration();
        let reg = match &m.content {
            Some(Content::Registration(r)) => r,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            reg.icd_version.as_deref(),
            Some(ajar_sapient_wire::ICD_VERSION_V2)
        );
        assert!(!reg.node_definition.is_empty());
        assert!(!reg.capabilities.is_empty());
        assert!(!reg.config_data.is_empty());
        let interval = reg
            .status_definition
            .as_ref()
            .unwrap()
            .status_interval
            .as_ref()
            .unwrap();
        assert_eq!(interval.value, Some(2.5));
        let mode = &reg.mode_definition[0];
        assert_eq!(mode.mode_name.as_deref(), Some("Default"));
        assert!(mode.settle_time.is_some());
        assert!(mode.task.as_ref().unwrap().region_definition.is_some());
        assert!(!mode.detection_definition.is_empty());
        // The bytes survive the wire.
        let bytes = ajar_sapient_wire::encode(&m);
        assert_eq!(ajar_sapient_wire::decode(&bytes).unwrap(), m);

        let s = node.status(true);
        match &s.content {
            Some(Content::StatusReport(r)) => {
                assert_eq!(r.system, Some(status_report::System::Ok as i32));
                assert_eq!(r.info, Some(status_report::Info::New as i32));
                assert_eq!(r.node_location.as_ref().and_then(|l| l.y), Some(51.0));
            }
            other => panic!("{other:?}"),
        }
        let ack = node.task_rejected("01J9A0TASK00000000000000001", Some("fusion"));
        assert_eq!(ack.destination_id.as_deref(), Some("fusion"));
        assert!(matches!(ack.content, Some(Content::TaskAck(_))));
    }

    #[test]
    fn timestamps_parse_and_garbage_does_not() {
        assert_eq!(
            parse_rfc3339("2026-05-28T20:26:42Z").map(|t| t.seconds),
            Some(1_780_000_002)
        );
        assert_eq!(
            parse_rfc3339("2026-05-28T21:26:42.5+01:00").map(|t| (t.seconds, t.nanos)),
            Some((1_780_000_002, 500_000_000))
        );
        assert!(parse_rfc3339("yesterday").is_none());
    }
}
