// SPDX-License-Identifier: Apache-2.0
//! The counter-UAS radar: a SAPIENT (BSI Flex 335) edge node at the coastal
//! radar site, reporting the uncrewed aircraft by range and bearing, as a
//! fusion node's output looks on the wire.
//!
//! The node registers, reports its status with its position every five
//! seconds, and reports the aircraft once a second as a track. The same
//! aircraft flies on MAVLink, so a fusion consumer gets the association work:
//! one object, seen by its own autopilot and by a radar that does not know
//! what it is. Every message is framed as the standard puts it on TCP.

use std::time::SystemTime;

use ajar_sapient_wire::v2::sapient_message::Content;
use ajar_sapient_wire::v2::{self, detection_report, registration, status_report};

use crate::scenario::{bearing_range, UavState, RADAR, RADAR_ALT_M};

/// The radar node's identity, fixed so a consumer can name it.
pub const NODE_ID: &str = "c0a5f1e2-6b3d-4f8a-9c1e-2d7b4a6f8e01";
/// The one object the radar follows.
pub const OBJECT_ID: &str = "01J9A0SYNTHUAV000000000001";
/// Status reports per detection reports, and registrations per status.
pub const STATUS_EVERY: u64 = 5;
pub const REGISTER_EVERY: u64 = 60;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A ULID-shaped identifier from the message time and a sequence number:
/// valid for the standard, and reproducible for the tests.
fn ulid(observed: SystemTime, seq: u64) -> String {
    let millis = observed
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let value = (u128::from(millis & 0xFFFF_FFFF_FFFF) << 80) | u128::from(seq);
    let mut out = [b'0'; 26];
    let mut v = value;
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(v & 31) as usize];
        v >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("ASCII")
}

fn timestamp(observed: SystemTime) -> prost_types::Timestamp {
    let d = observed
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    prost_types::Timestamp {
        seconds: d.as_secs() as i64,
        nanos: d.subsec_nanos() as i32,
    }
}

fn envelope(observed: SystemTime, content: Content) -> Vec<u8> {
    let m = v2::SapientMessage {
        timestamp: Some(timestamp(observed)),
        node_id: Some(NODE_ID.into()),
        destination_id: None,
        content: Some(content),
        additional_information: None,
    };
    ajar_sapient_wire::frame(&ajar_sapient_wire::encode(&m))
}

fn latlng() -> registration::LocationType {
    registration::LocationType {
        coordinates_oneof: Some(
            registration::location_type::CoordinatesOneof::LocationUnits(
                v2::LocationCoordinateSystem::LatLngDegM as i32,
            ),
        ),
        datum_oneof: Some(registration::location_type::DatumOneof::LocationDatum(
            v2::LocationDatum::Wgs84E as i32,
        )),
        zone: None,
    }
}

/// The node's registration, framed.
pub fn registration(observed: SystemTime) -> Vec<u8> {
    let seconds = |value: f32| registration::Duration {
        units: Some(registration::TimeUnits::Seconds as i32),
        value: Some(value),
    };
    envelope(
        observed,
        Content::Registration(v2::Registration {
            node_definition: vec![registration::NodeDefinition {
                node_type: Some(registration::NodeType::Radar as i32),
                node_sub_type: vec!["counter-UAS".into()],
            }],
            icd_version: Some(ajar_sapient_wire::ICD_VERSION_V2.into()),
            name: Some("Synthetic counter-UAS radar".into()),
            short_name: Some("CUAS-1".into()),
            capabilities: vec![registration::Capability {
                category: Some("Radar".into()),
                r#type: Some("Maximum range".into()),
                value: Some("5000".into()),
                units: Some("m".into()),
            }],
            status_definition: Some(registration::StatusDefinition {
                status_interval: Some(seconds(STATUS_EVERY as f32)),
                location_definition: Some(latlng()),
                ..Default::default()
            }),
            mode_definition: vec![registration::ModeDefinition {
                mode_name: Some("Scanning".into()),
                mode_type: Some(registration::ModeType::Permanent as i32),
                settle_time: Some(seconds(0.0)),
                detection_definition: vec![registration::DetectionDefinition {
                    location_type: Some(registration::LocationType {
                        coordinates_oneof: Some(
                            registration::location_type::CoordinatesOneof::RangeBearingUnits(
                                v2::RangeBearingCoordinateSystem::DegreesM as i32,
                            ),
                        ),
                        datum_oneof: Some(
                            registration::location_type::DatumOneof::RangeBearingDatum(
                                v2::RangeBearingDatum::True as i32,
                            ),
                        ),
                        zone: None,
                    }),
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
                    ..Default::default()
                }],
                task: Some(registration::TaskDefinition {
                    region_definition: Some(registration::RegionDefinition {
                        region_type: vec![registration::RegionType::AreaOfInterest as i32],
                        region_area: vec![latlng()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_data: vec![registration::ConfigurationData {
                manufacturer: "Ajar".into(),
                model: "feed-synthetic".into(),
                ..Default::default()
            }],
            ..Default::default()
        }),
    )
}

/// The node's status report: OK, scanning, at the radar site. `first` marks
/// the one after a registration.
pub fn status(observed: SystemTime, seq: u64, first: bool) -> Vec<u8> {
    envelope(
        observed,
        Content::StatusReport(v2::StatusReport {
            report_id: Some(ulid(observed, seq)),
            system: Some(status_report::System::Ok as i32),
            info: Some(if first {
                status_report::Info::New
            } else {
                status_report::Info::Unchanged
            } as i32),
            mode: Some("Scanning".into()),
            node_location: Some(v2::Location {
                x: Some(RADAR.lon),
                y: Some(RADAR.lat),
                z: Some(RADAR_ALT_M),
                coordinate_system: Some(v2::LocationCoordinateSystem::LatLngDegM as i32),
                datum: Some(v2::LocationDatum::Wgs84E as i32),
                ..Default::default()
            }),
            ..Default::default()
        }),
    )
}

/// The aircraft as the radar reports it: range, bearing and elevation from
/// the site, an ENU velocity, and a classification with a radar's confidence.
pub fn detection(u: &UavState, observed: SystemTime, seq: u64) -> Vec<u8> {
    let (bearing, range) = bearing_range(RADAR, u.fix);
    let elevation = (u.alt_m - RADAR_ALT_M).atan2(range).to_degrees();
    let heading = u.heading_deg.to_radians();
    envelope(
        observed,
        Content::DetectionReport(v2::DetectionReport {
            report_id: Some(ulid(observed, seq)),
            object_id: Some(OBJECT_ID.into()),
            location_oneof: Some(detection_report::LocationOneof::RangeBearing(
                v2::RangeBearing {
                    azimuth: Some(bearing),
                    elevation: Some(elevation),
                    range: Some(range),
                    azimuth_error: Some(0.5),
                    range_error: Some(5.0),
                    coordinate_system: Some(v2::RangeBearingCoordinateSystem::DegreesM as i32),
                    datum: Some(v2::RangeBearingDatum::True as i32),
                    ..Default::default()
                },
            )),
            detection_confidence: Some(0.85),
            velocity_oneof: Some(detection_report::VelocityOneof::EnuVelocity(
                v2::EnuVelocity {
                    east_rate: Some(u.speed_mps * heading.sin()),
                    north_rate: Some(u.speed_mps * heading.cos()),
                    up_rate: Some(0.0),
                    ..Default::default()
                },
            )),
            classification: vec![detection_report::DetectionReportClassification {
                r#type: Some("UAV".into()),
                confidence: Some(0.9),
                sub_class: vec![],
            }],
            track_info: vec![detection_report::TrackObjectInfo {
                r#type: Some("Track Quality".into()),
                value: Some("good".into()),
                error: None,
            }],
            ..Default::default()
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::Uav;
    use ajar_connector_common::{Enrichment, FrameParser};
    use ajar_sapient::SapientParser;

    fn parse(p: &SapientParser, framed: &[u8]) -> ajar_connector::Event {
        let (payload, rest) = ajar_sapient_wire::unframe(framed).expect("one whole frame");
        assert!(rest.is_empty());
        let mut events = p.parse(payload).expect("the connector accepts it");
        assert_eq!(events.len(), 1);
        events.remove(0)
    }

    #[test]
    fn the_connector_places_the_radar_track_where_the_scenario_put_the_aircraft() {
        let p = SapientParser::new("sapient-1", Enrichment::default());
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_780_000_000);
        let reg = parse(&p, &registration(now));
        assert_eq!(reg.entity_type, "sapient:sensor-status");
        let st = parse(&p, &status(now, 1, true));
        let site = st.location.as_ref().expect("the node's position");
        assert!((site.latitude - RADAR.lat).abs() < 1e-9);

        let u = Uav::at(30.0);
        let ev = parse(&p, &detection(&u, now, 2));
        assert_eq!(ev.entity_type, "sapient:track");
        let loc = ev.location.as_ref().expect("geolocated against the radar");
        // Flat-earth scenario geometry against the connector's spherical
        // geolocation, at under a kilometre: within a couple of metres.
        let dlat = (loc.latitude - u.fix.lat) * crate::scenario::M_PER_DEG_LAT;
        let dlon = (loc.longitude - u.fix.lon)
            * crate::scenario::M_PER_DEG_LAT
            * u.fix.lat.to_radians().cos();
        assert!(dlat.hypot(dlon) < 3.0, "{} m off", dlat.hypot(dlon));
        assert!((loc.altitude_m - u.alt_m).abs() < 1.0, "{}", loc.altitude_m);
        let speed: f64 = ev
            .attributes
            .iter()
            .find(|a| a.key == "speed")
            .and_then(|a| a.value.parse().ok())
            .expect("speed");
        assert!((speed - u.speed_mps).abs() < 0.01);
        assert!(ev
            .attributes
            .iter()
            .any(|a| a.key == "sapient_classification" && a.value == "UAV"));
        assert_eq!(ev.timestamp, "2026-05-28T20:26:40Z");
    }

    #[test]
    fn identifiers_have_the_shape_the_standard_requires() {
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_780_000_000);
        let id = ulid(now, 7);
        assert_eq!(id.len(), 26);
        assert!(id.bytes().all(|b| ALPHABET.contains(&b)));
        assert_ne!(ulid(now, 8), id);
        assert_eq!(OBJECT_ID.len(), 26);
    }
}
