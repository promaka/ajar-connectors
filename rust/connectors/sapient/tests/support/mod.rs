// SPDX-License-Identifier: Apache-2.0
//! A bench scenario on the wire: one radar node registers, reports its
//! position, then reports a UAV it is following, and raises an alert. Built
//! deterministically, so `tests/data/sapient-capture.bin` is exactly these
//! bytes and a decode of either proves the other.

use ajar_sapient_wire::v2::sapient_message::Content;
use ajar_sapient_wire::v2::{self, detection_report, registration, status_report};

pub const NODE: &str = "6b4f2d1a-7c3e-4a9b-8d2f-1e5c9a7b3d4f";
pub const OBJECT: &str = "01J9A0B1C2D3E4F5G6H7J8K9M0";

fn at(seconds: i64) -> Option<prost_types::Timestamp> {
    Some(prost_types::Timestamp {
        seconds: 1_780_000_000 + seconds,
        nanos: 0,
    })
}

fn envelope(seconds: i64, content: Content) -> v2::SapientMessage {
    v2::SapientMessage {
        timestamp: at(seconds),
        node_id: Some(NODE.into()),
        destination_id: None,
        content: Some(content),
        additional_information: None,
    }
}

fn latlng(lat: f64, lon: f64, alt: f64) -> v2::Location {
    v2::Location {
        x: Some(lon),
        y: Some(lat),
        z: Some(alt),
        coordinate_system: Some(v2::LocationCoordinateSystem::LatLngDegM as i32),
        datum: Some(v2::LocationDatum::Wgs84E as i32),
        ..Default::default()
    }
}

/// The scenario's messages, in order.
pub fn messages() -> Vec<v2::SapientMessage> {
    let registration = v2::Registration {
        node_definition: vec![registration::NodeDefinition {
            node_type: Some(registration::NodeType::Radar as i32),
            node_sub_type: vec![],
        }],
        icd_version: Some(ajar_sapient_wire::ICD_VERSION_V2.into()),
        name: Some("Bench radar".into()),
        short_name: Some("RADAR-1".into()),
        status_definition: Some(registration::StatusDefinition {
            status_interval: Some(registration::Duration {
                units: Some(registration::TimeUnits::Seconds as i32),
                value: Some(5.0),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let status = v2::StatusReport {
        report_id: Some("01J9A0STATUS000000000000001".into()),
        system: Some(status_report::System::Ok as i32),
        info: Some(status_report::Info::New as i32),
        mode: Some("Scanning".into()),
        node_location: Some(latlng(51.4700, -0.4543, 25.0)),
        ..Default::default()
    };
    let mut detections = Vec::new();
    for i in 0..5i64 {
        // Range and bearing from the radar: a UAV closing from the north-east.
        detections.push(envelope(
            2 + i,
            Content::DetectionReport(v2::DetectionReport {
                report_id: Some(format!("01J9A0DETECT00000000000000{i}")),
                object_id: Some(OBJECT.into()),
                location_oneof: Some(detection_report::LocationOneof::RangeBearing(
                    v2::RangeBearing {
                        azimuth: Some(45.0),
                        elevation: Some(2.0),
                        range: Some(1500.0 - 100.0 * i as f64),
                        range_error: Some(10.0),
                        coordinate_system: Some(v2::RangeBearingCoordinateSystem::DegreesM as i32),
                        datum: Some(v2::RangeBearingDatum::True as i32),
                        ..Default::default()
                    },
                )),
                detection_confidence: Some(0.85),
                velocity_oneof: Some(detection_report::VelocityOneof::EnuVelocity(
                    v2::EnuVelocity {
                        east_rate: Some(-7.07),
                        north_rate: Some(-7.07),
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
        ));
    }
    let alert = v2::Alert {
        alert_id: Some("01J9A0ALERT0000000000000001".into()),
        alert_type: Some(v2::alert::AlertType::Warning as i32),
        status: Some(v2::alert::AlertStatus::Active as i32),
        priority: Some(v2::alert::DiscretePriority::High as i32),
        description: Some("UAV inside the perimeter".into()),
        confidence: Some(0.8),
        ..Default::default()
    };
    let mut all = vec![
        envelope(0, Content::Registration(registration)),
        envelope(1, Content::StatusReport(status)),
    ];
    all.extend(detections);
    all.push(envelope(8, Content::Alert(alert)));
    all
}

/// The scenario as the bytes on a TCP stream: each message framed. Used by
/// the capture test; the conformance test needs only the messages.
#[allow(dead_code)]
pub fn capture() -> Vec<u8> {
    messages()
        .iter()
        .flat_map(|m| ajar_sapient_wire::frame(&ajar_sapient_wire::encode(m)))
        .collect()
}
