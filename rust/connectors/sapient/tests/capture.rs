// SPDX-License-Identifier: Apache-2.0
//! The replay test: the bench capture, frame by frame as the `file` transport
//! delivers it, must yield one event per world-describing message, each
//! geolocated once the node has said where it is, with every report accepted.
//!
//! `tests/data/sapient-capture.bin` is the scenario in `support` on the wire.
//! Regenerate it with `SAPIENT_WRITE_CAPTURE=1 cargo test -p ajar-sapient
//! --test capture` after changing the scenario; the first test fails until the
//! file and the scenario agree again.

mod support;

use ajar_connector_common::{Enrichment, FrameParser};
use ajar_sapient::SapientParser;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/sapient-capture.bin"
);

#[test]
fn the_fixture_is_the_scenario_on_the_wire() {
    let expected = support::capture();
    if std::env::var_os("SAPIENT_WRITE_CAPTURE").is_some() {
        std::fs::write(FIXTURE, &expected).expect("writing the fixture");
    }
    let on_disk = std::fs::read(FIXTURE).expect("the committed capture");
    assert_eq!(on_disk, expected, "regenerate with SAPIENT_WRITE_CAPTURE=1");
}

#[test]
fn every_report_in_the_capture_is_accepted_and_the_track_is_geolocated() {
    let bytes = std::fs::read(FIXTURE).expect("the committed capture");
    let parser = SapientParser::new("sapient-fusion-1", Enrichment::default());
    let mut rest = &bytes[..];
    let mut events = Vec::new();
    let mut frames = 0;
    while !rest.is_empty() {
        let (payload, after) = ajar_sapient_wire::unframe(rest).expect("a whole frame");
        frames += 1;
        events.extend(parser.parse(payload).expect("every frame parses"));
        rest = after;
    }
    assert_eq!(
        frames, 8,
        "registration, status, five detections, one alert"
    );
    assert_eq!(events.len(), 8, "each publishes one event");

    let kinds: Vec<&str> = events.iter().map(|e| e.entity_type.as_str()).collect();
    assert_eq!(kinds[0], "sapient:sensor-status");
    assert_eq!(kinds[1], "sapient:sensor-status");
    assert!(kinds[2..7].iter().all(|k| *k == "sapient:track"));
    assert_eq!(kinds[7], "sapient:alert");

    // The radar reported its position before any detection, so every
    // detection is geolocated against it, north-east and closing.
    let node = events[1].location.as_ref().expect("the node's position");
    let mut last_range = f64::MAX;
    for e in &events[2..7] {
        let loc = e.location.as_ref().expect("geolocated");
        assert!(loc.latitude > node.latitude && loc.longitude > node.longitude);
        let dlat = (loc.latitude - node.latitude).to_radians();
        let dlon = (loc.longitude - node.longitude).to_radians() * node.latitude.to_radians().cos();
        let range = (dlat * dlat + dlon * dlon).sqrt() * 6_371_008.8;
        assert!(range < last_range, "closing");
        last_range = range;
        assert_eq!(
            e.metadata
                .iter()
                .find(|m| m.key == "source_uid")
                .map(|m| m.value.as_str()),
            Some(format!("{}:{}", support::NODE, support::OBJECT).as_str())
        );
    }
    assert!(
        (last_range - 1100.0 * 2f64.to_radians().cos()).abs() < 5.0,
        "{last_range}"
    );
}

#[tokio::test]
async fn the_file_transport_delivers_the_capture_frame_by_frame() {
    use ajar_connector_common::{open_source, Framing, Transport};
    let transport = Transport::File {
        path: FIXTURE.to_string(),
        from_start: true,
        framing: Framing::LengthU32le,
    };
    let mut source = open_source(&transport).await.expect("opens");
    let parser = SapientParser::new("sapient-fusion-1", Enrichment::default());
    let mut buf = vec![0u8; ajar_connector_common::MAX_FRAME_BYTES];
    let mut published = 0;
    for _ in 0..8 {
        let n = source.recv(&mut buf).await.expect("a frame");
        published += parser.parse(&buf[..n]).expect("parses").len();
    }
    assert_eq!(published, 8);
}
