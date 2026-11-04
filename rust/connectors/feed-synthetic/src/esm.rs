// SPDX-License-Identifier: Apache-2.0
//! ESM: intercepts of the vessel's navigation radar as JSON lines, read by the
//! `generic` connector with `generic/esm-synthetic.example.toml`. A bearing is
//! not a fix, so the event has no location; the emitter's true position rides
//! as `truth_lat` and `truth_lon` for checking an association.

use std::time::SystemTime;

use crate::scenario::{rfc3339, Emitter, EmitterState, Vessel, RADAR_SAC, RADAR_SIC};

pub fn intercept(e: &EmitterState, observed: SystemTime) -> String {
    let v = serde_json::json!({
        "time": rfc3339(observed),
        "emitter_id": Emitter::ID,
        "frequency_hz": Emitter::FREQUENCY_HZ,
        "bandwidth_hz": Emitter::BANDWIDTH_HZ,
        "power_dbm": round1(e.power_dbm),
        "elnot": Emitter::ELNOT,
        "prf_hz": Emitter::PRF_HZ,
        "pulse_width_us": Emitter::PULSE_WIDTH_US,
        "scan_type": Emitter::SCAN_TYPE,
        "scan_period_s": Emitter::SCAN_PERIOD_S,
        "bearing_deg": round1(e.bearing_deg),
        "bearing_accuracy_deg": Emitter::BEARING_ACCURACY_DEG,
        "carried_by": Vessel::MMSI.to_string(),
        "carried_by_standard": "AIS",
        "observed_by": format!("{RADAR_SAC}:{RADAR_SIC}"),
        "observed_by_standard": "ASTERIX",
        "truth_lat": e.fix.lat,
        "truth_lon": e.fix.lon,
    });
    let mut s = v.to_string();
    s.push('\n');
    s
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{attr, meta, num, observed, OBSERVED};
    use ajar_connector_common::Enrichment;
    use ajar_generic::{GenericParser, Mapping};

    #[derive(serde::Deserialize)]
    struct MappingFile {
        mapping: Mapping,
    }

    #[test]
    fn intercept_maps_to_equipment_with_fingerprint() {
        let shipped = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../generic/esm-synthetic.example.toml"
        ))
        .expect("the ESM mapping ships beside the generic connector");
        let mapping = toml::from_str::<MappingFile>(&shipped)
            .expect("mapping parses")
            .mapping;
        let d = GenericParser::new("esm-1", mapping, Enrichment::default());
        let e = Emitter::at(40.0);
        let ev = d
            .to_event(intercept(&e, observed()).as_bytes())
            .expect("maps");
        assert_eq!(ev.entity_type, "mim:equipment");
        assert_eq!(ev.timestamp, OBSERVED, "the receiver's own time");
        assert_eq!(attr(&ev, "elnot").as_deref(), Some("G1234"));
        assert_eq!(num(&ev, "prf_hz"), Emitter::PRF_HZ);
        assert_eq!(num(&ev, "pulse_width_us"), Emitter::PULSE_WIDTH_US);
        assert_eq!(num(&ev, "scan_period_s"), Emitter::SCAN_PERIOD_S);
        assert_eq!(
            num(&ev, "bearing_accuracy_deg"),
            Emitter::BEARING_ACCURACY_DEG
        );
        let b = num(&ev, "bearing_deg");
        assert!((b - e.bearing_deg).abs() < 0.06, "{b} vs {}", e.bearing_deg);
        assert_eq!(attr(&ev, "frequency_hz").as_deref(), Some("9410000000"));
        assert_eq!(attr(&ev, "carried_by_alt_id").as_deref(), Some("235009870"));
        assert_eq!(
            attr(&ev, "carried_by_alt_id_standard").as_deref(),
            Some("AIS")
        );
        assert_eq!(attr(&ev, "observed_by_alt_id").as_deref(), Some("25:10"));
        assert_eq!(
            attr(&ev, "observed_by_alt_id_standard").as_deref(),
            Some("ASTERIX")
        );
        assert_eq!(attr(&ev, "scan_type").as_deref(), Some("circular"));
        assert!(attr(&ev, "modulation").is_none());
        assert!(ev.location.is_none(), "an ESM bearing is not a position");
        assert!(meta(&ev, "truth_lat").is_some());
    }
}
