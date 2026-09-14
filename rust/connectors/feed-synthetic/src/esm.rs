// SPDX-License-Identifier: Apache-2.0
//! ESM: intercepts of a navigation radar, as JSON lines for the `generic`
//! connector with the mapping in `generic/esm-synthetic.example.toml`.
//!
//! This is the feed a fusion partner correlating emitters cares about. It
//! reports what an electronic support receiver measures about a signal, as
//! distinct from what it can identify: an emission has parameters long before
//! it has a name.
//!
//! The emitter fingerprint contract revision 4 governs is all here: the ELINT
//! notation, pulse repetition frequency, pulse width, scan period, bearing and
//! its accuracy, and the two links that make the hardest association case in
//! the scenario resolvable. `carried_by` names the platform the emitter is
//! mounted on, the vessel, by her MMSI under the AIS standard code.
//! `observed_by` names the receiver, co-located with the coastal radar, by that
//! radar's SAC/SIC under the ASTERIX code, because a fixed site has no other
//! code in the list. The bearing is true, clockwise from north, from that
//! receiver to the emitter at the observation time.
//!
//! The position rides in metadata by design: an ESM receiver gives a line,
//! not a fix, and it takes two lines or a correlation to make a position. The
//! truth the bearing points at rides as `truth_lat` and `truth_lon` so a
//! consumer can check their association against it, and the event carries no
//! `location` because the sensor produced none. `scan_type` is governed free
//! text in the contract and is emitted as such.

use std::time::SystemTime;

use crate::scenario::{rfc3339, Emitter, EmitterState, Vessel, RADAR_SAC, RADAR_SIC};

/// One intercept as a JSON line.
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
    use ajar_connector_common::Enrichment;
    use ajar_generic::{GenericParser, Mapping};

    /// The shipped mapping, so the test proves the file a site would deploy.
    fn mapping() -> Mapping {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../generic/esm-synthetic.example.toml"
        ))
        .expect("the ESM mapping ships beside the generic connector");
        #[derive(serde::Deserialize)]
        struct W {
            mapping: Mapping,
        }
        toml::from_str::<W>(&text).expect("mapping parses").mapping
    }

    #[test]
    fn an_intercept_maps_to_governed_equipment_with_the_full_fingerprint() {
        let d = GenericParser::new("esm-1", mapping(), Enrichment::default());
        let e = Emitter::at(40.0);
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_780_000_000);
        let ev = d.to_event(intercept(&e, now).as_bytes()).expect("maps");
        assert_eq!(ev.entity_type, "mim:equipment");
        // The observation time is the receiver's own, carried on the line.
        assert_eq!(ev.timestamp, "2026-05-28T20:26:40Z");
        let attr = |k: &str| {
            ev.attributes
                .iter()
                .find(|a| a.key == k)
                .map(|a| a.value.clone())
        };
        let meta = |k: &str| {
            ev.metadata
                .iter()
                .find(|a| a.key == k)
                .map(|a| a.value.clone())
        };
        assert_eq!(attr("elnot").as_deref(), Some("G1234"));
        // Numbers pass through as the JSON wrote them; a consumer parses.
        let num = |k: &str| attr(k).unwrap().parse::<f64>().unwrap();
        assert_eq!(num("prf_hz"), Emitter::PRF_HZ);
        assert_eq!(num("pulse_width_us"), Emitter::PULSE_WIDTH_US);
        assert_eq!(num("scan_period_s"), Emitter::SCAN_PERIOD_S);
        assert_eq!(num("bearing_accuracy_deg"), Emitter::BEARING_ACCURACY_DEG);
        let b: f64 = attr("bearing_deg").unwrap().parse().unwrap();
        assert!((b - e.bearing_deg).abs() < 0.06, "{b} vs {}", e.bearing_deg);
        assert_eq!(attr("frequency_hz").as_deref(), Some("9410000000"));
        assert_eq!(attr("carried_by_alt_id").as_deref(), Some("235009870"));
        assert_eq!(attr("carried_by_alt_id_standard").as_deref(), Some("AIS"));
        assert_eq!(attr("observed_by_alt_id").as_deref(), Some("25:10"));
        assert_eq!(
            attr("observed_by_alt_id_standard").as_deref(),
            Some("ASTERIX")
        );
        // Free text in the contract, so the receiver's own word is governed.
        assert_eq!(attr("scan_type").as_deref(), Some("circular"));
        assert!(attr("modulation").is_none());
        // A line, not a fix.
        assert!(ev.location.is_none(), "an ESM bearing is not a position");
        assert!(meta("truth_lat").is_some());
    }
}
