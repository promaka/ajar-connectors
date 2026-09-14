// SPDX-License-Identifier: Apache-2.0
//! ADS-B: the airliner as SBS-1 "BaseStation" lines, what the `adsb` connector
//! reads.
//!
//! SBS-1 is what receivers actually speak, and its quirk is that one aircraft
//! arrives split across message types: identity in MSG,1, position in MSG,3,
//! velocity and vertical rate in MSG,4, squawk in MSG,6. The connector keeps a
//! per-ICAO cache and reassembles them, so a generator that emitted a single fat
//! line would exercise a path no real receiver uses. This emits the real
//! sequence.
//!
//! Twenty-two comma-separated fields, and the ones the connector reads are
//! fixed by the published layout: 4 ICAO, 10 callsign, 11 altitude (feet),
//! 12 ground speed (knots), 13 track, 14 and 15 latitude and longitude,
//! 16 vertical rate (feet per minute), 17 squawk. Units are the wire's, not the
//! contract's: feet and knots here, normalised by the connector, with the
//! native values kept in metadata.

use std::time::SystemTime;

use crate::scenario::{Aircraft, AircraftState, FTMIN_PER_MPS, FT_PER_M, MPS_TO_KN};

/// The date and time fields as SBS-1 writes them.
fn stamp(t: SystemTime) -> (String, String) {
    let odt = time::OffsetDateTime::from(t);
    (
        format!(
            "{:04}/{:02}/{:02}",
            odt.year(),
            odt.month() as u8,
            odt.day()
        ),
        format!(
            "{:02}:{:02}:{:02}.{:03}",
            odt.hour(),
            odt.minute(),
            odt.second(),
            odt.millisecond()
        ),
    )
}

/// One SBS-1 line. Empty fields stay empty, which is how a real receiver
/// reports what a given message type does not carry.
fn line(msg_type: u8, observed: SystemTime, fields: &[(usize, String)]) -> String {
    let mut f: Vec<String> = vec![String::new(); 22];
    let (date, time) = stamp(observed);
    f[0] = "MSG".into();
    f[1] = msg_type.to_string();
    f[2] = "1".into(); // session id
    f[3] = "1".into(); // aircraft id
    f[4] = Aircraft::ICAO24_HEX.into();
    f[5] = "1".into(); // flight id
    f[6] = date.clone();
    f[7] = time.clone(); // generated
    f[8] = date;
    f[9] = time; // logged
    for (i, v) in fields {
        f[*i] = v.clone();
    }
    f.join(",") + "\r\n"
}

/// The four lines one report cycle produces, in the order a receiver emits
/// them: identity, position, velocity, squawk.
pub fn report(a: &AircraftState, observed: SystemTime) -> String {
    let mut out = String::new();
    out += &line(1, observed, &[(10, Aircraft::CALLSIGN.to_string())]);
    out += &line(
        3,
        observed,
        &[
            (11, format!("{:.0}", a.alt_m * FT_PER_M)),
            (14, format!("{:.6}", a.fix.lat)),
            (15, format!("{:.6}", a.fix.lon)),
        ],
    );
    out += &line(
        4,
        observed,
        &[
            (12, format!("{:.0}", a.speed_mps * MPS_TO_KN)),
            (13, format!("{:.0}", a.course_deg)),
            (16, format!("{:.0}", a.vertical_rate_mps * FTMIN_PER_MPS)),
        ],
    );
    out += &line(6, observed, &[(17, Aircraft::SQUAWK.to_string())]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_adsb::AdsbParser;
    use ajar_connector_common::Enrichment;

    #[test]
    fn the_four_lines_reassemble_into_one_identified_track() {
        let d = AdsbParser::new("adsb-1", Enrichment::default().with_hostility("Neutral"));
        let a = Aircraft::at(30.0);
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_780_000_000);
        let text = report(&a, now);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(
            lines[0].starts_with("MSG,1,1,1,4CA2D6,1,2026/05/28,20:26:40.000,"),
            "{}",
            lines[0]
        );
        // Identity alone yields nothing; the position line emits the track; the
        // rest fold into the cache for the next one.
        assert!(d.parse_line(lines[0].as_bytes()).unwrap().is_none());
        let p = d
            .parse_line(lines[1].as_bytes())
            .unwrap()
            .expect("position emits");
        assert_eq!(p.icao, "4CA2D6");
        assert!((p.lat - a.fix.lat).abs() < 1e-6);
        assert!((p.lon - a.fix.lon).abs() < 1e-6);
        assert!((p.alt_m - Aircraft::ALT_M).abs() < 0.2, "{}", p.alt_m);
        assert_eq!(p.state.callsign.as_deref(), Some("BAW117"));
        assert!(d.parse_line(lines[2].as_bytes()).unwrap().is_none());
        assert!(d.parse_line(lines[3].as_bytes()).unwrap().is_none());
        // The next cycle's position carries everything the cache learnt.
        let text = report(&Aircraft::at(31.0), now);
        let next: Vec<&str> = text.lines().collect();
        let p = d.parse_line(next[1].as_bytes()).unwrap().unwrap();
        assert_eq!(p.state.squawk.as_deref(), Some("1234"));
        let ev = d.to_event_at(&p, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:aircraft");
        let attr = |k: &str| {
            ev.attributes
                .iter()
                .find(|a| a.key == k)
                .map(|a| a.value.clone())
        };
        assert_eq!(attr("alt_id").as_deref(), Some("4CA2D6"));
        assert_eq!(attr("alt_id_standard").as_deref(), Some("ICAO24"));
        assert_eq!(attr("squawk").as_deref(), Some("1234"));
        // Knots and feet per minute on the wire, the contract's units in the event.
        let speed: f64 = attr("speed").unwrap().parse().unwrap();
        assert!((speed - Aircraft::SPEED_MPS).abs() < 0.3, "{speed}");
        let vr: f64 = attr("vertical_rate").unwrap().parse().unwrap();
        assert!((vr - Aircraft::VERTICAL_RATE_MPS).abs() < 0.06, "{vr}");
        assert_eq!(attr("hostility").as_deref(), Some("Neutral"));
    }
}
