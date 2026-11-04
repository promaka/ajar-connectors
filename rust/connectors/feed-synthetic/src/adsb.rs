// SPDX-License-Identifier: Apache-2.0
//! ADS-B: the airliner as SBS-1 (BaseStation) lines, read by the `adsb`
//! connector. A report cycle is the identity, position, velocity and squawk
//! messages a receiver emits, which the connector reassembles per ICAO address.
//! Values are in the wire's units: feet, knots and feet per minute.

use std::time::SystemTime;

use crate::scenario::{Aircraft, AircraftState, FTMIN_PER_MPS, FT_PER_M, MPS_TO_KN};

/// One SBS-1 line; fields not given stay empty.
fn line(msg_type: u8, observed: SystemTime, fields: &[(usize, String)]) -> String {
    let odt = time::OffsetDateTime::from(observed);
    let date = format!(
        "{:04}/{:02}/{:02}",
        odt.year(),
        odt.month() as u8,
        odt.day()
    );
    let clock = format!(
        "{:02}:{:02}:{:02}.{:03}",
        odt.hour(),
        odt.minute(),
        odt.second(),
        odt.millisecond()
    );
    let msg_type = msg_type.to_string();
    let mut f = [""; 22];
    f[0] = "MSG";
    f[1] = &msg_type;
    f[2] = "1"; // session id
    f[3] = "1"; // aircraft id
    f[4] = Aircraft::ICAO24_HEX;
    f[5] = "1"; // flight id
    f[6] = &date; // generated
    f[7] = &clock;
    f[8] = &date; // logged
    f[9] = &clock;
    for (i, v) in fields {
        f[*i] = v;
    }
    f.join(",") + "\r\n"
}

/// One report cycle in receiver order: identity, position, velocity, squawk.
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
    use crate::fixtures::{attr, num, observed, EVENT_TIME};
    use ajar_adsb::AdsbParser;
    use ajar_connector_common::Enrichment;

    #[test]
    fn four_lines_reassemble_into_one_track() {
        let d = AdsbParser::new("adsb-1", Enrichment::default().with_hostility("Neutral"));
        let a = Aircraft::at(30.0);
        let text = report(&a, observed());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(
            lines[0].starts_with("MSG,1,1,1,4CA2D6,1,2026/05/28,20:26:40.000,"),
            "{}",
            lines[0]
        );
        assert!(
            d.parse_line(lines[0].as_bytes()).unwrap().is_none(),
            "identity alone yields nothing"
        );
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
        let text = report(&Aircraft::at(31.0), observed());
        let next: Vec<&str> = text.lines().collect();
        let p = d.parse_line(next[1].as_bytes()).unwrap().unwrap();
        assert_eq!(
            p.state.squawk.as_deref(),
            Some("1234"),
            "the next position carries the cached squawk"
        );
        let ev = d.to_event_at(p, EVENT_TIME).unwrap();
        assert_eq!(ev.entity_type, "mim:aircraft");
        assert_eq!(attr(&ev, "alt_id").as_deref(), Some("4CA2D6"));
        assert_eq!(attr(&ev, "alt_id_standard").as_deref(), Some("ICAO24"));
        assert_eq!(attr(&ev, "squawk").as_deref(), Some("1234"));
        let speed = num(&ev, "speed");
        assert!((speed - Aircraft::SPEED_MPS).abs() < 0.3, "{speed} m/s");
        let vr = num(&ev, "vertical_rate");
        assert!((vr - Aircraft::VERTICAL_RATE_MPS).abs() < 0.06, "{vr} m/s");
        assert_eq!(attr(&ev, "hostility").as_deref(), Some("Neutral"));
    }
}
