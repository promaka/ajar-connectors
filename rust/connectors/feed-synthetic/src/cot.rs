// SPDX-License-Identifier: Apache-2.0
//! CoT: a friendly shore party's self-report as XML on the TAK multicast group,
//! read by the `tak-cot` connector. It carries an identity and a position only:
//! `ce` and `le` are TAK's unknown sentinel and there is no `<track>`.

use std::time::{Duration, SystemTime};

use crate::scenario::{rfc3339, Unit};

/// How long the report stays valid, as TAK's `stale`.
const STALE_S: u64 = 60;

pub fn event(observed: SystemTime) -> String {
    let t = rfc3339(observed);
    let stale = rfc3339(observed + Duration::from_secs(STALE_S));
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<event version="2.0" uid="{uid}" type="{ty}" how="m-g" time="{t}" start="{t}" stale="{stale}">"#,
            r#"<point lat="{lat:.6}" lon="{lon:.6}" hae="{hae:.1}" ce="9999999.0" le="9999999.0"/>"#,
            r#"<detail><contact callsign="{cs}"/><__group name="Cyan" role="Team Member"/></detail>"#,
            r#"</event>"#,
        ),
        uid = Unit::UID,
        ty = Unit::COT_TYPE,
        t = t,
        stale = stale,
        lat = Unit::FIX.lat,
        lon = Unit::FIX.lon,
        hae = Unit::ALT_M,
        cs = Unit::CALLSIGN,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{observed, OBSERVED};
    use ajar_connector_common::Enrichment;
    use ajar_tak_cot::CotParser;

    #[test]
    fn self_report_decodes_to_friendly_unit() {
        let d = CotParser::new("tak-1", Default::default(), Enrichment::default());
        let ev = d.to_event(event(observed()).as_bytes()).expect("valid CoT");
        assert_eq!(ev.timestamp, OBSERVED);
        let loc = ev.location.expect("a self-report has a position");
        assert!((loc.latitude - Unit::FIX.lat).abs() < 1e-6);
        assert!((loc.longitude - Unit::FIX.lon).abs() < 1e-6);
        let find = |k: &str| {
            ev.attributes
                .iter()
                .chain(ev.metadata.iter())
                .find(|a| a.key == k)
                .map(|a| a.value.clone())
        };
        assert_eq!(find("callsign").as_deref(), Some("BRAVO21"));
        assert_eq!(find("hostility").as_deref(), Some("Friend"));
        assert_eq!(find("alt_id").as_deref(), Some("SHORE-PARTY-1"));
        assert_eq!(find("alt_id_standard").as_deref(), Some("CoT"));
        assert!(
            find("course").is_none(),
            "a standing unit reports no course"
        );
        assert!(find("speed").is_none());
    }
}
