// SPDX-License-Identifier: Apache-2.0
//! The 4676 decoder walks attacker-influenced XML — arbitrary namespace prefixes,
//! truncated elements, positions that lie, Base64 that is not — so its one absolute
//! obligation is to never panic: random bytes and track-shaped XML with random
//! field values must all return `Ok` or a typed error.

use ajar_connector_common::Enrichment;
use ajar_stanag4676::S4676Parser;
use proptest::prelude::*;
use std::collections::HashMap;

fn parser() -> S4676Parser {
    S4676Parser::new("fuzz", HashMap::new(), Enrichment::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parser().to_events(&bytes);
    }

    /// A well-formed track skeleton with attacker-chosen field values: a random
    /// uid string, coordinate system, position/velocity vectors, status, identity,
    /// and relTime. Exercises Base64 decode, the float-vector parse, the deferred
    /// per-track flush, and the time reconstruction. Must never panic.
    #[test]
    fn track_shaped_input_never_panics(
        uid in "[A-Za-z0-9+/=]{0,32}",
        cs in prop::sample::select(vec!["WGS_84", "ECEF", "LOCAL_CARTESIAN", "?"]),
        pos in "[-0-9. eE]{0,40}",
        vel in "[-0-9. eE]{0,40}",
        status in prop::sample::select(vec!["INITIATING", "MAINTAINING", "TERMINATED", "X"]),
        identity in prop::sample::select(vec!["FRIEND", "HOSTILE", "SUSPECT", ""]),
        rel in any::<i64>(),
    ) {
        let xml = format!(
            r#"<ns2:nitsRoot xmlns:ns2="urn:nato:niia:stanag:4676:isrtrackingstandard:b:1">
  <ns2:message>
    <ns2:baseTime>2026-06-10T08:00:00Z</ns2:baseTime>
    <ns2:relTimeIncrement>0.001</ns2:relTimeIncrement>
    <ns2:track>
      <ns2:uid>{uid}</ns2:uid>
      <ns2:segment><ns2:status>{status}</ns2:status>
        <ns2:tp>
          <ns2:relTime>{rel}</ns2:relTime>
          <ns2:dynamics cs="{cs}"><ns2:pos>{pos}</ns2:pos><ns2:vel>{vel}</ns2:vel></ns2:dynamics>
        </ns2:tp>
      </ns2:segment>
      <ns2:object><ns2:id1241><ns2:identity>{identity}</ns2:identity></ns2:id1241></ns2:object>
    </ns2:track>
  </ns2:message>
</ns2:nitsRoot>"#
        );
        let _ = parser().to_events(xml.as_bytes());
    }
}
