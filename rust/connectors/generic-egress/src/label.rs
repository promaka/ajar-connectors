// SPDX-License-Identifier: Apache-2.0
//! STANAG 4774-shaped confidentiality labels, projected from policy tags.
//!
//! NATO-facing consumers and accreditors expect a confidentiality label in
//! the 4774 information model: a policy identifier, a classification, and
//! category values such as releasability. Ajar's markings already carry that
//! information as policy tags (`class:secret`, `rel:NATO`,
//! `releasable:maritime`); this module PROJECTS those tags into the 4774
//! shape on delivery. A projection, deliberately:
//!
//!  - it changes no enforcement anywhere (Core governs exactly as before);
//!  - the tags themselves are still delivered verbatim in `policy_tags`,
//!    which remains the source of truth (the label can be cross-checked
//!    against it by any consumer);
//!  - it is opt-in per deployment, so no existing consumer's format changes;
//!  - classification values pass through uppercased rather than being
//!    reinterpreted: the deployment's policy defines the vocabulary, and a
//!    projection that second-guessed it would be an enforcement change.
//!
//! The 4778-style binding of label to data needs no new mechanism here: the
//! label is derived from policy tags that live INSIDE the sealed envelope,
//! signed at origin and re-signed by the egress authority.

use ajar_connector::Event;
use serde::Deserialize;
use serde_json::{json, Value};

/// Per-deployment label settings, under `[confidentiality_label]`.
#[derive(Debug, Clone, Deserialize)]
pub struct LabelConfig {
    /// The security policy the label's values are defined by (4774 labels are
    /// meaningless without one). Set it to the policy authority your
    /// accreditor names, e.g. a national or coalition policy identifier.
    pub policy_identifier: String,
}

/// Project an event's policy tags into a confidentiality label, or `None`
/// when the event carries no `class:` tag (no classification means there is
/// nothing to label; the tags, if any, still ride in `policy_tags`).
pub fn confidentiality_label(cfg: &LabelConfig, event: &Event) -> Option<Value> {
    let mut classification: Option<String> = None;
    let mut releasability: Vec<String> = Vec::new();

    for tag in &event.policy_tags {
        if let Some(v) = tag.strip_prefix("class:") {
            // First class: tag wins; a second one is a malformed marking and
            // stays visible in policy_tags rather than being adjudicated here.
            if classification.is_none() && !v.trim().is_empty() {
                classification = Some(v.trim().to_uppercase());
            }
        } else if let Some(v) = tag.strip_prefix("rel:") {
            releasability.push(v.trim().to_uppercase());
        } else if let Some(v) = tag.strip_prefix("releasable:") {
            releasability.push(v.trim().to_uppercase());
        }
    }
    let classification = classification?;

    releasability.sort_unstable();
    releasability.dedup();
    releasability.retain(|v| !v.is_empty());

    let mut label = json!({
        "policyIdentifier": cfg.policy_identifier,
        "classification": classification,
        "creationDateTime": event.timestamp,
    });
    if !releasability.is_empty() {
        label["categories"] = json!([{
            "tagName": "Releasability",
            "type": "PERMISSIVE",
            "values": releasability,
        }]);
    }
    Some(label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector::EventBuilder;

    fn cfg() -> LabelConfig {
        LabelConfig {
            policy_identifier: "TEST-POLICY".into(),
        }
    }

    fn event(tags: &[&str]) -> Event {
        let mut b = EventBuilder::new("s-1", "mim:vessel")
            .new_id()
            .timestamp("2026-09-01T10:00:00Z");
        for t in tags {
            b = b.policy_tag(*t);
        }
        b.build().unwrap()
    }

    #[test]
    fn class_and_releasability_project_into_the_4774_shape() {
        let label = confidentiality_label(
            &cfg(),
            &event(&["class:secret", "rel:NATO", "releasable:maritime"]),
        )
        .unwrap();
        assert_eq!(label["policyIdentifier"], "TEST-POLICY");
        assert_eq!(label["classification"], "SECRET");
        assert_eq!(label["creationDateTime"], "2026-09-01T10:00:00Z");
        let values = label["categories"][0]["values"].as_array().unwrap();
        // Sorted, deduplicated, uppercased.
        assert_eq!(values, &vec![json!("MARITIME"), json!("NATO")]);
        assert_eq!(label["categories"][0]["tagName"], "Releasability");
    }

    #[test]
    fn the_policy_vocabulary_passes_through_not_reinterpreted() {
        // A policy-specific level the projection has never heard of survives
        // verbatim (uppercased): the policy owns the vocabulary.
        let label = confidentiality_label(&cfg(), &event(&["class:cosmic-ts"])).unwrap();
        assert_eq!(label["classification"], "COSMIC-TS");
        assert!(label.get("categories").is_none());
    }

    #[test]
    fn no_class_tag_means_no_label_not_a_guessed_one() {
        assert!(confidentiality_label(&cfg(), &event(&["rel:NATO"])).is_none());
        assert!(confidentiality_label(&cfg(), &event(&[])).is_none());
    }

    #[test]
    fn a_conflicting_second_class_tag_does_not_flap_the_label() {
        let label =
            confidentiality_label(&cfg(), &event(&["class:secret", "class:restricted"])).unwrap();
        // First wins deterministically; the conflict stays visible in
        // policy_tags, which is always delivered verbatim.
        assert_eq!(label["classification"], "SECRET");
    }
}
