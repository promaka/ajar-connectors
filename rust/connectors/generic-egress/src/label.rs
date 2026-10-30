// SPDX-License-Identifier: Apache-2.0
//! STANAG 4774-shaped confidentiality labels, projected from policy tags.
//!
//! `class:` becomes the classification and `rel:`/`releasable:` the
//! Releasability category. The tags themselves are still delivered verbatim in
//! `policy_tags`.

use ajar_connector::Event;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelConfig {
    pub policy_identifier: String,
}

/// The label for an event, or `None` when it carries no `class:` tag. Values
/// pass through uppercased; the first `class:` tag wins.
pub fn confidentiality_label(cfg: &LabelConfig, event: &Event) -> Option<Value> {
    let mut classification: Option<String> = None;
    let mut releasability: Vec<String> = Vec::new();

    for tag in &event.policy_tags {
        if let Some(v) = tag.strip_prefix("class:") {
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

    let mut label = serde_json::json!({
        "policyIdentifier": cfg.policy_identifier,
        "classification": classification,
        "creationDateTime": event.timestamp,
    });
    if !releasability.is_empty() {
        label["categories"] = serde_json::json!([{
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
    fn class_and_releasability_project_to_label() {
        let label = confidentiality_label(
            &cfg(),
            &event(&["class:secret", "rel:NATO", "releasable:maritime"]),
        )
        .unwrap();
        assert_eq!(label["policyIdentifier"], "TEST-POLICY");
        assert_eq!(label["classification"], "SECRET");
        assert_eq!(label["creationDateTime"], "2026-09-01T10:00:00Z");
        let values = label["categories"][0]["values"].as_array().unwrap();
        assert_eq!(
            values,
            &vec![serde_json::json!("MARITIME"), serde_json::json!("NATO")],
            "sorted, deduplicated, uppercased"
        );
        assert_eq!(label["categories"][0]["tagName"], "Releasability");
    }

    #[test]
    fn unknown_classification_passes_through() {
        let label = confidentiality_label(&cfg(), &event(&["class:cosmic-ts"])).unwrap();
        assert_eq!(label["classification"], "COSMIC-TS");
        assert!(label.get("categories").is_none());
    }

    #[test]
    fn no_class_tag_means_no_label() {
        assert!(confidentiality_label(&cfg(), &event(&["rel:NATO"])).is_none());
        assert!(confidentiality_label(&cfg(), &event(&[])).is_none());
    }

    #[test]
    fn first_class_tag_wins() {
        let label =
            confidentiality_label(&cfg(), &event(&["class:secret", "class:restricted"])).unwrap();
        assert_eq!(label["classification"], "SECRET");
    }
}
