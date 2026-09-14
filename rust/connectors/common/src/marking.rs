// SPDX-License-Identifier: Apache-2.0
//! Security marking, stamped on every event a connector publishes.
//!
//! A site that cannot mark its data cannot use the clearance machinery it is
//! paying for: Core's policy engine reads `class:`, `rel:`, `policy:` and
//! `caveat:` tags off each event, and until now nothing on the way in set them,
//! so every event from a stock connector arrived unclassified. The `[marking]`
//! block is the operator's assertion about a feed, applied by the shared
//! runtime before sealing so the tags are inside the signature. That is the
//! difference between this and marking applied after ingest: a tag bound at
//! origin is what the provenance statement claims, a tag added later is not.
//!
//! ```toml
//! [marking]
//! classification = "restricted"     # unclassified | restricted | confidential | secret | top-secret
//! releasable_to = ["GBR", "ITA"]    # ISO 3166-1 alpha-3, or a group such as NATO
//! policy = "NATO"                   # whose classification scheme the level is in
//! caveats = ["EXERCISE"]
//! ```
//!
//! Every field is optional and the block may name any one of them: a synthetic
//! feed marks itself `caveats = ["EXERCISE"]` with no classification at all, so
//! a training track carries the caveat inside its signature wherever it goes.
//!
//! The config is a floor, not a ceiling. A tag the wire carried stays, and Core
//! takes the highest `class:` it finds, so a feed's own marking can raise the
//! level the operator set but never lower it. That is what an operator means
//! by "nothing from this radar is below RESTRICTED".
//!
//! Validation is at load and fails closed. Core ignores a tag it does not
//! recognise, so a typo here would ship unclassified events in silence, which
//! is the exact failure the block exists to end.

use ajar_connector::Event;
use serde::Deserialize;

/// The canonical classification levels, lowest first. Core parses aliases
/// (`u`, `unclass`, `ts`, `topsecret`, any case) and canonicalises to these; a
/// connector emits the canonical form so two sites' events compare as strings.
pub const LEVELS: [&str; 5] = [
    "unclassified",
    "restricted",
    "confidential",
    "secret",
    "top-secret",
];

/// The most tags one `[marking]` block may produce. Generous for any real
/// marking, and leaves room under the event's tag limit for what the wire adds.
pub const MAX_CONFIG_TAGS: usize = 16;

/// The `[marking]` block as written.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MarkingConfig {
    /// Classification level. Any case, and the aliases Core accepts.
    #[serde(default)]
    pub classification: Option<String>,
    /// Who the events are releasable to: country trigrams or a group name.
    #[serde(default)]
    pub releasable_to: Vec<String>,
    /// The classification policy the level belongs to (`NATO`, `UK`).
    #[serde(default)]
    pub policy: Option<String>,
    /// Handling caveats (`NOFORN`, `EXERCISE`).
    #[serde(default)]
    pub caveats: Vec<String>,
}

/// Why a `[marking]` block was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum MarkingError {
    /// The block exists but asserts nothing.
    Empty,
    /// A classification outside the five levels and their aliases.
    UnknownLevel(String),
    /// A releasability, policy or caveat token that is empty or not plain
    /// ASCII letters and digits.
    BadToken { field: &'static str, value: String },
    /// More tags than [`MAX_CONFIG_TAGS`].
    TooMany(usize),
}

impl std::fmt::Display for MarkingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MarkingError::Empty => write!(
                f,
                "[marking] is present but sets nothing; give it a classification, \
                 releasable_to, policy or caveats, or remove the block"
            ),
            MarkingError::UnknownLevel(v) => write!(
                f,
                "[marking] classification {v:?} is not a level; use one of {} (any case; \
                 Core would ignore the tag and the events would ship unclassified)",
                LEVELS.join(", ")
            ),
            MarkingError::BadToken { field, value } => write!(
                f,
                "[marking] {field} entry {value:?} must be letters, digits, '-' or '_' \
                 with no spaces (a country trigram such as GBR, or a name such as NATO)"
            ),
            MarkingError::TooMany(n) => write!(
                f,
                "[marking] produces {n} tags; at most {MAX_CONFIG_TAGS} are allowed"
            ),
        }
    }
}

impl std::error::Error for MarkingError {}

/// A validated marking: the tags it stamps, in a fixed order, so two
/// connectors with the same block sign identical bytes for identical events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marking {
    tags: Vec<String>,
}

impl Marking {
    /// Validate a block into the tags it will stamp.
    pub fn from_config(cfg: &MarkingConfig) -> Result<Marking, MarkingError> {
        let mut tags = Vec::new();
        if let Some(level) = &cfg.classification {
            let canonical = classification_level(level)
                .ok_or_else(|| MarkingError::UnknownLevel(level.clone()))?;
            tags.push(format!("class:{canonical}"));
        }
        if let Some(policy) = &cfg.policy {
            tags.push(format!("policy:{}", token("policy", policy)?));
        }
        for party in &cfg.releasable_to {
            tags.push(format!("rel:{}", token("releasable_to", party)?));
        }
        for caveat in &cfg.caveats {
            tags.push(format!("caveat:{}", token("caveats", caveat)?));
        }
        if tags.is_empty() {
            return Err(MarkingError::Empty);
        }
        tags.dedup();
        if tags.len() > MAX_CONFIG_TAGS {
            return Err(MarkingError::TooMany(tags.len()));
        }
        Ok(Marking { tags })
    }

    /// The tags this marking stamps, in emission order.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Stamp the marking on an event. Tags the wire already placed stay, and a
    /// tag already present is not doubled, so applying twice is harmless.
    pub fn apply(&self, event: &mut Event) {
        for tag in &self.tags {
            if !event.policy_tags.contains(tag) {
                event.policy_tags.push(tag.clone());
            }
        }
    }
}

impl std::fmt::Display for Marking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.tags.join(" "))
    }
}

/// The canonical level for a classification as an operator or a wire format
/// spells it: case-insensitive, and the short forms Core also accepts.
pub fn classification_level(raw: &str) -> Option<&'static str> {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "unclassified" | "unclass" | "u" => Some("unclassified"),
        "restricted" | "r" => Some("restricted"),
        "confidential" | "c" => Some("confidential"),
        "secret" | "s" => Some("secret"),
        "top-secret" | "top secret" | "topsecret" | "top_secret" | "ts" => Some("top-secret"),
        _ => None,
    }
}

/// The tags for a NATO Information and Track Standard (STANAG 4676)
/// confidentiality label: the level, and the policy the string names.
///
/// `NATO SECRET` is a level under the NATO policy, and `COSMIC TOP SECRET` is
/// NATO's own name for its top level, so both carry `policy:NATO`. A bare level
/// (`SECRET`) carries no policy; the message's own `PolicyIdentifier` says whose
/// it is, and the caller passes that separately. An unrecognised string maps
/// to nothing rather than to a guess, and the raw wire string belongs in
/// metadata regardless, where nothing is lost.
pub fn nits_classification(raw: &str) -> Option<Vec<String>> {
    let trimmed = raw.trim();
    let upper = trimmed.to_ascii_uppercase();
    let (level, policy) = if upper == "COSMIC TOP SECRET" {
        ("top-secret", Some("NATO"))
    } else if let Some(rest) = upper.strip_prefix("NATO ") {
        (classification_level(rest)?, Some("NATO"))
    } else {
        (classification_level(&upper)?, None)
    };
    let mut tags = vec![format!("class:{level}")];
    if let Some(p) = policy {
        tags.push(format!("policy:{p}"));
    }
    Some(tags)
}

/// A releasability, policy or caveat token: trimmed, uppercased (Core
/// uppercases `rel:` and `caveat:` on parse, and every policy id it names is
/// uppercase), and restricted to what a tag can carry unambiguously.
fn token(field: &'static str, raw: &str) -> Result<String, MarkingError> {
    let t = raw.trim().to_ascii_uppercase();
    let ok = !t.is_empty()
        && t.len() <= 32
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(t)
    } else {
        Err(MarkingError::BadToken {
            field,
            value: raw.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector::EventBuilder;

    fn block(toml_text: &str) -> MarkingConfig {
        toml::from_str(toml_text).expect("block parses")
    }

    #[test]
    fn the_documented_block_produces_the_tags_core_reads_in_a_fixed_order() {
        let m = Marking::from_config(&block(
            r#"classification = "restricted"
               releasable_to = ["GBR", "ITA"]
               policy = "NATO"
               caveats = ["NOFORN"]"#,
        ))
        .unwrap();
        assert_eq!(
            m.tags(),
            [
                "class:restricted",
                "policy:NATO",
                "rel:GBR",
                "rel:ITA",
                "caveat:NOFORN"
            ]
        );
        assert_eq!(
            m.to_string(),
            "class:restricted policy:NATO rel:GBR rel:ITA caveat:NOFORN"
        );
    }

    #[test]
    fn a_caveat_alone_is_a_valid_marking() {
        // The first consumer: a synthetic feed marks itself EXERCISE and
        // asserts no classification at all.
        let m = Marking::from_config(&block(r#"caveats = ["EXERCISE"]"#)).unwrap();
        assert_eq!(m.tags(), ["caveat:EXERCISE"]);
    }

    #[test]
    fn levels_are_canonicalised_from_any_spelling_core_accepts() {
        for (raw, want) in [
            ("SECRET", "secret"),
            ("Top Secret", "top-secret"),
            ("ts", "top-secret"),
            ("u", "unclassified"),
            ("Unclass", "unclassified"),
            (" restricted ", "restricted"),
        ] {
            let m = Marking::from_config(&block(&format!("classification = {raw:?}"))).unwrap();
            assert_eq!(m.tags(), [format!("class:{want}")], "{raw}");
        }
    }

    #[test]
    fn an_unknown_level_is_refused_and_names_the_five() {
        let e = Marking::from_config(&block(r#"classification = "official""#)).unwrap_err();
        assert_eq!(e, MarkingError::UnknownLevel("official".into()));
        let msg = e.to_string();
        for level in LEVELS {
            assert!(msg.contains(level), "{msg}");
        }
        assert!(msg.contains("unclassified"), "{msg}");
    }

    #[test]
    fn an_empty_block_is_refused_rather_than_silently_asserting_nothing() {
        assert_eq!(
            Marking::from_config(&block("")).unwrap_err(),
            MarkingError::Empty
        );
        assert_eq!(
            Marking::from_config(&block("releasable_to = []")).unwrap_err(),
            MarkingError::Empty
        );
    }

    #[test]
    fn tokens_are_uppercased_and_junk_is_refused() {
        let m = Marking::from_config(&block("releasable_to = [\"gbr\"]\ncaveats = [\"noforn\"]"))
            .unwrap();
        assert_eq!(m.tags(), ["rel:GBR", "caveat:NOFORN"]);
        for bad in [
            r#"releasable_to = [""]"#,
            r#"caveats = ["NO FORN"]"#,
            r#"policy = "na:to""#,
        ] {
            assert!(
                matches!(
                    Marking::from_config(&block(bad)),
                    Err(MarkingError::BadToken { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_repeated_party_is_stamped_once_and_too_many_is_refused() {
        let m = Marking::from_config(&block(r#"releasable_to = ["GBR", "GBR"]"#)).unwrap();
        assert_eq!(m.tags(), ["rel:GBR"]);
        let many: Vec<String> = (0..MAX_CONFIG_TAGS + 1)
            .map(|i| format!("\"P{i}\""))
            .collect();
        let e = Marking::from_config(&block(&format!("releasable_to = [{}]", many.join(","))))
            .unwrap_err();
        assert_eq!(e, MarkingError::TooMany(MAX_CONFIG_TAGS + 1));
    }

    #[test]
    fn a_config_is_a_floor_the_wire_can_raise_but_not_lower() {
        let m = Marking::from_config(&block(
            "classification = \"restricted\"\ncaveats = [\"EXERCISE\"]",
        ))
        .unwrap();
        // The feed's own label survives beside the operator's, and Core takes
        // the highest class it finds.
        let mut ev = EventBuilder::new("s", "mim:object")
            .new_id()
            .now()
            .policy_tag("class:secret")
            .policy_tag("caveat:EXERCISE")
            .build()
            .unwrap();
        m.apply(&mut ev);
        assert_eq!(
            ev.policy_tags,
            ["class:secret", "caveat:EXERCISE", "class:restricted"]
        );
        // Applying again changes nothing.
        m.apply(&mut ev);
        assert_eq!(ev.policy_tags.len(), 3);
    }

    #[test]
    fn nits_labels_normalise_to_the_pair_core_reads() {
        assert_eq!(
            nits_classification("NATO UNCLASSIFIED").unwrap(),
            ["class:unclassified", "policy:NATO"]
        );
        assert_eq!(
            nits_classification("NATO SECRET").unwrap(),
            ["class:secret", "policy:NATO"]
        );
        assert_eq!(
            nits_classification("COSMIC TOP SECRET").unwrap(),
            ["class:top-secret", "policy:NATO"]
        );
        assert_eq!(nits_classification("SECRET").unwrap(), ["class:secret"]);
        assert_eq!(
            nits_classification("Top Secret").unwrap(),
            ["class:top-secret"]
        );
        assert_eq!(nits_classification("PROTECTED"), None);
        assert_eq!(nits_classification(""), None);
    }
}
