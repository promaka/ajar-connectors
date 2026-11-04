// SPDX-License-Identifier: Apache-2.0
//! Security marking: the operator's `[marking]` block, stamped on every event
//! before sealing so the `class:`, `rel:`, `policy:` and `caveat:` tags Core's
//! policy engine reads are inside the signature. The configured level is a
//! floor: a wire marking can raise it, never lower it.

use ajar_connector::Event;
use serde::Deserialize;

/// The canonical classification levels, lowest first. Connectors emit these
/// so two sites' events compare as strings.
pub const LEVELS: [&str; 5] = [
    "unclassified",
    "restricted",
    "confidential",
    "secret",
    "top-secret",
];

/// The most tags one `[marking]` block may produce. The stamp runs after the
/// builder's tag limit is checked, so this leaves room under it for wire tags.
pub const MAX_CONFIG_TAGS: usize = 16;

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MarkingConfig {
    /// Any case, and the aliases Core accepts.
    #[serde(default)]
    pub classification: Option<String>,
    /// Country trigrams or a group name.
    #[serde(default)]
    pub releasable_to: Vec<String>,
    /// The classification policy the level belongs to (`NATO`, `UK`).
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default)]
    pub caveats: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MarkingError {
    #[error(
        "[marking] is present but sets nothing; give it a classification, \
         releasable_to, policy or caveats, or remove the block"
    )]
    Empty,
    #[error(
        "[marking] classification {0:?} is not a level; use one of {levels} (any case; \
         Core would ignore the tag and the events would ship unclassified)",
        levels = LEVELS.join(", ")
    )]
    UnknownLevel(String),
    /// A releasability, policy or caveat token that is empty, too long or not
    /// ASCII letters, digits, `-` or `_`.
    #[error(
        "[marking] {field} entry {value:?} must be letters, digits, '-' or '_' \
         with no spaces (a country trigram such as GBR, or a name such as NATO)"
    )]
    BadToken { field: &'static str, value: String },
    #[error("[marking] produces {0} tags; at most {MAX_CONFIG_TAGS} are allowed")]
    TooMany(usize),
}

/// A validated marking: its tags in a fixed order, so two connectors with the
/// same block sign identical bytes for identical events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marking {
    tags: Vec<String>,
}

impl Marking {
    pub fn from_config(cfg: &MarkingConfig) -> Result<Marking, MarkingError> {
        let mut tags: Vec<String> = Vec::new();
        let mut push = |tag: String| {
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        };
        if let Some(level) = &cfg.classification {
            let canonical = classification_level(level)
                .ok_or_else(|| MarkingError::UnknownLevel(level.clone()))?;
            push(format!("class:{canonical}"));
        }
        if let Some(policy) = &cfg.policy {
            push(format!("policy:{}", token("policy", policy)?));
        }
        for party in &cfg.releasable_to {
            push(format!("rel:{}", token("releasable_to", party)?));
        }
        for caveat in &cfg.caveats {
            push(format!("caveat:{}", token("caveats", caveat)?));
        }
        if tags.is_empty() {
            return Err(MarkingError::Empty);
        }
        if tags.len() > MAX_CONFIG_TAGS {
            return Err(MarkingError::TooMany(tags.len()));
        }
        Ok(Marking { tags })
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Stamp the marking on an event. The classification resolves to one
    /// `class:` tag, the higher of the wire's and the operator's; other wire
    /// tags stay, and no tag is doubled, so applying twice is harmless.
    pub fn apply(&self, event: &mut Event) {
        let floor = self
            .tags
            .iter()
            .find_map(|t| t.strip_prefix("class:"))
            .and_then(classification_level);
        if let Some(floor) = floor {
            let ranked = |t: &String| t.strip_prefix("class:").and_then(classification_level);
            let highest = event
                .policy_tags
                .iter()
                .filter_map(ranked)
                .fold(floor, |a, b| if rank(b) > rank(a) { b } else { a });
            // One class tag, where the wire's was or first, so a consumer that
            // reads the first class tag sees the resolved level.
            let at = event
                .policy_tags
                .iter()
                .position(|t| ranked(t).is_some())
                .unwrap_or(0);
            event.policy_tags.retain(|t| ranked(t).is_none());
            let at = at.min(event.policy_tags.len());
            event.policy_tags.insert(at, format!("class:{highest}"));
        }
        for tag in self.tags.iter().filter(|t| !t.starts_with("class:")) {
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
/// spells it: any case, hyphen, underscore or space between words, and Core's
/// short forms.
pub fn classification_level(raw: &str) -> Option<&'static str> {
    let lower = raw.trim().to_ascii_lowercase().replace(['_', '-'], " ");
    let i = match lower.as_str() {
        "unclassified" | "unclass" | "u" => 0,
        "restricted" | "r" => 1,
        "confidential" | "c" => 2,
        "secret" | "s" => 3,
        "top secret" | "topsecret" | "ts" => 4,
        _ => return None,
    };
    Some(LEVELS[i])
}

/// Position of a canonical level in [`LEVELS`], lowest first.
fn rank(level: &str) -> usize {
    LEVELS.iter().position(|l| *l == level).unwrap_or(0)
}

/// The tags for a STANAG 4774 confidentiality label as STANAG 4676 carries it.
///
/// A stated policy identifier wins. Without one, `NATO <level>` and
/// `COSMIC TOP SECRET` carry `policy:NATO` and a bare level carries none. A
/// non-empty label that does not normalise is stamped `top-secret`, since
/// over-classifying is visible and under-classifying is not. An empty label
/// yields nothing.
pub fn wire_classification(raw: &str, policy_id: Option<&str>) -> Vec<String> {
    let upper = raw.trim().to_ascii_uppercase().replace(['_', '-'], " ");
    if upper.is_empty() {
        return Vec::new();
    }
    let (level, named_policy) = if upper == "COSMIC TOP SECRET" {
        (Some("top-secret"), Some("NATO"))
    } else if let Some(rest) = upper.strip_prefix("NATO ") {
        (classification_level(rest), Some("NATO"))
    } else {
        (classification_level(&upper), None)
    };
    let level = level.unwrap_or("top-secret");
    let mut tags = vec![format!("class:{level}")];
    let policy = policy_id
        .and_then(|p| token("policy", p).ok())
        .or_else(|| named_policy.map(str::to_string));
    if let Some(p) = policy {
        tags.push(format!("policy:{p}"));
    }
    tags
}

/// A releasability, policy or caveat token: trimmed, uppercased as Core reads
/// it, and restricted to what a tag can carry unambiguously.
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
    fn block_yields_tags_in_a_fixed_order() {
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
    fn caveat_alone_is_a_valid_marking() {
        let m = Marking::from_config(&block(r#"caveats = ["EXERCISE"]"#)).unwrap();
        assert_eq!(m.tags(), ["caveat:EXERCISE"]);
    }

    #[test]
    fn levels_canonicalise_from_any_spelling() {
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
    fn unknown_level_is_refused_naming_the_levels() {
        let e = Marking::from_config(&block(r#"classification = "official""#)).unwrap_err();
        assert_eq!(e, MarkingError::UnknownLevel("official".into()));
        let msg = e.to_string();
        for level in LEVELS {
            assert!(msg.contains(level), "{msg}");
        }
        assert!(msg.contains("unclassified"), "{msg}");
    }

    #[test]
    fn empty_block_is_refused() {
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
    fn repeated_party_once_and_too_many_refused() {
        let m = Marking::from_config(&block(r#"releasable_to = ["GBR", "ITA", "GBR"]"#)).unwrap();
        assert_eq!(m.tags(), ["rel:GBR", "rel:ITA"]);
        let many: Vec<String> = (0..MAX_CONFIG_TAGS + 1)
            .map(|i| format!("\"P{i}\""))
            .collect();
        let e = Marking::from_config(&block(&format!("releasable_to = [{}]", many.join(","))))
            .unwrap_err();
        assert_eq!(e, MarkingError::TooMany(MAX_CONFIG_TAGS + 1));
    }

    #[test]
    fn config_level_is_a_floor_for_the_wire() {
        let m = Marking::from_config(&block(
            "classification = \"restricted\"\ncaveats = [\"EXERCISE\"]",
        ))
        .unwrap();
        let wire = |tags: &[&str]| {
            let mut b = EventBuilder::new("s", "mim:object").new_id().now();
            for t in tags {
                b = b.policy_tag(*t);
            }
            b.build().unwrap()
        };
        let mut ev = wire(&["class:secret", "policy:NATO", "caveat:EXERCISE"]);
        m.apply(&mut ev);
        assert_eq!(
            ev.policy_tags,
            ["class:secret", "policy:NATO", "caveat:EXERCISE"],
            "a higher wire level stands"
        );
        let mut ev = wire(&["class:unclassified", "policy:NATO"]);
        m.apply(&mut ev);
        assert_eq!(
            ev.policy_tags,
            ["class:restricted", "policy:NATO", "caveat:EXERCISE"],
            "a lower wire level is raised to the floor"
        );
        let mut ev = wire(&[]);
        m.apply(&mut ev);
        assert_eq!(ev.policy_tags, ["class:restricted", "caveat:EXERCISE"]);
        m.apply(&mut ev);
        assert_eq!(
            ev.policy_tags,
            ["class:restricted", "caveat:EXERCISE"],
            "applying twice changes nothing"
        );
        let only = Marking::from_config(&block(r#"caveats = ["EXERCISE"]"#)).unwrap();
        let mut ev = wire(&["class:secret"]);
        only.apply(&mut ev);
        assert_eq!(
            ev.policy_tags,
            ["class:secret", "caveat:EXERCISE"],
            "a caveat-only marking leaves the wire level alone"
        );
    }

    #[test]
    fn wire_labels_normalise_to_tags() {
        let w = |raw: &str, pid: Option<&str>| wire_classification(raw, pid);
        assert_eq!(
            w("NATO UNCLASSIFIED", None),
            ["class:unclassified", "policy:NATO"]
        );
        assert_eq!(w("NATO SECRET", None), ["class:secret", "policy:NATO"]);
        assert_eq!(w("NATO_SECRET", None), ["class:secret", "policy:NATO"]);
        assert_eq!(
            w("COSMIC TOP SECRET", None),
            ["class:top-secret", "policy:NATO"]
        );
        assert_eq!(w("SECRET", None), ["class:secret"]);
        assert_eq!(w("Top Secret", None), ["class:top-secret"]);
        assert_eq!(w("TOP_SECRET", None), ["class:top-secret"]);
        assert_eq!(w("SECRET", Some("UK")), ["class:secret", "policy:UK"]);
        assert_eq!(
            w("NATO SECRET", Some("TEST")),
            ["class:secret", "policy:TEST"]
        );
        assert_eq!(w("PROTECTED B", None), ["class:top-secret"]);
        assert_eq!(
            w("SECRET//NOFORN", Some("US")),
            ["class:top-secret", "policy:US"]
        );
        assert!(w("", Some("UK")).is_empty());
        assert!(w("   ", None).is_empty());
    }
}
