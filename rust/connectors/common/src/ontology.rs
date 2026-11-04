// SPDX-License-Identifier: Apache-2.0
//! Check a connector's mapping against the vendored ontology at boot, and route
//! values per event. Core does not inherit attributes: it looks a name up on the
//! event's own entity type, so every check here reads that type's list alone.
//! A mapping fault would only show as quarantined fields or rejected events.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use ajar_connector::{Event, EventBuilder};
use serde::Deserialize;

const ONTOLOGY_JSON: &str = include_str!("../../../../vendor/contract/ontology.json");

#[derive(Debug, Deserialize)]
struct Ontology {
    version: String,
    types: Vec<TypeDef>,
}

#[derive(Debug, Deserialize)]
struct TypeDef {
    id: String,
    parent: Option<String>,
    #[serde(default)]
    attributes: Vec<AttrDef>,
}

#[derive(Debug, Deserialize, Clone)]
struct AttrDef {
    name: String,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    values: Option<Vec<String>>,
}

/// What a connector proposes to emit on one entity type. A connector that
/// emits several types declares each.
#[derive(Debug, Default)]
pub struct Declared {
    /// A `mim:` type; an `x:` vendor type is the operator's and passes.
    pub entity_type: String,
    pub attributes: Vec<String>,
    /// Attribute values fixed at config time. One attribute may appear with
    /// several values, and each is checked.
    pub fixed_values: Vec<(String, String)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Fault {
    UnknownEntityType {
        name: String,
        closest: Option<String>,
    },
    UnknownAttribute {
        name: String,
        closest: Option<String>,
        /// The nearest ancestor that declares it.
        governed_on: Option<String>,
    },
    NotInVocabulary {
        attribute: String,
        value: String,
        allowed: Vec<String>,
    },
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::UnknownEntityType { name, closest } => {
                write!(f, "entity_type {name:?} is not in the ontology")?;
                if let Some(c) = closest {
                    write!(f, " (did you mean {c:?}?)")?;
                }
                Ok(())
            }
            Fault::UnknownAttribute {
                name,
                closest,
                governed_on,
            } => {
                write!(f, "attribute {name:?} is not governed on this entity type")?;
                if let Some(c) = closest {
                    write!(f, " (did you mean {c:?}?)")?;
                }
                if let Some(anc) = governed_on {
                    write!(
                        f,
                        "; it is governed on {anc:?}, but attributes are not inherited, so Core \
                         would not govern it here"
                    )?;
                } else {
                    write!(f, "; Core would not govern it")?;
                }
                write!(f, ". Put it in metadata instead, which is always kept")
            }
            Fault::NotInVocabulary {
                attribute,
                value,
                allowed,
            } => write!(
                f,
                "{attribute} = {value:?} is not one of {}; values are case-sensitive",
                allowed.join(", ")
            ),
        }
    }
}

/// The nearest ancestor of `from` that declares `attribute`. The parent chain
/// is read only to name it in a fault.
fn nearest_ancestor_governing(
    by_id: &BTreeMap<&str, &TypeDef>,
    from: &TypeDef,
    attribute: &str,
) -> Option<String> {
    let mut cur = from.parent.as_deref();
    while let Some(id) = cur {
        let t = by_id.get(id)?;
        if t.attributes.iter().any(|a| a.name == attribute) {
            return Some(t.id.clone());
        }
        cur = t.parent.as_deref();
    }
    None
}

fn load() -> Ontology {
    serde_json::from_str(ONTOLOGY_JSON).expect("vendored ontology is valid JSON")
}

/// The ontology parsed once into a per-type attribute index, for the per-event
/// helpers.
struct Index {
    version: String,
    attrs: BTreeMap<String, BTreeSet<String>>,
}

fn index() -> &'static Index {
    static INDEX: OnceLock<Index> = OnceLock::new();
    INDEX.get_or_init(|| {
        let ont = load();
        Index {
            version: ont.version,
            attrs: ont
                .types
                .into_iter()
                .map(|t| (t.id, t.attributes.into_iter().map(|a| a.name).collect()))
                .collect(),
        }
    })
}

/// Whether `entity_type` is outside the vendored contract (`x:acme:radar-hit`,
/// `sapient:detection`), so the operator's registration with Core governs it.
pub fn operator_namespace(entity_type: &str) -> bool {
    !entity_type.starts_with("mim:")
}

/// Whether the ontology declares `attribute` on `entity_type` itself. An
/// operator-namespace type allows anything.
pub fn governs(entity_type: &str, attribute: &str) -> bool {
    operator_namespace(entity_type)
        || index()
            .attrs
            .get(entity_type)
            .is_some_and(|set| set.contains(attribute))
}

/// Whether the ontology declares `entity_type`. An operator-namespace type
/// counts as known.
pub fn knows_type(entity_type: &str) -> bool {
    operator_namespace(entity_type) || index().attrs.contains_key(entity_type)
}

/// The attributes on a built event that its own entity type does not declare:
/// quarantined on a graceful site, rejected on a strict one. For an unknown
/// entity type this is every attribute; see [`knows_type`].
pub fn ungoverned(event: &Event) -> Vec<String> {
    event
        .attributes
        .iter()
        .filter(|a| !governs(&event.entity_type, &a.key))
        .map(|a| a.key.clone())
        .collect()
}

/// Route a value to an attribute when the event's own type declares the name,
/// to metadata otherwise: Core's demotion, done visibly at the producer.
pub trait GovernedAttribute {
    fn governed(self, entity_type: &str, key: &str, value: impl Into<String>) -> Self;
}

impl GovernedAttribute for EventBuilder {
    fn governed(self, entity_type: &str, key: &str, value: impl Into<String>) -> Self {
        if governs(entity_type, key) {
            self.attribute(key, value)
        } else {
            self.metadata(key, value)
        }
    }
}

pub fn version() -> &'static str {
    &index().version
}

/// Case-insensitive match, which catches `mim:Aircraft` for `mim:aircraft`.
fn closest<'a, S: AsRef<str> + 'a>(
    needle: &str,
    hay: impl Iterator<Item = &'a S>,
) -> Option<String> {
    let lower = needle.to_ascii_lowercase();
    hay.map(AsRef::as_ref)
        .find(|c| c.to_ascii_lowercase() == lower)
        .map(str::to_string)
}

/// Every fault in a declared mapping, so one restart shows them all.
pub fn check(declared: &Declared) -> Vec<Fault> {
    let ont = load();
    let by_id: BTreeMap<&str, &TypeDef> = ont.types.iter().map(|t| (t.id.as_str(), t)).collect();
    let mut faults = Vec::new();

    if declared.entity_type.starts_with("x:") {
        return faults;
    }
    let Some(def) = by_id.get(declared.entity_type.as_str()) else {
        let all: Vec<String> = ont.types.iter().map(|t| t.id.clone()).collect();
        faults.push(Fault::UnknownEntityType {
            name: declared.entity_type.clone(),
            closest: closest(&declared.entity_type, all.iter()),
        });
        // Every attribute would be unknown too, burying the real fault.
        return faults;
    };

    let allowed: BTreeMap<&str, &AttrDef> = def
        .attributes
        .iter()
        .map(|a| (a.name.as_str(), a))
        .collect();

    for name in &declared.attributes {
        if !allowed.contains_key(name.as_str()) {
            faults.push(Fault::UnknownAttribute {
                name: name.clone(),
                closest: closest(name, allowed.keys()),
                governed_on: nearest_ancestor_governing(&by_id, def, name),
            });
        }
    }

    for (name, value) in &declared.fixed_values {
        if let Some(def) = allowed.get(name.as_str()) {
            if let Some(values) = &def.values {
                if !values.contains(value) {
                    faults.push(Fault::NotInVocabulary {
                        attribute: name.clone(),
                        value: value.clone(),
                        allowed: values.clone(),
                    });
                }
            }
        }
    }

    faults
}

/// Check and refuse to start on any fault.
pub fn enforce(declared: &Declared) -> anyhow::Result<()> {
    let faults = check(declared);
    if faults.is_empty() {
        tracing::info!(
            ontology = version(),
            "mapping validated against the ontology"
        );
        return Ok(());
    }
    for f in &faults {
        tracing::error!(fault = %f, "mapping fault");
    }
    anyhow::bail!(
        "{} mapping fault(s) against ontology {}: Core would reject these events or \
         quarantine the fields, so the connector is refusing to start",
        faults.len(),
        version()
    )
}

/// The unit the ontology declares for an attribute.
pub fn unit_of(attribute: &str) -> Option<String> {
    load()
        .types
        .iter()
        .flat_map(|t| t.attributes.iter())
        .find(|a| a.name == attribute)
        .and_then(|a| a.unit.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(ty: &str, attrs: &[&str]) -> Declared {
        Declared {
            entity_type: ty.to_string(),
            attributes: attrs.iter().map(|s| s.to_string()).collect(),
            fixed_values: Vec::new(),
        }
    }

    #[test]
    fn a_correct_mapping_passes() {
        assert!(check(&d("mim:aircraft", &["speed", "hostility", "callsign"])).is_empty());
    }

    #[test]
    fn attributes_are_not_inherited() {
        assert!(check(&d("mim:aircraft", &["hostility", "speed"])).is_empty());
        assert!(check(&d("mim:equipment", &["speed"])).is_empty());
        let f = check(&d("mim:sensor", &["speed"]));
        assert!(matches!(f.as_slice(), [Fault::UnknownAttribute { name, .. }] if name == "speed"));
        assert!(check(&d("mim:object", &["environment"])).is_empty());
        let f = check(&d("mim:vessel", &["environment"]));
        assert!(
            matches!(f.as_slice(), [Fault::UnknownAttribute { name, .. }] if name == "environment"),
            "{f:?}"
        );
        let msg = f[0].to_string();
        assert!(msg.contains("mim:object"), "{msg}");
        assert!(msg.contains("not inherited"), "{msg}");
        assert!(msg.contains("metadata"), "{msg}");
        let msg = check(&d("mim:sensor", &["speed"]))[0].to_string();
        assert!(msg.contains("mim:equipment"), "{msg}");
        let msg = check(&d("mim:aircraft", &["not_a_thing"]))[0].to_string();
        assert!(!msg.contains("it is governed on"), "{msg}");
        assert!(msg.contains("Core would not govern it"), "{msg}");
    }

    #[test]
    fn invented_entity_type_is_caught() {
        let f = check(&d("mim:banana", &[]));
        assert!(
            matches!(f.as_slice(), [Fault::UnknownEntityType { name, .. }] if name == "mim:banana")
        );
    }

    #[test]
    fn type_case_error_suggests_the_real_type() {
        let f = check(&d("mim:Aircraft", &[]));
        match f.as_slice() {
            [Fault::UnknownEntityType { closest, .. }] => {
                assert_eq!(closest.as_deref(), Some("mim:aircraft"))
            }
            other => panic!("expected a suggestion, got {other:?}"),
        }
    }

    #[test]
    fn undeclared_attribute_points_at_metadata() {
        let f = check(&d("mim:aircraft", &["speed_kn"]));
        assert!(
            matches!(f.as_slice(), [Fault::UnknownAttribute { name, .. }] if name == "speed_kn")
        );
        assert!(f[0].to_string().contains("metadata"));
    }

    #[test]
    fn lowercase_hostility_is_a_vocabulary_fault() {
        let mut decl = d("mim:aircraft", &["hostility"]);
        decl.fixed_values
            .push(("hostility".into(), "friendly".into()));
        let f = check(&decl);
        match f.as_slice() {
            [Fault::NotInVocabulary { value, allowed, .. }] => {
                assert_eq!(value, "friendly");
                assert!(allowed.contains(&"Friend".to_string()));
            }
            other => panic!("expected a vocabulary fault, got {other:?}"),
        }
    }

    #[test]
    fn governed_routes_by_the_events_own_type() {
        assert!(governs("mim:aircraft", "squawk"));
        assert!(!governs("mim:object", "squawk"));
        assert!(governs("mim:object", "environment"));
        assert!(!governs("mim:vessel", "environment"));
        assert!(governs("x:acme:radar-hit", "anything"));
        assert!(!governs("mim:banana", "speed"));

        let ev = EventBuilder::new("s", "mim:vessel")
            .new_id()
            .now()
            .governed("mim:vessel", "speed", "8.0")
            .governed("mim:vessel", "environment", "SURFACE")
            .governed("mim:vessel", "squawk", "1234")
            .build()
            .unwrap();
        let attrs: Vec<&str> = ev.attributes.iter().map(|a| a.key.as_str()).collect();
        let meta: Vec<&str> = ev.metadata.iter().map(|a| a.key.as_str()).collect();
        assert_eq!(attrs, ["speed"]);
        assert_eq!(meta, ["environment", "squawk"]);
        assert!(ungoverned(&ev).is_empty());

        let raw = EventBuilder::new("s", "mim:sensor")
            .new_id()
            .now()
            .attribute("speed", "1")
            .attribute("hostility", "Unknown")
            .build()
            .unwrap();
        assert_eq!(ungoverned(&raw), ["speed"]);
        assert!(version().starts_with("mim-5.3-conformant-"));
    }

    #[test]
    fn vendor_namespace_is_not_checked() {
        assert!(check(&d("x:acme:radar-hit", &[])).is_empty());
    }

    #[test]
    fn every_fault_is_reported_at_once() {
        let f = check(&d("mim:aircraft", &["speed_kn", "nonsense"]));
        assert_eq!(f.len(), 2, "one restart should show every fault");
    }

    #[test]
    fn declared_unit_is_available() {
        assert_eq!(unit_of("speed").as_deref(), Some("m/s"));
    }
}
