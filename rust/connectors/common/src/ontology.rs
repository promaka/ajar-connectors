// SPDX-License-Identifier: Apache-2.0
//! Check a connector's declared mapping against the vendored ontology, at boot.
//!
//! Core runs a graceful ingest: an entity type or attribute name it does not
//! recognise is discarded rather than rejected. That keeps a feed alive through
//! an ontology change, but it means a typo has no symptom. The connector runs,
//! seals, publishes, reports healthy — and the tracks never appear. Operators
//! lose days to it, and the failure looks like a network problem.
//!
//! So the check happens here instead, before the first frame: a mapping that
//! names something the ontology does not declare stops the connector with a
//! message naming the offender, rather than being discarded silently downstream.
//!
//! The ontology is vendored and hash-pinned alongside `event.proto`, so this
//! never reaches the network and works in an air-gapped build.
//!
//! Attributes are NOT inherited. Core looks an attribute up on the event's own
//! entity type, so the per-type list in the ontology is the whole truth and the
//! narrowing in it is deliberate: `environment` is declared on `mim:object`
//! alone, because a typed class already implies its domain, and `mim:sensor`
//! deliberately lacks the kinematics its parent `mim:equipment` allows. A
//! validator that walked the parent chain would be more permissive than the
//! enforcer, which is worse than having no validator at all: it would certify
//! exactly the mappings Core discards in silence. One `Declared` is therefore
//! one entity type and what a connector sets on it; a connector that emits
//! several types checks each.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

/// The vendored ontology, compiled in so a connector validates without a file.
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

/// What a connector proposes to emit on ONE entity type, checked before it
/// starts. A connector that emits several types builds one of these per type,
/// because the ontology governs attributes per type and so does Core.
#[derive(Debug, Default)]
pub struct Declared {
    /// The entity type, or an `x:`-namespaced vendor type (not checked here;
    /// the operator registers those).
    pub entity_type: String,
    /// Governed attribute names the mapping sets on that type.
    pub attributes: Vec<String>,
    /// Attribute values fixed at config time, so checkable now. A list, not a
    /// map: one attribute may take several fixed values across a connector's
    /// paths, and every one of them is checked.
    pub fixed_values: Vec<(String, String)>,
}

/// A mapping fault worth refusing to start over.
#[derive(Debug, PartialEq, Eq)]
pub enum Fault {
    /// An entity type the ontology does not declare.
    UnknownEntityType {
        name: String,
        closest: Option<String>,
    },
    /// An attribute the declared entity type does not allow. Not inherited:
    /// see the module doc.
    UnknownAttribute {
        name: String,
        closest: Option<String>,
        /// The nearest ancestor that does declare it, when there is one. This is
        /// the whole mistake in one field: the author assumed inheritance, and
        /// naming the type that governs the attribute says so plainly.
        governed_on: Option<String>,
    },
    /// A value outside a controlled vocabulary, which case errors trip.
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
                         would discard it here"
                    )?;
                } else {
                    write!(f, "; it would be discarded")?;
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

/// The nearest ancestor of `from` that declares `attribute`, if any. The parent
/// chain is read for this reason alone: an attribute that exists further up is
/// an author assuming inheritance, and the fault should say so rather than
/// leaving them to guess.
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

/// Case-insensitive near match, which is what catches `friendly` for `Friend`
/// and `mim:Aircraft` for `mim:aircraft` — the two mistakes that cost most.
fn closest<'a>(needle: &str, hay: impl Iterator<Item = &'a String>) -> Option<String> {
    let lower = needle.to_ascii_lowercase();
    hay.filter(|c| c.to_ascii_lowercase() == lower)
        .map(|c| c.to_string())
        .next()
}

/// Validate a declared mapping. Returns every fault, so one restart shows all of
/// them rather than one per attempt.
pub fn check(declared: &Declared) -> Vec<Fault> {
    let ont = load();
    let by_id: BTreeMap<&str, &TypeDef> = ont.types.iter().map(|t| (t.id.as_str(), t)).collect();
    let mut faults = Vec::new();

    // A vendor namespace is registered with the operator, not declared here.
    if declared.entity_type.starts_with("x:") {
        return faults;
    }
    let Some(def) = by_id.get(declared.entity_type.as_str()) else {
        let all: Vec<String> = ont.types.iter().map(|t| t.id.clone()).collect();
        faults.push(Fault::UnknownEntityType {
            name: declared.entity_type.clone(),
            closest: closest(&declared.entity_type, all.iter()),
        });
        // With no recognised type there is nothing to check attributes against,
        // and reporting every attribute as unknown would bury the real fault.
        return faults;
    };

    // The type's own list, and nothing from its parents: Core reads it the same
    // way (see the module doc).
    let allowed: BTreeMap<&str, &AttrDef> = def
        .attributes
        .iter()
        .map(|a| (a.name.as_str(), a))
        .collect();
    let names: BTreeSet<&String> = def.attributes.iter().map(|a| &a.name).collect();

    for name in &declared.attributes {
        if !allowed.contains_key(name.as_str()) {
            faults.push(Fault::UnknownAttribute {
                name: name.clone(),
                closest: closest(name, names.iter().copied()),
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
        tracing::info!(ontology = %load().version, "mapping validated against the ontology");
        return Ok(());
    }
    for f in &faults {
        tracing::error!("{f}");
    }
    anyhow::bail!(
        "{} mapping fault(s) against ontology {}: the events would be accepted by the \
         bus and discarded by Core, so the connector is refusing to start",
        faults.len(),
        load().version
    )
}

/// The unit the ontology declares for an attribute, for diagnostics.
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
    fn attributes_are_not_inherited_because_core_does_not_inherit_them() {
        // The ontology lists every attribute a type allows, including the ones
        // it shares with its parent, and Core reads only that list. So the
        // deliberate narrowings are enforced here too: a sensor has no speed
        // even though its parent equipment does, and only a bare mim:object
        // carries environment, because a typed class implies its domain.
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
        // The fault names the type that does govern it, which is the mistake
        // stated back to the author rather than left to guess.
        let msg = f[0].to_string();
        assert!(msg.contains("mim:object"), "{msg}");
        assert!(msg.contains("not inherited"), "{msg}");
        assert!(msg.contains("metadata"), "{msg}");
        // A sensor's missing speed points at the parent that has it.
        let msg = check(&d("mim:sensor", &["speed"]))[0].to_string();
        assert!(msg.contains("mim:equipment"), "{msg}");
        // A name nobody governs says so without inventing an ancestor.
        let msg = check(&d("mim:aircraft", &["not_a_thing"]))[0].to_string();
        assert!(!msg.contains("it is governed on"), "{msg}");
        assert!(msg.contains("would be discarded"), "{msg}");
    }

    #[test]
    fn an_invented_entity_type_is_caught() {
        let f = check(&d("mim:banana", &[]));
        assert!(
            matches!(f.as_slice(), [Fault::UnknownEntityType { name, .. }] if name == "mim:banana")
        );
    }

    #[test]
    fn a_case_error_in_the_type_suggests_the_real_one() {
        let f = check(&d("mim:Aircraft", &[]));
        match f.as_slice() {
            [Fault::UnknownEntityType { closest, .. }] => {
                assert_eq!(closest.as_deref(), Some("mim:aircraft"))
            }
            other => panic!("expected a suggestion, got {other:?}"),
        }
    }

    #[test]
    fn an_undeclared_attribute_is_caught_and_points_at_metadata() {
        let f = check(&d("mim:aircraft", &["speed_kn"]));
        assert!(
            matches!(f.as_slice(), [Fault::UnknownAttribute { name, .. }] if name == "speed_kn")
        );
        assert!(f[0].to_string().contains("metadata"));
    }

    #[test]
    fn a_lowercase_hostility_is_caught_with_the_correct_value() {
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
    fn a_vendor_namespace_is_not_second_guessed() {
        // x: types are registered with the operator, not declared in the ontology.
        assert!(check(&d("x:acme:radar-hit", &[])).is_empty());
    }

    #[test]
    fn every_fault_is_reported_at_once() {
        let f = check(&d("mim:aircraft", &["speed_kn", "nonsense"]));
        assert_eq!(f.len(), 2, "one restart should show every fault");
    }

    #[test]
    fn the_declared_unit_is_available_for_diagnostics() {
        assert_eq!(unit_of("speed").as_deref(), Some("m/s"));
    }
}
