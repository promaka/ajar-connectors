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

/// What a connector proposes to emit, checked before it starts.
#[derive(Debug, Default)]
pub struct Declared {
    /// Entity types, or `x:`-namespaced vendor types (which are not checked).
    pub entity_types: Vec<String>,
    /// Governed attribute names the mapping will set.
    pub attributes: Vec<String>,
    /// Attribute values that are fixed at config time, so can be checked now.
    pub fixed_values: BTreeMap<String, String>,
}

/// A mapping fault worth refusing to start over.
#[derive(Debug, PartialEq, Eq)]
pub enum Fault {
    /// An entity type the ontology does not declare.
    UnknownEntityType {
        name: String,
        closest: Option<String>,
    },
    /// An attribute no ancestor of the declared types allows.
    UnknownAttribute {
        name: String,
        closest: Option<String>,
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
            Fault::UnknownAttribute { name, closest } => {
                write!(
                    f,
                    "attribute {name:?} is not governed for these entity types"
                )?;
                if let Some(c) = closest {
                    write!(f, " (did you mean {c:?}?)")?;
                }
                write!(f, "; it would be discarded, put it in metadata instead")
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
    let all_ids: Vec<String> = ont.types.iter().map(|t| t.id.clone()).collect();
    let mut faults = Vec::new();

    // Attributes are inherited, so an aircraft may set anything mim:object allows.
    let mut allowed: BTreeMap<String, AttrDef> = BTreeMap::new();
    let mut known_types: BTreeSet<&str> = BTreeSet::new();

    for want in &declared.entity_types {
        // A vendor namespace is registered with the operator, not declared here.
        if want.starts_with("x:") {
            continue;
        }
        match by_id.get(want.as_str()) {
            None => faults.push(Fault::UnknownEntityType {
                name: want.clone(),
                closest: closest(want, all_ids.iter()),
            }),
            Some(_) => {
                known_types.insert(want.as_str());
                let mut cur = Some(want.as_str());
                while let Some(id) = cur {
                    if let Some(t) = by_id.get(id) {
                        for a in &t.attributes {
                            allowed.entry(a.name.clone()).or_insert_with(|| a.clone());
                        }
                        cur = t.parent.as_deref();
                    } else {
                        break;
                    }
                }
            }
        }
    }

    // With no recognised type there is nothing to check attributes against, and
    // reporting every attribute as unknown would bury the real fault.
    if known_types.is_empty() {
        return faults;
    }

    for name in &declared.attributes {
        if !allowed.contains_key(name) {
            faults.push(Fault::UnknownAttribute {
                name: name.clone(),
                closest: closest(name, allowed.keys().collect::<Vec<_>>().into_iter()),
            });
        }
    }

    for (name, value) in &declared.fixed_values {
        if let Some(def) = allowed.get(name) {
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

    fn d(types: &[&str], attrs: &[&str]) -> Declared {
        Declared {
            entity_types: types.iter().map(|s| s.to_string()).collect(),
            attributes: attrs.iter().map(|s| s.to_string()).collect(),
            fixed_values: BTreeMap::new(),
        }
    }

    #[test]
    fn a_correct_mapping_passes() {
        assert!(check(&d(&["mim:aircraft"], &["speed", "hostility", "callsign"])).is_empty());
    }

    #[test]
    fn attributes_are_inherited_from_ancestors() {
        // `hostility` is declared on mim:object; an aircraft may still set it.
        assert!(check(&d(&["mim:aircraft"], &["hostility"])).is_empty());
    }

    #[test]
    fn an_invented_entity_type_is_caught() {
        let f = check(&d(&["mim:banana"], &[]));
        assert!(
            matches!(f.as_slice(), [Fault::UnknownEntityType { name, .. }] if name == "mim:banana")
        );
    }

    #[test]
    fn a_case_error_in_the_type_suggests_the_real_one() {
        let f = check(&d(&["mim:Aircraft"], &[]));
        match f.as_slice() {
            [Fault::UnknownEntityType { closest, .. }] => {
                assert_eq!(closest.as_deref(), Some("mim:aircraft"))
            }
            other => panic!("expected a suggestion, got {other:?}"),
        }
    }

    #[test]
    fn an_undeclared_attribute_is_caught_and_points_at_metadata() {
        let f = check(&d(&["mim:aircraft"], &["speed_kn"]));
        assert!(
            matches!(f.as_slice(), [Fault::UnknownAttribute { name, .. }] if name == "speed_kn")
        );
        assert!(f[0].to_string().contains("metadata"));
    }

    #[test]
    fn a_lowercase_hostility_is_caught_with_the_correct_value() {
        let mut decl = d(&["mim:aircraft"], &["hostility"]);
        decl.fixed_values
            .insert("hostility".into(), "friendly".into());
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
        assert!(check(&d(&["x:acme:radar-hit"], &[])).is_empty());
    }

    #[test]
    fn every_fault_is_reported_at_once() {
        let f = check(&d(&["mim:aircraft"], &["speed_kn", "nonsense"]));
        assert_eq!(f.len(), 2, "one restart should show every fault");
    }

    #[test]
    fn the_declared_unit_is_available_for_diagnostics() {
        assert_eq!(unit_of("speed").as_deref(), Some("m/s"));
    }
}
