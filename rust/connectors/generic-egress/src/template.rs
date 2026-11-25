// SPDX-License-Identifier: Apache-2.0
//! Render a governed event into a consumer's own JSON body. The template is JSON in which a
//! string of the form `"${path}"` or `"${path|filter}"` is replaced by that event value. A path
//! absent from the event removes the key that holds it, and an element of an array none of whose
//! placeholders has a value is removed.

use ajar_connector::Event;
use anyhow::Context as _;
use serde_json::{Map, Number, Value};

use crate::map::{lookup, unmapped_content, validate_path, Unmapped};

/// The template-only path, alongside the event paths of [`crate::map`].
const UNMAPPED: &str = "unmapped";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filter {
    /// The value as it is: strings for attributes and metadata, numbers for positions.
    Keep,
    /// A number; a value that does not parse as a finite number is absent.
    Number,
    /// A string; a non-string value as its JSON text.
    Text,
}

#[derive(Debug, PartialEq)]
enum Node {
    Literal(Value),
    Field { path: String, filter: Filter },
    Object(Vec<(String, Node)>),
    Array(Vec<Node>),
}

#[derive(Debug, PartialEq)]
pub struct Template {
    root: Node,
    /// Every path the template places, for the unmapped content check.
    paths: Vec<String>,
}

impl Template {
    /// Compiles a template, refusing one that could drop the event id or its markings: it must
    /// place `id` and `policy_tags`, and `unmapped` unless `unmapped` is `refuse`.
    pub fn parse(text: &str, unmapped: Unmapped) -> anyhow::Result<Template> {
        let value: Value = serde_json::from_str(text).context("template is not JSON")?;
        let mut paths = Vec::new();
        let root = compile(value, &mut paths)?;
        let required = match unmapped {
            Unmapped::Include => &["id", "policy_tags", UNMAPPED][..],
            Unmapped::Refuse => &["id", "policy_tags"][..],
        };
        if let Some(missing) = required.iter().find(|p| !paths.iter().any(|q| q == *p)) {
            anyhow::bail!("template must place \"${{{missing}}}\"");
        }
        Ok(Template { root, paths })
    }

    /// The consumer body for one event, or `None` when `Unmapped::Refuse` rejects it.
    pub fn render(&self, event: &Event, unmapped: Unmapped) -> Option<Value> {
        let extra = unmapped_content(event, &self.paths);
        if extra.is_some() && unmapped == Unmapped::Refuse {
            return None;
        }
        let context = Context {
            event,
            unmapped: extra.map(Value::Object),
        };
        Some(context.fill(&self.root).value.unwrap_or(Value::Null))
    }
}

/// A filled node, and how many placeholders it holds and how many of them had a value.
struct Filled {
    value: Option<Value>,
    placeholders: usize,
    present: usize,
}

struct Context<'e> {
    event: &'e Event,
    unmapped: Option<Value>,
}

impl Context<'_> {
    /// `value` is `None` when a placeholder's path is absent, so its parent drops it.
    fn fill(&self, node: &Node) -> Filled {
        match node {
            Node::Literal(v) => Filled {
                value: Some(v.clone()),
                placeholders: 0,
                present: 0,
            },
            Node::Field { path, filter } => {
                let raw = match path.as_str() {
                    UNMAPPED => self.unmapped.clone(),
                    _ => lookup(self.event, path),
                };
                let value = raw.and_then(|v| match (filter, v) {
                    (Filter::Keep, v) => Some(v),
                    (Filter::Number, Value::Number(n)) => Some(Value::Number(n)),
                    (Filter::Number, Value::String(s)) => s
                        .trim()
                        .parse::<f64>()
                        .ok()
                        .and_then(Number::from_f64)
                        .map(Value::Number),
                    (Filter::Number, _) => None,
                    (Filter::Text, Value::String(s)) => Some(Value::String(s)),
                    (Filter::Text, v) => Some(Value::String(v.to_string())),
                });
                Filled {
                    present: usize::from(value.is_some()),
                    value,
                    placeholders: 1,
                }
            }
            Node::Object(fields) => {
                let mut object = Map::with_capacity(fields.len());
                let (mut placeholders, mut present) = (0, 0);
                for (key, child) in fields {
                    let filled = self.fill(child);
                    placeholders += filled.placeholders;
                    present += filled.present;
                    if let Some(value) = filled.value {
                        object.insert(key.clone(), value);
                    }
                }
                Filled {
                    value: Some(Value::Object(object)),
                    placeholders,
                    present,
                }
            }
            Node::Array(items) => {
                let mut array = Vec::with_capacity(items.len());
                let (mut placeholders, mut present) = (0, 0);
                for child in items {
                    let filled = self.fill(child);
                    placeholders += filled.placeholders;
                    present += filled.present;
                    let empty = filled.placeholders > 0 && filled.present == 0;
                    if let (Some(value), false) = (filled.value, empty) {
                        array.push(value);
                    }
                }
                Filled {
                    value: Some(Value::Array(array)),
                    placeholders,
                    present,
                }
            }
        }
    }
}

fn compile(value: Value, paths: &mut Vec<String>) -> anyhow::Result<Node> {
    Ok(match value {
        Value::String(s) => match s.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
            Some(inner) => {
                let (path, filter) = match inner.split_once('|') {
                    None => (inner.trim(), Filter::Keep),
                    Some((path, "number")) => (path.trim(), Filter::Number),
                    Some((path, "text")) => (path.trim(), Filter::Text),
                    Some((_, other)) => {
                        anyhow::bail!("unknown filter {other:?} in {s:?}: expected number or text")
                    }
                };
                if path != UNMAPPED {
                    validate_path(path)?;
                }
                paths.push(path.to_string());
                Node::Field {
                    path: path.to_string(),
                    filter,
                }
            }
            None => Node::Literal(Value::String(s)),
        },
        Value::Object(map) => Node::Object(
            map.into_iter()
                .map(|(k, v)| Ok((k, compile(v, paths)?)))
                .collect::<anyhow::Result<_>>()?,
        ),
        Value::Array(items) => Node::Array(
            items
                .into_iter()
                .map(|v| compile(v, paths))
                .collect::<anyhow::Result<_>>()?,
        ),
        other => Node::Literal(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector::EventBuilder;

    const TRACK: &str = r#"{
        "feed": "external",
        "updates": [{
            "action": 0,
            "id": "${meta:source_uid}",
            "position": {
                "time": "${timestamp}",
                "lat": "${lat}",
                "lon": "${lon}",
                "speed": "${attr:speed|number}",
                "callsign": "${attr:callsign}"
            },
            "fields": [
                {"id": "ajar.event_id", "value": "${id}"},
                {"id": "ajar.policy_tags", "value": "${policy_tags|text}"},
                {"id": "ajar.unmapped", "value": "${unmapped|text}"}
            ]
        }]
    }"#;

    fn event() -> Event {
        EventBuilder::new("coastal-radar", "mim:vessel")
            .new_id()
            .timestamp("2026-06-10T08:00:00Z")
            .location(59.33, 18.07, 0.0)
            .attribute("speed", "8.20")
            .attribute("hostility", "Friend")
            .metadata("source_uid", "T-7")
            .policy_tag("class:restricted")
            .policy_tag("rel:NATO")
            .build()
            .unwrap()
    }

    fn render(template: &str, unmapped: Unmapped) -> Option<Value> {
        Template::parse(template, unmapped)
            .unwrap()
            .render(&event(), unmapped)
    }

    #[test]
    fn fills_the_consumer_shape() {
        let out = render(TRACK, Unmapped::Include).unwrap();
        let update = &out["updates"][0];
        assert_eq!(out["feed"], "external");
        assert_eq!(update["action"], 0);
        assert_eq!(update["id"], "T-7");
        assert_eq!(update["position"]["time"], "2026-06-10T08:00:00Z");
        assert_eq!(update["position"]["lat"], 59.33);
        assert_eq!(update["position"]["speed"], 8.2, "number filter");
    }

    #[test]
    fn absent_value_drops_its_key() {
        let out = render(TRACK, Unmapped::Include).unwrap();
        assert!(out["updates"][0]["position"].get("callsign").is_none());
    }

    #[test]
    fn array_entry_with_no_values_is_removed() {
        let template = Template::parse(TRACK, Unmapped::Include).unwrap();
        let mut event = event();
        event.attributes.retain(|a| a.key == "speed");
        let out = template.render(&event, Unmapped::Include).unwrap();
        let fields = out["updates"][0]["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 2, "no unmapped content, no unmapped entry");
    }

    #[test]
    fn array_entry_with_some_values_is_kept() {
        let template = Template::parse(
            r#"{"updates":[{"id":"${id}","name":"${attr:callsign}"}],"t":"${policy_tags}","u":"${unmapped}"}"#,
            Unmapped::Include,
        )
        .unwrap();
        let out = template.render(&event(), Unmapped::Include).unwrap();
        let update = &out["updates"][0];
        assert!(update["id"].is_string(), "{out}");
        assert!(update.get("name").is_none());
    }

    #[test]
    fn id_markings_and_unmapped_content_are_placed() {
        let out = render(TRACK, Unmapped::Include).unwrap();
        let fields = &out["updates"][0]["fields"];
        assert!(fields[0]["value"].is_string());
        assert_eq!(fields[1]["value"], r#"["class:restricted","rel:NATO"]"#);
        let unmapped = fields[2]["value"].as_str().unwrap();
        assert!(unmapped.contains("hostility"), "{unmapped}");
    }

    #[test]
    fn refuse_rejects_an_event_with_unplaced_content() {
        let template = TRACK.replace(
            r#",
                {"id": "ajar.unmapped", "value": "${unmapped|text}"}"#,
            "",
        );
        assert!(render(&template, Unmapped::Refuse).is_none());
    }

    #[test]
    fn template_without_the_event_id_is_refused() {
        let err = Template::parse(
            r#"{"tags":"${policy_tags}","u":"${unmapped}"}"#,
            Unmapped::Include,
        )
        .unwrap_err();
        assert!(err.to_string().contains("${id}"), "{err}");
    }

    #[test]
    fn template_without_unmapped_needs_refuse() {
        let template = r#"{"id":"${id}","tags":"${policy_tags}"}"#;
        assert!(Template::parse(template, Unmapped::Include).is_err());
        assert!(Template::parse(template, Unmapped::Refuse).is_ok());
    }

    const REQUIRED: &str = r#""id":"${id}","tags":"${policy_tags}","u":"${unmapped}""#;

    #[test]
    fn unknown_path_is_refused() {
        let template = format!(r#"{{{REQUIRED},"x":"${{latitude}}"}}"#);
        assert!(Template::parse(&template, Unmapped::Include).is_err());
    }

    #[test]
    fn unknown_filter_is_refused() {
        let template = format!(r#"{{{REQUIRED},"x":"${{lat|upper}}"}}"#);
        assert!(Template::parse(&template, Unmapped::Include).is_err());
    }

    #[test]
    fn text_without_a_placeholder_is_literal() {
        let out = render(
            r#"{"id":"${id}","t":"${policy_tags}","u":"${unmapped}","note":"cost is $5 {each}"}"#,
            Unmapped::Include,
        )
        .unwrap();
        assert_eq!(out["note"], "cost is $5 {each}");
    }
}
