// SPDX-License-Identifier: Apache-2.0
//! Egress config: the shared egress fields, whose `target` is the URL events are posted to,
//! and the consumer's field mapping or body template and delivery settings.

use std::collections::BTreeMap;

use ajar_connector::Event;
use ajar_connector_common::oauth::OAuthClient;
use serde::Deserialize;
use serde_json::Value;

use crate::label::LabelConfig;
use crate::map::Unmapped;
use crate::template::Template;

pub type Config = ajar_connector_common::EgressConfig<GenericSettings>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericSettings {
    #[serde(default)]
    pub deliver: Deliver,
    #[serde(default)]
    pub mapping: Option<Mapping>,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub unmapped: Unmapped,
    #[serde(default)]
    pub confidentiality_label: Option<LabelConfig>,
    #[serde(default = "default_buffer_max")]
    pub buffer_max: usize,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Deliver {
    pub headers: BTreeMap<String, String>,
    /// Attempts per event before it is counted as dropped.
    pub attempts: u32,
    pub oauth: Option<OAuthClient>,
}

impl Default for Deliver {
    fn default() -> Self {
        Deliver {
            headers: BTreeMap::new(),
            attempts: 2,
            oauth: None,
        }
    }
}

/// How an event becomes the request body.
#[derive(Debug)]
pub enum Body {
    /// One flat object, consumer field name to event path.
    Fields(BTreeMap<String, String>),
    Template(Template),
}

impl Body {
    /// The body for one event, or `None` when `Unmapped::Refuse` rejects it.
    pub fn render(
        &self,
        event: &Event,
        unmapped: Unmapped,
        label: Option<&LabelConfig>,
    ) -> Option<Value> {
        match self {
            Body::Fields(fields) => crate::map::render(event, fields, unmapped, label),
            Body::Template(template) => template.render(event, unmapped),
        }
    }
}

/// Consumer field name to event path.
// Free-form: every key is a consumer field name, so unknown fields are allowed.
#[derive(Debug, Deserialize)]
pub struct Mapping {
    #[serde(flatten)]
    pub fields: BTreeMap<String, String>,
}

fn default_buffer_max() -> usize {
    1000
}

pub fn load(path: &str) -> anyhow::Result<(Config, Body)> {
    let cfg = Config::load(path)?;
    let body = validate(&cfg)?;
    Ok((cfg, body))
}

fn validate(cfg: &Config) -> anyhow::Result<Body> {
    let settings = &cfg.connector;
    if settings.deliver.attempts == 0 {
        anyhow::bail!("deliver.attempts must be at least 1");
    }
    if settings.deliver.oauth.is_some()
        && settings
            .deliver
            .headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("authorization"))
    {
        anyhow::bail!("deliver.oauth and an Authorization header are exclusive");
    }
    match (&settings.mapping, &settings.template) {
        (Some(_), Some(_)) => anyhow::bail!("[mapping] and template are exclusive"),
        (None, None) => anyhow::bail!("set [mapping] or template: nothing would be delivered"),
        (None, Some(_)) if settings.confidentiality_label.is_some() => {
            anyhow::bail!("[confidentiality_label] needs [mapping], not template")
        }
        (None, Some(text)) => Ok(Body::Template(Template::parse(text, settings.unmapped)?)),
        (Some(mapping), None) => {
            if mapping.fields.is_empty() {
                anyhow::bail!("[mapping] is empty: nothing would be delivered");
            }
            for path in mapping.fields.values() {
                crate::map::validate_path(path)?;
            }
            Ok(Body::Fields(mapping.fields.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(settings: &str) -> anyhow::Result<(Config, Body)> {
        let cfg = Config::parse(&format!(
            r#"
            nats_url = "nats://127.0.0.1:4222"
            egress_subject = "ajar.egress.signed.>"
            egress_verifying_key = "/instance/egress.pub"
            target = "http://127.0.0.1:9000/events"
            {settings}
            "#
        ))?;
        let body = validate(&cfg)?;
        Ok((cfg, body))
    }

    #[test]
    fn delivery_defaults_apply_without_a_deliver_table() {
        let (cfg, _) = cfg("[mapping]\ntrack_id = \"meta:source_uid\"").unwrap();
        assert_eq!(cfg.connector.deliver.attempts, 2);
        assert!(cfg.connector.deliver.headers.is_empty());
    }

    #[test]
    fn empty_mapping_is_refused() {
        let err = cfg("[mapping]").unwrap_err().to_string();
        assert!(err.contains("[mapping] is empty"), "{err}");
    }

    #[test]
    fn template_compiles_instead_of_a_mapping() {
        let (_, body) =
            cfg(r#"template = '{"id":"${id}","t":"${policy_tags}","u":"${unmapped}"}'"#).unwrap();
        assert!(matches!(body, Body::Template(_)));
    }

    #[test]
    fn mapping_and_template_together_are_refused() {
        let err = cfg("template = '{}'\n[mapping]\nid = \"id\"").unwrap_err();
        assert!(err.to_string().contains("exclusive"), "{err}");
    }

    #[test]
    fn label_with_a_template_is_refused() {
        let err =
            cfg("template = '{}'\n[confidentiality_label]\npolicy_identifier = \"P\"").unwrap_err();
        assert!(err.to_string().contains("needs [mapping]"), "{err}");
    }

    #[test]
    fn neither_mapping_nor_template_is_refused() {
        let err = cfg("").unwrap_err();
        assert!(
            err.to_string().contains("nothing would be delivered"),
            "{err}"
        );
    }

    #[test]
    fn oauth_with_an_authorization_header_is_refused() {
        let err = cfg(
            "[deliver.headers]\nauthorization = \"Bearer x\"\n[deliver.oauth]\n\
             token_url = \"t\"\nclient_id = \"c\"\nclient_secret_file = \"f\"\n\
             [mapping]\nid = \"id\"",
        )
        .unwrap_err();
        assert!(err.to_string().contains("exclusive"), "{err}");
    }

    #[test]
    fn unknown_deliver_key_is_refused() {
        let err = cfg("[deliver]\nurl = \"http://elsewhere\"\n[mapping]\nid = \"id\"").unwrap_err();
        assert!(format!("{err:#}").contains("url"), "{err:#}");
    }
}
