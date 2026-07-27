//! Community YAML configuration loader (`docs/architecture/core/01` §3.5).
//!
//! Parses `/etc/archiv/agent.yaml` into typed structs and maps them to the
//! pipeline's domain types (`archiv_redact::RuleSpec`, sampling policy data).
//! Loading is **fail-fast**: unknown keys are rejected, out-of-range sampling
//! targets and invalid redaction field selectors abort startup — a
//! misconfigured agent must not start silently degraded.
//!
//! Every key is optional; an empty document (`{}`) yields a working
//! pass-through config (no sampling, no redaction). Evaluation engines consume
//! the parsed policy; this crate only loads and validates. The SIGHUP / file
//! watch reload trigger is wired in `main.rs` (receivers loop) — the loader is
//! pure so it is trivially testable and re-runnable on reload.

#![forbid(unsafe_code)]

use std::path::Path;

use archiv_redact::{FieldSelector, RuleSpec};
use serde::Deserialize;

/// Default OTLP ports and channel bound (`core/01` §3.2, CLAUDE.md §6).
const DEFAULT_GRPC_ENDPOINT: &str = "0.0.0.0:4317";
const DEFAULT_HTTP_ENDPOINT: &str = "0.0.0.0:4318";
const DEFAULT_CHANNEL_CAPACITY: usize = 8192;
/// 512 MiB spool cap (`core/05` §3.2).
const DEFAULT_SPOOL_MAX_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_SPOOL_DIR: &str = "/var/lib/archiv/spool";
/// 4 MiB request cap (`core/02` §3.4).
const DEFAULT_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing YAML config: {0}")]
    Parse(#[from] serde_norway::Error),
    #[error("sampling {which} target {target} out of range (0..=100)")]
    TargetOutOfRange { which: String, target: u16 },
    #[error("ingest.channel_capacity must be > 0")]
    ZeroChannelCapacity,
    #[error("limits.max_body_bytes must be > 0")]
    ZeroMaxBodyBytes,
    #[error("redaction rule `{rule}` has no field selectors")]
    EmptyFields { rule: String },
    #[error(
        "redaction rule `{rule}`: invalid field selector `{selector}` (expected `body` or `attributes.<glob>`)"
    )]
    InvalidFieldSelector { rule: String, selector: String },
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentConfig {
    pub ingest: IngestConfig,
    pub sampling: SamplingConfig,
    pub redaction: RedactionConfig,
    pub export: ExportConfig,
    pub limits: Limits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IngestConfig {
    pub grpc_endpoint: String,
    pub http_endpoint: String,
    pub channel_capacity: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            grpc_endpoint: DEFAULT_GRPC_ENDPOINT.to_string(),
            http_endpoint: DEFAULT_HTTP_ENDPOINT.to_string(),
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SamplingConfig {
    /// Percent kept when no rule matches; 100 = sampling disabled.
    pub default_target: u16,
    /// First match wins, evaluated top-down (`core/03` §3.3).
    pub rules: Vec<SamplingRule>,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            default_target: 100,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingRule {
    #[serde(rename = "match")]
    pub selector: SamplingMatch,
    pub target: u16,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SamplingMatch {
    /// k8s namespace glob (e.g. `payments`, `batch-*`).
    pub namespace: Option<String>,
    /// Keep-at-most severity (e.g. `DEBUG`).
    pub severity_lte: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RedactionConfig {
    pub regex_rules: Vec<RegexRuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegexRuleConfig {
    pub name: String,
    pub pattern: String,
    pub mask: String,
    /// e.g. `[body, "attributes.*"]` (`core/04` §3).
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExportConfig {
    /// Destination OTLP endpoint; `None` = validate-only (no forwarding).
    pub otlp_endpoint: Option<String>,
    pub spool_dir: String,
    pub spool_max_bytes: u64,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            spool_dir: DEFAULT_SPOOL_DIR.to_string(),
            spool_max_bytes: DEFAULT_SPOOL_MAX_BYTES,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

impl AgentConfig {
    /// Parse and validate from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, ConfigError> {
        let cfg: AgentConfig = serde_norway::from_str(yaml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Read, parse, and validate from a file path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml(&text)
    }

    /// Stable fingerprint of the **governance policy** (sampling + redaction) —
    /// the `policy_version` that tags 10 s aggregates (`core/06` §3.1). Hashes
    /// the parsed policy fields (order-sensitive, since rules are first-match),
    /// so it is independent of comments/formatting and identical across restarts
    /// for the same policy. Transport/limits fields are excluded (they do not
    /// change governance decisions).
    #[must_use]
    pub fn policy_fingerprint(&self) -> u64 {
        use xxhash_rust::xxh64::Xxh64;
        let mut h = Xxh64::new(0);
        h.update(&self.sampling.default_target.to_le_bytes());
        for r in &self.sampling.rules {
            h.update(r.selector.namespace.as_deref().unwrap_or("").as_bytes());
            h.update(&[0]);
            h.update(r.selector.severity_lte.as_deref().unwrap_or("").as_bytes());
            h.update(&[0]);
            h.update(&r.target.to_le_bytes());
        }
        h.update(&[0xFF]); // sampling / redaction section separator
        for r in &self.redaction.regex_rules {
            for field in [r.name.as_bytes(), r.pattern.as_bytes(), r.mask.as_bytes()] {
                h.update(field);
                h.update(&[0]);
            }
            for f in &r.fields {
                h.update(f.as_bytes());
                h.update(&[0]);
            }
            h.update(&[0xFE]); // rule terminator
        }
        h.digest()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.sampling.default_target > 100 {
            return Err(ConfigError::TargetOutOfRange {
                which: "default".to_string(),
                target: self.sampling.default_target,
            });
        }
        for (i, rule) in self.sampling.rules.iter().enumerate() {
            if rule.target > 100 {
                return Err(ConfigError::TargetOutOfRange {
                    which: format!("rules[{i}]"),
                    target: rule.target,
                });
            }
        }
        if self.ingest.channel_capacity == 0 {
            return Err(ConfigError::ZeroChannelCapacity);
        }
        if self.limits.max_body_bytes == 0 {
            return Err(ConfigError::ZeroMaxBodyBytes);
        }
        // Redaction selectors are validated eagerly so a typo fails startup,
        // not the first matching record at runtime.
        for rule in &self.redaction.regex_rules {
            rule.parse_selectors()?;
        }
        Ok(())
    }

    /// Consume the redaction config into `archiv-redact` specs. Rule strings
    /// are **moved** (no copy); startup wiring passes these to
    /// `RedactEngine::compile`, which fails fast on a bad pattern. Selectors
    /// were already validated at load by [`Self::validate`].
    pub fn into_redaction_rule_specs(self) -> Result<Vec<RuleSpec>, ConfigError> {
        self.redaction.into_rule_specs()
    }
}

impl RedactionConfig {
    /// Consume into specs, moving each rule's owned strings.
    pub fn into_rule_specs(self) -> Result<Vec<RuleSpec>, ConfigError> {
        self.regex_rules
            .into_iter()
            .map(RegexRuleConfig::into_rule_spec)
            .collect()
    }
}

impl RegexRuleConfig {
    /// Validate and parse field selectors without consuming the rule. Error
    /// messages carry the config rule id / selector text; those `String`
    /// clones are config metadata for a diagnostic, never payload bytes.
    fn parse_selectors(&self) -> Result<Vec<FieldSelector>, ConfigError> {
        if self.fields.is_empty() {
            let rule = self.name.clone(); // NOT-A-PAYLOAD: config rule id for a diagnostic
            return Err(ConfigError::EmptyFields { rule });
        }
        let mut out = Vec::with_capacity(self.fields.len());
        for f in &self.fields {
            let sel = FieldSelector::parse(f).ok_or_else(|| {
                let rule = self.name.clone(); // NOT-A-PAYLOAD: config rule id for a diagnostic
                let selector = f.clone(); // NOT-A-PAYLOAD: config selector text for a diagnostic
                ConfigError::InvalidFieldSelector { rule, selector }
            })?;
            out.push(sel);
        }
        Ok(out)
    }

    /// Consume into a `RuleSpec`, moving `name`/`pattern`/`mask` (no clone).
    fn into_rule_spec(self) -> Result<RuleSpec, ConfigError> {
        let fields = self.parse_selectors()?;
        let RegexRuleConfig {
            name,
            pattern,
            mask,
            ..
        } = self;
        Ok(RuleSpec {
            name,
            pattern,
            mask,
            fields,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
ingest:
  grpc_endpoint: "0.0.0.0:5317"
  http_endpoint: "0.0.0.0:5318"
  channel_capacity: 4096
sampling:
  default_target: 100
  rules:
    - match: { namespace: "payments" }
      target: 100
    - match: { severity_lte: "DEBUG" }
      target: 10
    - match: { namespace: "batch-*" }
      target: 25
redaction:
  regex_rules:
    - name: email
      pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
      mask: "[REDACTED:email]"
      fields: [body, "attributes.*"]
export:
  otlp_endpoint: "https://otlp.example.com:4318"
  spool_dir: "/data/spool"
  spool_max_bytes: 1073741824
limits:
  max_body_bytes: 8388608
"#;

    #[test]
    fn full_config_parses_with_all_fields() {
        let cfg = AgentConfig::from_yaml(FULL).unwrap();
        assert_eq!(cfg.ingest.grpc_endpoint, "0.0.0.0:5317");
        assert_eq!(cfg.ingest.channel_capacity, 4096);
        assert_eq!(cfg.sampling.rules.len(), 3);
        // First-match ordering preserved.
        assert_eq!(
            cfg.sampling.rules[0].selector.namespace.as_deref(),
            Some("payments")
        );
        assert_eq!(
            cfg.sampling.rules[1].selector.severity_lte.as_deref(),
            Some("DEBUG")
        );
        assert_eq!(cfg.sampling.rules[1].target, 10);
        assert_eq!(
            cfg.export.otlp_endpoint.as_deref(),
            Some("https://otlp.example.com:4318")
        );
        assert_eq!(cfg.export.spool_max_bytes, 1_073_741_824);
        assert_eq!(cfg.limits.max_body_bytes, 8_388_608);

        // Consuming map to redact specs (moves rule strings).
        let specs = cfg.into_redaction_rule_specs().unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "email");
        assert_eq!(specs[0].fields.len(), 2);
    }

    #[test]
    fn policy_fingerprint_is_stable_and_policy_sensitive() {
        let a = "sampling:\n  default_target: 25\nredaction:\n  regex_rules:\n    - { name: email, pattern: 'x@y', mask: '[E]', fields: [body] }\n";
        // Same policy, extra comment + different transport/limits → same fingerprint.
        let b = "# a comment\nsampling:\n  default_target: 25\nredaction:\n  regex_rules:\n    - { name: email, pattern: 'x@y', mask: '[E]', fields: [body] }\nlimits:\n  max_body_bytes: 999\n";
        // Different governance (target) → different fingerprint.
        let c = "sampling:\n  default_target: 50\nredaction:\n  regex_rules:\n    - { name: email, pattern: 'x@y', mask: '[E]', fields: [body] }\n";

        let fa = AgentConfig::from_yaml(a).unwrap().policy_fingerprint();
        let fb = AgentConfig::from_yaml(b).unwrap().policy_fingerprint();
        let fc = AgentConfig::from_yaml(c).unwrap().policy_fingerprint();

        assert_eq!(fa, fb, "comments/limits must not change the policy version");
        assert_ne!(
            fa, fc,
            "a different sampling target is a new policy version"
        );
    }

    #[test]
    fn empty_document_yields_working_defaults() {
        let cfg = AgentConfig::from_yaml("{}").unwrap();
        assert_eq!(cfg.ingest.grpc_endpoint, "0.0.0.0:4317");
        assert_eq!(cfg.ingest.http_endpoint, "0.0.0.0:4318");
        assert_eq!(cfg.ingest.channel_capacity, 8192);
        assert_eq!(cfg.sampling.default_target, 100);
        assert!(cfg.sampling.rules.is_empty());
        assert!(cfg.redaction.regex_rules.is_empty());
        assert_eq!(cfg.export.otlp_endpoint, None);
        assert_eq!(cfg.export.spool_max_bytes, 512 * 1024 * 1024);
        assert_eq!(cfg.limits.max_body_bytes, 4 * 1024 * 1024);
    }

    #[test]
    fn partial_section_keeps_sibling_defaults() {
        let cfg = AgentConfig::from_yaml("ingest:\n  channel_capacity: 100\n").unwrap();
        assert_eq!(cfg.ingest.channel_capacity, 100);
        // Missing endpoints fall back to defaults.
        assert_eq!(cfg.ingest.grpc_endpoint, "0.0.0.0:4317");
    }

    #[test]
    fn unknown_key_is_rejected() {
        let err = AgentConfig::from_yaml("ingest:\n  grcp_endpoint: x\n").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn out_of_range_target_is_rejected() {
        let yaml = "sampling:\n  rules:\n    - match: { namespace: x }\n      target: 150\n";
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(err, ConfigError::TargetOutOfRange { target: 150, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn default_target_over_100_is_rejected() {
        let err = AgentConfig::from_yaml("sampling:\n  default_target: 101\n").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::TargetOutOfRange { target: 101, .. }
        ));
    }

    #[test]
    fn zero_channel_capacity_is_rejected() {
        let err = AgentConfig::from_yaml("ingest:\n  channel_capacity: 0\n").unwrap_err();
        assert!(matches!(err, ConfigError::ZeroChannelCapacity));
    }

    #[test]
    fn invalid_field_selector_fails_startup() {
        let yaml = "redaction:\n  regex_rules:\n    - name: r\n      pattern: 'x'\n      mask: '[X]'\n      fields: [bodies]\n";
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidFieldSelector { ref selector, .. } if selector == "bodies"),
            "got {err:?}"
        );
    }

    #[test]
    fn empty_fields_list_is_rejected() {
        let yaml = "redaction:\n  regex_rules:\n    - name: r\n      pattern: 'x'\n      mask: '[X]'\n      fields: []\n";
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(err, ConfigError::EmptyFields { .. }),
            "got {err:?}"
        );
    }
}
