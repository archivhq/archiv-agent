//! Static regex redaction engine (`docs/architecture/core/04` §3) — Open_source.
//!
//! One contract shared with the Enterprise WASM engine: emit `Redaction`
//! replacement spans (`core/02` §3.2). Payloads are never rewritten here;
//! the exporter performs vectored assembly. Masks carry type, not value —
//! redacted content is never reconstructable downstream.
//!
//! Engines are compiled **once per policy swap** (`compile`); the per-record
//! path (`Stage::apply`) is allocation-free apart from span bookkeeping and
//! operates on `&[u8]` via `regex::bytes` (`core/02` §3.5, §4).

#![forbid(unsafe_code)]

mod glob;
mod lint;

use std::sync::atomic::{AtomicU64, Ordering};

use archiv_pipeline::{Envelope, MaskId, Redaction, Stage, StageError, StageId};
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};

pub use lint::check_nested_repetition;

/// Stage id for this engine; also the bypass/aggregate label (`core/05` §3.2).
pub const STAGE_REDACT_REGEX: StageId = StageId("redact-regex");

/// Which payload fields a rule scans (`core/04` §3 rule shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldSelector {
    /// The record body.
    Body,
    /// Attribute values whose key matches this glob (`*` wildcard).
    Attrs(String),
}

impl FieldSelector {
    /// Parse the YAML form: `body` or `attributes.<glob>`.
    pub fn parse(s: &str) -> Option<Self> {
        if s == "body" {
            return Some(Self::Body);
        }
        s.strip_prefix("attributes.")
            .filter(|glob| !glob.is_empty())
            .map(|glob| Self::Attrs(glob.to_string()))
    }
}

/// One rule as configured (YAML `redaction.regex_rules[]`, `core/01` §3.5).
/// These are config strings shared via `Arc` at swap time — not payload data.
#[derive(Debug, Clone)]
pub struct RuleSpec {
    pub name: String,
    pub pattern: String,
    pub mask: String,
    pub fields: Vec<FieldSelector>,
}

/// Compile-time policy validation limits (`core/04` §3): expansion size cap
/// plus the nested-repetition lint. Rejecting at compile keeps catastrophic
/// patterns out of the hot path entirely.
#[derive(Debug, Clone, Copy)]
pub struct CompileLimits {
    /// `RegexBuilder::size_limit` — max compiled-program bytes per rule.
    pub size_limit: usize,
}

impl Default for CompileLimits {
    fn default() -> Self {
        // 1 MiB per compiled rule: generous for PII patterns, small enough to
        // protect the 50 MB agent RSS budget at 10+ rules.
        Self {
            size_limit: 1 << 20,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("rule `{rule}`: {detail} — unbounded nested repetition is banned (core/04 §3)")]
    NestedRepetition { rule: String, detail: &'static str },
    #[error("rule `{rule}`: regex rejected: {source}")]
    Regex {
        rule: String,
        #[source]
        source: regex::Error,
    },
    #[error(
        "rule `{rule}`: invalid field selector `{selector}` (expected `body` or `attributes.<glob>`)"
    )]
    Selector { rule: String, selector: String },
    #[error("rule `{rule}`: at least one field selector is required")]
    NoFields { rule: String },
}

#[derive(Debug)]
struct CompiledRule {
    name: String,
    regex: Regex,
    mask: MaskId,
    fields: Vec<FieldSelector>,
}

impl CompiledRule {
    fn applies_to_body(&self) -> bool {
        self.fields.contains(&FieldSelector::Body)
    }

    fn applies_to_attr(&self, key: &[u8]) -> bool {
        self.fields.iter().any(|f| match f {
            FieldSelector::Body => false,
            FieldSelector::Attrs(g) => glob::matches(g.as_bytes(), key),
        })
    }
}

/// A compiled rule set. Build once per policy swap, share via `Arc`
/// (`arc-swap` once `archiv-config` lands); evaluation is read-only.
#[derive(Debug)]
pub struct RedactEngine {
    /// Fast pre-filter: which rules match this field at all (`core/04` §3).
    prefilter: RegexSet,
    rules: Vec<CompiledRule>,
    /// Mask table indexed by `MaskId`; the exporter interleaves these bytes.
    masks: Vec<String>,
}

impl RedactEngine {
    /// Consumes the specs: rule strings are moved, never copied.
    pub fn compile(specs: Vec<RuleSpec>, limits: CompileLimits) -> Result<Self, CompileError> {
        // Validate and compile per rule first — per-rule errors pin to the
        // offending rule (`ui/03` §3.2 needs that) before the set build.
        let mut regexes = Vec::with_capacity(specs.len());
        for spec in &specs {
            if spec.fields.is_empty() {
                return Err(CompileError::NoFields {
                    rule: spec.name.to_string(),
                });
            }
            if let Err(detail) = lint::check_nested_repetition(&spec.pattern) {
                return Err(CompileError::NestedRepetition {
                    rule: spec.name.to_string(),
                    detail,
                });
            }
            let regex = RegexBuilder::new(&spec.pattern)
                .size_limit(limits.size_limit)
                .build()
                .map_err(|source| CompileError::Regex {
                    rule: spec.name.to_string(),
                    source,
                })?;
            regexes.push(regex);
        }

        let prefilter = RegexSetBuilder::new(specs.iter().map(|s| s.pattern.as_str()))
            .size_limit(limits.size_limit.saturating_mul(specs.len().max(1)))
            .build()
            .map_err(|source| CompileError::Regex {
                rule: "<set>".to_string(),
                source,
            })?;

        let mut rules = Vec::with_capacity(specs.len());
        let mut masks: Vec<String> = Vec::new();
        for (spec, regex) in specs.into_iter().zip(regexes) {
            let mask = match masks.iter().position(|m| *m == spec.mask) {
                Some(i) => MaskId(i as u32),
                None => {
                    masks.push(spec.mask);
                    MaskId((masks.len() - 1) as u32)
                }
            };
            rules.push(CompiledRule {
                name: spec.name,
                regex,
                mask,
                fields: spec.fields,
            });
        }

        Ok(Self {
            prefilter,
            rules,
            masks,
        })
    }

    /// Mask bytes for a span — consumed by the exporter's vectored assembly.
    pub fn mask_bytes(&self, id: MaskId) -> Option<&[u8]> {
        self.masks.get(id.0 as usize).map(|s| s.as_bytes())
    }

    pub fn rule_names(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|r| r.name.as_str())
    }

    /// All masks in `MaskId` order — feeds the exporter's mask table at
    /// policy-swap time.
    pub fn masks(&self) -> impl Iterator<Item = &str> {
        self.masks.iter().map(String::as_str)
    }
}

/// The pipeline stage. Wrap invocations in `archiv_pipeline::guarded` —
/// a faulty rule bypasses redaction for that record, never loses data
/// (`core/05` §3.1).
#[derive(Debug)]
pub struct RedactStage {
    engine: RedactEngine,
    /// Per-rule match counters (`redaction_count` per rule id, `core/04` §5);
    /// flushed by `archiv-metrics` in a later loop. Relaxed atomics: counters,
    /// not synchronization.
    counts: Vec<AtomicU64>,
}

impl RedactStage {
    pub fn new(engine: RedactEngine) -> Self {
        let counts = engine.rules.iter().map(|_| AtomicU64::new(0)).collect();
        Self { engine, counts }
    }

    pub fn engine(&self) -> &RedactEngine {
        &self.engine
    }

    /// Snapshot of per-rule match counts, in rule order.
    pub fn counts(&self) -> impl Iterator<Item = (&str, u64)> {
        self.engine
            .rules
            .iter()
            .zip(&self.counts)
            .map(|(r, c)| (r.name.as_str(), c.load(Ordering::Relaxed)))
    }

    fn redact_field(
        &self,
        field: &[u8],
        base: usize,
        record: usize,
        key: Option<&[u8]>,
        decisions: &mut archiv_pipeline::Decisions,
    ) {
        if field.is_empty() {
            return;
        }
        for rule_idx in self.engine.prefilter.matches(field) {
            let rule = &self.engine.rules[rule_idx];
            let applies = match key {
                None => rule.applies_to_body(),
                Some(k) => rule.applies_to_attr(k),
            };
            if !applies {
                continue;
            }
            for m in rule.regex.find_iter(field) {
                decisions.push_redaction(
                    STAGE_REDACT_REGEX,
                    record,
                    Redaction {
                        target: base + m.start()..base + m.end(),
                        mask: rule.mask,
                    },
                );
                self.counts[rule_idx].fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Stage for RedactStage {
    fn id(&self) -> StageId {
        STAGE_REDACT_REGEX
    }

    fn apply(&self, env: &mut Envelope) -> Result<(), StageError> {
        let Envelope {
            raw,
            records,
            decisions,
            ..
        } = env;
        for (idx, rec) in records.iter().enumerate() {
            if let Some(body) = raw.get(rec.body.start..rec.body.end) {
                self.redact_field(body, rec.body.start, idx, None, decisions);
            }
            for attr in &rec.attrs {
                let Some(key) = raw.get(attr.key.start..attr.key.end) else {
                    continue;
                };
                let Some(val) = raw.get(attr.value.start..attr.value.end) else {
                    continue;
                };
                self.redact_field(val, attr.value.start, idx, Some(key), decisions);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email_rule() -> RuleSpec {
        RuleSpec {
            name: "email".to_string(),
            // The doc's canonical example pattern (core/04 §3).
            pattern: r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}".to_string(),
            mask: "[REDACTED:email]".to_string(),
            fields: vec![
                FieldSelector::Body,
                FieldSelector::Attrs("user.*".to_string()),
            ],
        }
    }

    #[test]
    fn compile_accepts_canonical_rules_and_dedups_masks() {
        let second = RuleSpec {
            name: "email-attrs".to_string(),
            pattern: r"@[A-Za-z0-9.-]+".to_string(),
            mask: "[REDACTED:email]".to_string(),
            fields: vec![FieldSelector::Attrs("*".to_string())],
        };
        let engine =
            RedactEngine::compile(vec![email_rule(), second], CompileLimits::default()).unwrap();
        assert_eq!(engine.masks.len(), 1, "identical masks share one MaskId");
        assert_eq!(
            engine.mask_bytes(MaskId(0)),
            Some(b"[REDACTED:email]".as_slice())
        );
    }

    #[test]
    fn nested_repetition_is_rejected_at_compile() {
        for pattern in [r"(a+)+", r"([a-z]*)*", r"(?:\d+){3,}", r"((ab)+c)*"] {
            let spec = RuleSpec {
                name: "bad".to_string(),
                pattern: pattern.to_string(),
                mask: "[X]".to_string(),
                fields: vec![FieldSelector::Body],
            };
            let err = RedactEngine::compile(vec![spec], CompileLimits::default()).unwrap_err();
            assert!(
                matches!(err, CompileError::NestedRepetition { .. }),
                "{pattern} should be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn oversized_pattern_is_rejected_by_size_limit() {
        let spec = RuleSpec {
            name: "huge".to_string(),
            pattern: r"(?:abcdefghij){1,1000}".to_string(),
            mask: "[X]".to_string(),
            fields: vec![FieldSelector::Body],
        };
        let err = RedactEngine::compile(vec![spec], CompileLimits { size_limit: 256 }).unwrap_err();
        assert!(matches!(err, CompileError::Regex { .. }), "got: {err}");
    }

    #[test]
    fn field_selector_parsing() {
        assert_eq!(FieldSelector::parse("body"), Some(FieldSelector::Body));
        assert_eq!(
            FieldSelector::parse("attributes.*"),
            Some(FieldSelector::Attrs("*".to_string()))
        );
        assert_eq!(
            FieldSelector::parse("attributes.user.email"),
            Some(FieldSelector::Attrs("user.email".to_string()))
        );
        assert_eq!(FieldSelector::parse("attributes."), None);
        assert_eq!(FieldSelector::parse("bodies"), None);
    }
}
