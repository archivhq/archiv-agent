//! The pipeline orchestrator: the composition root that runs one OTLP payload
//! through the fixed stage order (`docs/architecture/core/01` §3.4):
//!
//! ```text
//! parse(view) → sample → redact → export(assemble)
//! ```
//!
//! Every transform runs inside the fail-open guard (`core/05` §3.1): if any
//! stage panics or errors, its decisions are discarded and the original
//! payload still leaves the node. Assembly failure likewise forwards the
//! original bytes untouched. **No log is lost because governance failed.**
//!
//! Sampling resolves each record's target from the config policy (namespace /
//! severity rules, first match wins — `core/03` §3.3), then applies the frozen
//! decision function. Records without a trace id use the fallback key.

use archiv_config::AgentConfig;
use archiv_export::{AssembledPayload, MaskTable, assemble};
use archiv_ingest::ParseStage;
use archiv_pipeline::{Envelope, SampleVerdict, StageOutcome, guarded};
use archiv_redact::{CompileLimits, RedactEngine, RedactStage};
use archiv_sampling::policy::{Rule, SamplingPolicy, severity_band_max};
use archiv_sampling::{keep, keep_untraced};
use bytes::Bytes;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("config: {0}")]
    Config(#[from] archiv_config::ConfigError),
    #[error("redaction compile: {0}")]
    Redact(#[from] archiv_redact::CompileError),
    #[error(
        "unknown severity `{name}` in a sampling rule (expected TRACE|DEBUG|INFO|WARN|ERROR|FATAL)"
    )]
    UnknownSeverity { name: String },
}

/// Per-request outcome counters — numbers only, never payload content.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub records_in: usize,
    pub kept: usize,
    pub dropped: usize,
    pub redactions: usize,
    pub bytes_in: usize,
    pub bytes_out: usize,
    /// Parse failed → payload forwarded verbatim (fail-open).
    pub parse_bypassed: bool,
    /// Redaction failed → no masks applied, payload forwarded (fail-open).
    pub redact_bypassed: bool,
    /// Assembly failed → original bytes forwarded (fail-open).
    pub assemble_bypassed: bool,
}

pub struct Processed {
    pub output: AssembledPayload,
    pub stats: Stats,
}

/// A compiled, ready-to-run pipeline. Build once per policy swap and share;
/// `process` is read-only and allocation-light on the payload path.
pub struct Pipeline {
    parse: ParseStage,
    redact: RedactStage,
    masks: MaskTable,
    /// Namespace / severity → target resolution (`core/03` §3.3).
    policy: SamplingPolicy,
    /// Request-size cap enforced by the ingest receivers.
    max_body_bytes: usize,
    /// Trips redaction off after repeated faults, keeping the pipeline exporting
    /// (`core/05` §3.2 row 2).
    redact_breaker: crate::breaker::CircuitBreaker,
}

impl Pipeline {
    /// Build the pipeline from a validated config, compiling the sampling
    /// policy and redaction rules (fails fast on a bad pattern or unknown
    /// severity name). Consumes the config, moving its owned strings.
    pub fn from_config(config: AgentConfig) -> Result<Self, BuildError> {
        let AgentConfig {
            sampling,
            redaction,
            limits,
            ..
        } = config;
        let max_body_bytes = limits.max_body_bytes;

        // Compile sampling rules: severity names → band-max numbers; targets
        // (validated 0..=100 at load) narrow to u8.
        let default_target = sampling.default_target as u8;
        let mut rules = Vec::with_capacity(sampling.rules.len());
        for r in sampling.rules {
            let severity_lte = match r.selector.severity_lte {
                Some(name) => {
                    Some(severity_band_max(&name).ok_or(BuildError::UnknownSeverity { name })?)
                }
                None => None,
            };
            rules.push(Rule {
                namespace_glob: r.selector.namespace,
                severity_lte,
                target: r.target as u8,
            });
        }
        let policy = SamplingPolicy::new(rules, default_target);

        let specs = redaction.into_rule_specs()?;
        let engine = RedactEngine::compile(specs, CompileLimits::default())?;
        let masks = MaskTable::new(engine.masks().map(str::to_string).collect::<Vec<_>>());

        Ok(Self {
            parse: ParseStage,
            redact: RedactStage::new(engine),
            masks,
            policy,
            max_body_bytes,
            redact_breaker: crate::breaker::CircuitBreaker::with_defaults(),
        })
    }

    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    pub fn default_target(&self) -> u8 {
        self.policy.default_target()
    }

    /// Run one OTLP `ExportLogsServiceRequest` buffer through every stage.
    /// Always returns exportable bytes — the fail-open guarantee.
    pub fn process(&self, raw: Bytes) -> Processed {
        let _span = tracing::info_span!("pipeline.process").entered();
        let bytes_in = raw.len();
        let mut stats = Stats {
            bytes_in,
            ..Stats::default()
        };

        let mut env = Envelope::new(raw);

        // 1. parse(view) — malformed payload bypasses (no views) and forwards.
        if let StageOutcome::Bypassed(_) = guarded(&self.parse, &mut env) {
            stats.parse_bypassed = true;
        }
        stats.records_in = env.records.len();

        // 2. sample — resolve each record's target from the policy, then decide.
        let verdicts: Vec<SampleVerdict> = env
            .records
            .iter()
            .map(|rec| self.sample_verdict(rec, &env.raw))
            .collect();
        for v in &verdicts {
            match v {
                SampleVerdict::Keep => stats.kept += 1,
                SampleVerdict::Drop => stats.dropped += 1,
            }
        }
        env.decisions.set_sampling(verdicts);

        // 3. redact — guarded, with a circuit breaker (`core/05` §3.2 row 2):
        // repeated faults trip redaction off (keep exporting, the fail-open
        // direction) until a cooldown, instead of re-running a faulty stage.
        let now = std::time::Instant::now();
        if self.redact_breaker.allow_at(now) {
            if let StageOutcome::Bypassed(reason) = guarded(&self.redact, &mut env) {
                stats.redact_bypassed = true;
                if self.redact_breaker.record_fault_at(now) {
                    tracing::warn!(
                        ?reason,
                        "redaction circuit breaker tripped — disabling redaction and \
                         exporting unredacted until cooldown (core/05 §3.2)"
                    );
                }
            }
        } else {
            // Breaker open: skip redaction entirely; unredacted data still exports.
            stats.redact_bypassed = true;
        }

        stats.redactions = env.decisions.redaction_total();

        // 4. export(assemble) — on any wire-walk error, forward original bytes.
        let output = match assemble(&env, &self.masks) {
            Ok(payload) => payload,
            Err(_) => {
                stats.assemble_bypassed = true;
                AssembledPayload::passthrough(env.raw.slice(..))
            }
        };
        stats.bytes_out = output.len();

        Processed { output, stats }
    }

    fn sample_verdict(&self, rec: &archiv_pipeline::RecordView, raw: &Bytes) -> SampleVerdict {
        // Resolve this record's target from the policy (namespace / severity),
        // then apply the frozen decision function.
        let target = self
            .policy
            .resolve(rec.namespace_bytes(raw), rec.severity_number);
        let keep_it = match rec.trace_id_bytes(raw) {
            Some(id) => keep(&id, target),
            None => {
                // No trace id → fallback key `xxh64(service.name ‖ 0 ‖ body)`
                // (`core/03` §3.2). `service.name` comes from the Resource
                // attribute; empty when absent (still deterministic).
                let body = raw.get(rec.body.start..rec.body.end).unwrap_or(&[]);
                let service = rec.service_name_bytes(raw).unwrap_or(&[]);
                keep_untraced(service, body, target)
            }
        };
        if keep_it {
            SampleVerdict::Keep
        } else {
            SampleVerdict::Drop
        }
    }
}
