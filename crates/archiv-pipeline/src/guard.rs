//! The fail-open guard (`docs/architecture/core/05` §3.1) [NORMATIVE].
//!
//! Every transform stage runs inside `guarded()`. Panics and errors bypass the
//! stage for that envelope: the stage's decisions are discarded and the
//! original payload continues to export. No log is ever lost because
//! governance failed.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::envelope::Envelope;

/// Stable stage identifier; also the label on bypass counters/aggregates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageId(pub &'static str);

/// Stage errors carry rule/module ids and reasons — never payload bytes
/// (docs/engineering/02 §7).
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    #[error("rule {rule_id} failed: {reason}")]
    Rule { rule_id: u32, reason: &'static str },
    #[error("stage internal error: {0}")]
    Internal(&'static str),
}

#[derive(Debug)]
pub enum BypassReason {
    Panic,
    Error(StageError),
}

#[derive(Debug)]
pub enum StageOutcome {
    Applied,
    Bypassed(BypassReason),
}

pub trait Stage {
    fn id(&self) -> StageId;
    fn apply(&self, env: &mut Envelope) -> Result<(), StageError>;
}

/// Wrap a stage invocation in the fail-open boundary.
///
/// Correctness rests on the zero-copy model: `raw` is never mutated in place
/// and decisions are additive spans, so bypass = discard this stage's spans
/// and continue. The caller increments `failopen_count` (labelled `stage`,
/// `reason`) on every `Bypassed` outcome.
pub fn guarded<T: Stage>(stage: &T, env: &mut Envelope) -> StageOutcome {
    let result = catch_unwind(AssertUnwindSafe(|| stage.apply(env)));
    match result {
        Ok(Ok(())) => StageOutcome::Applied,
        Ok(Err(e)) => {
            env.decisions.clear_stage(stage.id());
            StageOutcome::Bypassed(BypassReason::Error(e))
        }
        Err(_panic) => {
            env.decisions.clear_stage(stage.id());
            StageOutcome::Bypassed(BypassReason::Panic)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{MaskId, Redaction};
    use bytes::Bytes;

    struct PanicStage;
    impl Stage for PanicStage {
        fn id(&self) -> StageId {
            StageId("panic-test")
        }
        fn apply(&self, env: &mut Envelope) -> Result<(), StageError> {
            // Simulate a half-applied stage before the panic.
            env.decisions.push_redaction(
                self.id(),
                0,
                Redaction {
                    target: 0..2,
                    mask: MaskId(9),
                },
            );
            panic!("boom");
        }
    }

    struct FailingStage;
    impl Stage for FailingStage {
        fn id(&self) -> StageId {
            StageId("failing-test")
        }
        fn apply(&self, _env: &mut Envelope) -> Result<(), StageError> {
            Err(StageError::Rule {
                rule_id: 7,
                reason: "bad pattern",
            })
        }
    }

    struct OkStage;
    impl Stage for OkStage {
        fn id(&self) -> StageId {
            StageId("ok-test")
        }
        fn apply(&self, env: &mut Envelope) -> Result<(), StageError> {
            env.decisions.push_redaction(
                self.id(),
                0,
                Redaction {
                    target: 0..1,
                    mask: MaskId(1),
                },
            );
            Ok(())
        }
    }

    #[test]
    fn panic_is_contained_and_stage_decisions_discarded() {
        let payload = Bytes::from_static(b"original payload");
        let mut env = Envelope::new(payload.clone());

        // A previous healthy stage's decision must survive the bypass.
        let outcome_ok = guarded(&OkStage, &mut env);
        assert!(matches!(outcome_ok, StageOutcome::Applied));

        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // keep test output clean
        let outcome = guarded(&PanicStage, &mut env);
        std::panic::set_hook(prev_hook);

        assert!(matches!(
            outcome,
            StageOutcome::Bypassed(BypassReason::Panic)
        ));
        // The panicking stage's half-applied span is gone; OkStage's remains.
        assert_eq!(env.decisions.redactions_for(0).count(), 1);
        // Original payload untouched and exportable (Bytes refcount, not copy).
        assert_eq!(env.raw, payload);
    }

    #[test]
    fn error_bypasses_with_reason() {
        let mut env = Envelope::new(Bytes::from_static(b"payload"));
        let outcome = guarded(&FailingStage, &mut env);
        match outcome {
            StageOutcome::Bypassed(BypassReason::Error(StageError::Rule { rule_id, .. })) => {
                assert_eq!(rule_id, 7);
            }
            other => panic!("expected rule bypass, got {other:?}"),
        }
    }
}
