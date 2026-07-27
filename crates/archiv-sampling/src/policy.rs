//! Sampling policy resolution (`docs/architecture/core/03` §3.3).
//!
//! Rules are evaluated top-down, **first match wins**; the first matching
//! rule's target applies, else `default_target`. A rule may constrain the k8s
//! `namespace` (glob) and/or the record `severity` (`severity_lte`); a rule
//! matches only when **every** condition it specifies matches. The resolved
//! target then feeds the frozen decision function ([`crate::keep`]).
//!
//! This module is pure data → target resolution. It holds no config
//! dependency: the agent maps `agent.yaml` into [`Rule`]s (converting severity
//! names via [`severity_band_max`]) and builds a [`SamplingPolicy`].

/// A compiled sampling rule. Both conditions are optional; a rule with neither
/// is an unconditional catch-all.
#[derive(Debug, Clone)]
pub struct Rule {
    /// k8s namespace glob (`*` wildcard), e.g. `batch-*`.
    pub namespace_glob: Option<String>,
    /// Inclusive upper `SeverityNumber` bound (band max, see
    /// [`severity_band_max`]); the rule matches records at or below it.
    pub severity_lte: Option<i32>,
    /// Percent kept if this rule wins; 0..=100.
    pub target: u8,
}

/// A compiled policy: ordered rules plus the fallback target.
#[derive(Debug, Clone)]
pub struct SamplingPolicy {
    rules: Vec<Rule>,
    default_target: u8,
}

impl SamplingPolicy {
    pub fn new(rules: Vec<Rule>, default_target: u8) -> Self {
        Self {
            rules,
            default_target,
        }
    }

    /// The sampling target for a record with the given namespace / severity —
    /// first matching rule wins, else the default (`core/03` §3.3).
    pub fn resolve(&self, namespace: Option<&[u8]>, severity: Option<i32>) -> u8 {
        for rule in &self.rules {
            if rule_matches(rule, namespace, severity) {
                return rule.target;
            }
        }
        self.default_target
    }

    pub fn default_target(&self) -> u8 {
        self.default_target
    }
}

fn rule_matches(rule: &Rule, namespace: Option<&[u8]>, severity: Option<i32>) -> bool {
    // A condition that is specified but whose field is absent on the record
    // means the rule does not apply (a namespace rule can't match a record
    // with no namespace).
    if let Some(glob) = &rule.namespace_glob {
        match namespace {
            Some(ns) if glob_matches(glob.as_bytes(), ns) => {}
            _ => return false,
        }
    }
    if let Some(threshold) = rule.severity_lte {
        match severity {
            Some(sev) if sev <= threshold => {}
            _ => return false,
        }
    }
    true
}

/// OTLP `SeverityNumber` name → the maximum number in its band, for
/// `severity_lte` comparisons (`core/03` §3.3). Case-insensitive. Bands per the
/// OTLP spec: TRACE 1-4, DEBUG 5-8, INFO 9-12, WARN 13-16, ERROR 17-20,
/// FATAL 21-24. `severity_lte: DEBUG` therefore matches TRACE and DEBUG
/// records (number ≤ 8).
pub fn severity_band_max(name: &str) -> Option<i32> {
    match name.to_ascii_uppercase().as_str() {
        "TRACE" => Some(4),
        "DEBUG" => Some(8),
        "INFO" => Some(12),
        "WARN" | "WARNING" => Some(16),
        "ERROR" => Some(20),
        "FATAL" => Some(24),
        _ => None,
    }
}

/// Minimal `*`-wildcard glob over namespace bytes (same semantics as the
/// redaction attribute-key matcher): `*` matches any run of bytes (incl.
/// empty); every other byte is a literal. No allocation.
fn glob_matches(pattern: &[u8], key: &[u8]) -> bool {
    let (mut p, mut k) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while k < key.len() {
        if p < pattern.len() && pattern[p] == key[k] {
            p += 1;
            k += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p + 1, k));
            p += 1;
        } else if let Some((sp, sk)) = star {
            p = sp;
            k = sk + 1;
            star = Some((sp, sk + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(ns: Option<&str>, sev: Option<i32>, target: u8) -> Rule {
        Rule {
            namespace_glob: ns.map(str::to_string),
            severity_lte: sev,
            target,
        }
    }

    #[test]
    fn first_match_wins_then_default() {
        // payments → 100 (never sample), debug (≤8) → 10, batch-* → 25.
        let policy = SamplingPolicy::new(
            vec![
                rule(Some("payments"), None, 100),
                rule(None, Some(8), 10),
                rule(Some("batch-*"), None, 25),
            ],
            50,
        );

        // payments matches rule 1 regardless of severity.
        assert_eq!(policy.resolve(Some(b"payments"), Some(9)), 100);
        // a DEBUG (5) record in some namespace hits the severity rule.
        assert_eq!(policy.resolve(Some(b"web"), Some(5)), 10);
        // batch-nightly matches the glob (rule 3) — but only if severity rule
        // (rule 2) didn't match first; INFO(9) > 8 so rule 2 is skipped.
        assert_eq!(policy.resolve(Some(b"batch-nightly"), Some(9)), 25);
        // nothing matches → default.
        assert_eq!(policy.resolve(Some(b"web"), Some(9)), 50);
        assert_eq!(policy.resolve(None, None), 50);
    }

    #[test]
    fn specified_condition_with_absent_field_does_not_match() {
        let policy = SamplingPolicy::new(vec![rule(Some("payments"), None, 100)], 25);
        // No namespace on the record → the namespace rule cannot apply.
        assert_eq!(policy.resolve(None, Some(9)), 25);
        // Severity rule needs a severity.
        let sev_policy = SamplingPolicy::new(vec![rule(None, Some(8), 10)], 25);
        assert_eq!(sev_policy.resolve(Some(b"x"), None), 25);
    }

    #[test]
    fn catch_all_rule_matches_everything() {
        let policy = SamplingPolicy::new(vec![rule(None, None, 5)], 100);
        assert_eq!(policy.resolve(None, None), 5);
        assert_eq!(policy.resolve(Some(b"any"), Some(20)), 5);
    }

    #[test]
    fn severity_bands() {
        assert_eq!(severity_band_max("DEBUG"), Some(8));
        assert_eq!(severity_band_max("debug"), Some(8));
        assert_eq!(severity_band_max("INFO"), Some(12));
        assert_eq!(severity_band_max("FATAL"), Some(24));
        assert_eq!(severity_band_max("nope"), None);
    }

    #[test]
    fn glob_semantics() {
        assert!(glob_matches(b"batch-*", b"batch-nightly"));
        assert!(glob_matches(b"*", b"anything"));
        assert!(!glob_matches(b"payments", b"payments-eu"));
        assert!(glob_matches(b"*-eu", b"payments-eu"));
    }
}
