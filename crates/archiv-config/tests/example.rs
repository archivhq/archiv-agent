//! The shipped example config must always parse and validate — it is the
//! reference operators copy, and a drift between it and the loader is a bug.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

use archiv_config::AgentConfig;

const EXAMPLE: &str = include_str!("../../../config/agent.example.yaml");

#[test]
fn shipped_example_config_loads_and_validates() {
    let cfg = AgentConfig::from_yaml(EXAMPLE).expect("example config must load");
    assert_eq!(cfg.sampling.rules.len(), 4);
    assert_eq!(cfg.export.spool_max_bytes, 512 * 1024 * 1024);
    assert_eq!(cfg.limits.max_body_bytes, 4 * 1024 * 1024);

    let specs = cfg
        .into_redaction_rule_specs()
        .expect("redaction specs valid");
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].name, "email");
}
