//! End-to-end tests of the authoring surface on an external crate path.
//!
//! These live here, not in a unit module, because a unit test resolves names
//! through the crate internals and a `pub` demoted to `pub(crate)` would still
//! compile; only an external path enforces `pub` (docs/rules/test.md). They
//! also exercise the full `#[security_test]` expansion, which references this
//! crate as `::redstep`.

use redstep::{
    Capability, Confidence, EvidenceDraft, Intensity, Observation, Reproduction, RunSummary, Scope,
    TestContext, Verdict, run, security_test,
};

/// A tautology: should pass.
#[security_test]
async fn tautology_demo(ctx: &TestContext) -> redstep::Result<()> {
    ctx.check(true, "a tautology holds")?;
    Ok(())
}

/// A failed check: should verdict Fail.
#[security_test]
async fn failing_demo(ctx: &TestContext) -> redstep::Result<()> {
    ctx.check(false, "deliberately false")?;
    Ok(())
}

/// A panic: should be caught and verdict Error, not abort the run.
#[security_test]
async fn panicking_demo(_ctx: &TestContext) -> redstep::Result<()> {
    panic!("deliberate panic in a demo test");
}

/// Resolving an out-of-scope target errors before a target is produced; that
/// error verdicts Error.
#[security_test]
async fn out_of_scope_demo(ctx: &TestContext) -> redstep::Result<()> {
    let _target = ctx.resolve("db:5432")?;
    Ok(())
}

/// Resolving an in-scope target succeeds when the run's scope allows it. Used
/// to prove the runner hands its scope to the test.
#[security_test]
async fn in_scope_resolve_demo(ctx: &TestContext) -> redstep::Result<()> {
    let target = ctx.resolve("web:80")?;
    ctx.check(target.port() == 80, "resolved the allowed port")?;
    Ok(())
}

/// An expectation an observation violates: the expect path verdicts Fail and
/// the body still returns Ok, so the verdict comes from the recorded judgement.
#[security_test]
async fn expect_fail_demo(ctx: &TestContext) -> redstep::Result<()> {
    let observed = Observation {
        value: true,
        confidence: Confidence::High,
    };
    ctx.expect(&observed).to_be(false);
    Ok(())
}

/// An observation too weak for the required confidence: the expect path
/// verdicts Inconclusive, which must surface as the run verdict.
#[security_test]
async fn expect_inconclusive_demo(ctx: &TestContext) -> redstep::Result<()> {
    let observed = Observation {
        value: false,
        confidence: Confidence::Low,
    };
    ctx.expect(&observed)
        .min_confidence(Confidence::High)
        .to_be(false);
    Ok(())
}

/// A High observation that matches the expectation verdicts Pass through the
/// expect path end to end.
#[security_test]
async fn expect_pass_demo(ctx: &TestContext) -> redstep::Result<()> {
    let observed = Observation {
        value: false,
        confidence: Confidence::High,
    };
    ctx.expect(&observed).to_be(false);
    Ok(())
}

/// A Low observation with no explicit minimum: the default gate requires High,
/// so this is Inconclusive, not a confident Pass. This is the fail-closed
/// default that keeps a timeout (Low) from reading as "the boundary held".
#[security_test]
async fn default_gate_demo(ctx: &TestContext) -> redstep::Result<()> {
    let observed = Observation {
        value: false,
        confidence: Confidence::Low,
    };
    ctx.expect(&observed).to_be(false);
    Ok(())
}

/// A test that asserts nothing: Inconclusive, not Pass. Nothing was proven.
#[security_test]
async fn no_assertion_demo(_ctx: &TestContext) -> redstep::Result<()> {
    Ok(())
}

/// A Safe capability an external crate implements against the public trait,
/// observing a reachable target with no socket. Proves the evidence shape
/// (`EvidenceDraft`, `Reproduction`) is publicly constructible, and gives
/// `run_collects_evidence_into_the_store` deterministic records to find. The
/// target is a field so one test can run it twice with distinct records.
struct StubReachable {
    target: &'static str,
}

impl Capability for StubReachable {
    type Value = bool;

    fn name(&self) -> &'static str {
        "stub_reachable"
    }

    fn intensity(&self) -> Intensity {
        Intensity::Safe
    }

    async fn execute(&self) -> redstep::Result<(Observation<bool>, EvidenceDraft)> {
        Ok((
            Observation {
                value: true,
                confidence: Confidence::High,
            },
            EvidenceDraft {
                capability: self.name(),
                target: self.target.to_owned(),
                intensity: Intensity::Safe,
                observed: serde_json::Value::Bool(true),
                confidence: Confidence::High,
                summary: "reachable".to_owned(),
                reproduction: Reproduction {
                    capability: self.name().to_owned(),
                    target: self.target.to_owned(),
                    params: serde_json::json!({}),
                },
            },
        ))
    }
}

/// Runs a Safe capability twice, so the run produces two evidence records the
/// store collects in order.
#[security_test]
async fn records_evidence_demo(ctx: &TestContext) -> redstep::Result<()> {
    let first = ctx
        .run(StubReachable {
            target: "stub:alpha",
        })
        .await?;
    let second = ctx
        .run(StubReachable {
            target: "stub:beta",
        })
        .await?;
    ctx.expect(&first).to_be(true);
    ctx.expect(&second).to_be(true);
    Ok(())
}

/// A second evidence producer whose name sorts before `records_evidence_demo`,
/// so it runs first and takes evidence id 0. That makes `records_evidence_demo`'s
/// records start at a non-zero id, which is what lets a test tell the runner's
/// per-test `base` offset from a bare index (issue #14): with no prior producer
/// `base` is always 0 and dropping it changes nothing.
#[security_test]
async fn aaa_earlier_evidence_demo(ctx: &TestContext) -> redstep::Result<()> {
    let recorded = ctx
        .run(StubReachable {
            target: "stub:earlier",
        })
        .await?;
    ctx.expect(&recorded).to_be(true);
    Ok(())
}

/// The verdict of the discovered test whose name ends with `suffix`.
fn verdict_of(summary: &RunSummary, suffix: &str) -> Verdict {
    summary
        .runs
        .iter()
        .find(|r| r.name.ends_with(suffix))
        .unwrap_or_else(|| panic!("test {suffix} was not discovered"))
        .verdict
}

/// Guard: every `#[security_test]` is discovered and its verdict is right,
/// including a caught panic (Error) and the three-valued expect path (Fail and
/// Inconclusive surface as run verdicts). Mutation: make the macro omit its
/// `inventory::submit!` -> the demos are absent -> the lookups panic. The caught
/// panic does not abort the run, so the later tautology_demo still verdicts
/// Pass.
#[test]
fn registered_tests_are_discovered_and_executed_with_mapped_verdicts() {
    let summary: RunSummary = run(Scope::default()).expect("the runtime starts");

    assert_eq!(verdict_of(&summary, "::tautology_demo"), Verdict::Pass);
    assert_eq!(verdict_of(&summary, "::failing_demo"), Verdict::Fail);
    assert_eq!(verdict_of(&summary, "::panicking_demo"), Verdict::Error);
    assert_eq!(verdict_of(&summary, "::out_of_scope_demo"), Verdict::Error);
    assert_eq!(verdict_of(&summary, "::expect_fail_demo"), Verdict::Fail);
    assert_eq!(verdict_of(&summary, "::expect_pass_demo"), Verdict::Pass);
    assert_eq!(
        verdict_of(&summary, "::expect_inconclusive_demo"),
        Verdict::Inconclusive
    );
    assert_eq!(
        verdict_of(&summary, "::default_gate_demo"),
        Verdict::Inconclusive,
        "a Low observation with no explicit minimum is Inconclusive, not a confident Pass"
    );
    assert_eq!(
        verdict_of(&summary, "::no_assertion_demo"),
        Verdict::Inconclusive,
        "a test that asserts nothing proved nothing"
    );

    // The judgement reason survives into the summary (not dropped). Mutation:
    // build TestRun with `judgements: Vec::new()` -> this find fails.
    let expect_fail = summary
        .runs
        .iter()
        .find(|r| r.name.ends_with("::expect_fail_demo"))
        .expect("discovered");
    let judgement = expect_fail
        .judgements
        .first()
        .expect("expect_fail_demo recorded a judgement");
    assert_eq!(judgement.expected, "false");
    assert_eq!(judgement.actual, "true");
}

/// Guard: `run` hands its scope to the tests. Mutation: make `run` discard the
/// caller's scope and use `Scope::default()` -> in_scope_resolve_demo can no
/// longer resolve `web:80`, so it errors instead of passing -> fails. The
/// deny direction is asserted alongside: an out-of-scope target stays rejected
/// under the same scope.
#[test]
fn run_passes_the_scope_to_tests() {
    let scope = Scope::builder().allow("web:80").expect("valid").build();
    let summary = run(scope).expect("the runtime starts");

    assert_eq!(
        verdict_of(&summary, "::in_scope_resolve_demo"),
        Verdict::Pass
    );
    assert_eq!(verdict_of(&summary, "::out_of_scope_demo"), Verdict::Error);
}

/// Guard: a run collects every capability execution's evidence into the summary's
/// store, in execution order, with run-scoped sequential ids and a real clock
/// timestamp (Decision D). Two demos produce evidence: `aaa_earlier_evidence_demo`
/// (sorts first) once, then `records_evidence_demo` twice, so the store holds
/// `earlier`, `alpha`, `beta` at ids 0, 1, 2.
/// Mutations caught: drop the collection loop in `run` -> store empty -> the
/// length assert fails; `.rev()` or `.take(1)` the drain -> the order or the
/// count fails; `append(draft, 0)` instead of `now_ms()`, or `now_ms` returning a
/// constant or seconds -> the timestamp assert fails.
#[test]
fn run_collects_evidence_into_the_store() {
    let summary = run(Scope::default()).expect("the runtime starts");

    let records: Vec<_> = summary
        .evidence
        .records()
        .iter()
        .filter(|e| e.capability == "stub_reachable")
        .collect();

    let targets: Vec<&str> = records.iter().map(|e| e.target.as_str()).collect();
    assert_eq!(
        targets,
        ["stub:earlier", "stub:alpha", "stub:beta"],
        "all three executions collected in execution order"
    );
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record.id, redstep::EvidenceId(index as u64));
    }
    assert_eq!(records[0].observed, serde_json::Value::Bool(true));
    // The runner stamps a real wall clock, not a constant or seconds: this is
    // well past 2020-09 in epoch milliseconds (and far above any seconds value).
    assert!(
        records[0].recorded_at_ms > 1_600_000_000_000,
        "recorded_at_ms must be real epoch milliseconds, got {}",
        records[0].recorded_at_ms
    );
}

/// Guard: a judgement from `expect` over a capability's result resolves, through
/// its `evidence` id, to the record that capability produced, in order and in the
/// right test; a `check` judgement carries no id (issue #14).
/// `aaa_earlier_evidence_demo` runs first and takes id 0, so `records_evidence_demo`'s
/// records start at id 1: its judgements must resolve to ids 1 and 2
/// (`stub:alpha`, `stub:beta`), not 0 and 1. That makes the runner's per-test
/// `base` offset load-bearing.
/// Mutations caught: drop `base` in the remap (`EvidenceId(index)`) -> the second
/// demo's first judgement resolves to id 0 (`stub:earlier`, another test's
/// record) -> the `stub:alpha` assert fails; an index off-by-one or reversal ->
/// the wrong target -> fails; make `Recorded` carry no reference, or `check` carry
/// one -> the counts or the `check` assert fail.
#[test]
fn run_links_judgements_to_their_evidence() {
    let summary = run(Scope::default()).expect("the runtime starts");

    let resolve = |id: redstep::EvidenceId| {
        summary
            .evidence
            .records()
            .iter()
            .find(|e| e.id == id)
            .unwrap_or_else(|| panic!("evidence id {id:?} does not resolve"))
    };
    let links = |suffix: &str| -> Vec<redstep::EvidenceId> {
        summary
            .runs
            .iter()
            .find(|r| r.name.ends_with(suffix))
            .unwrap_or_else(|| panic!("test {suffix} was not discovered"))
            .judgements
            .iter()
            .filter_map(|j| j.evidence)
            .collect()
    };

    // The earlier producer's judgement links to its own record (id 0).
    let earlier = links("::aaa_earlier_evidence_demo");
    assert_eq!(earlier.len(), 1);
    assert_eq!(resolve(earlier[0]).target, "stub:earlier");

    // The later producer's two judgements link to its own records, at a non-zero
    // base (ids 1 and 2), not to the earlier test's record.
    let later = links("::records_evidence_demo");
    assert_eq!(later.len(), 2, "both judgements link to their evidence");
    assert!(
        later[0] != redstep::EvidenceId(0),
        "the later test's link must carry the per-test base, not start at 0"
    );
    assert_eq!(resolve(later[0]).target, "stub:alpha");
    assert_eq!(resolve(later[1]).target, "stub:beta");

    // A check links to nothing.
    assert!(
        links("::tautology_demo").is_empty(),
        "a check judgement links to no evidence"
    );
}

/// Guard: the CLI maps a usage error to exit 2. Mutation: change main's
/// usage-error `ExitCode::from(2)`, or drop the unknown-argument arm of
/// `parse_args` -> the process exits 0 -> fails.
#[test]
fn cli_rejects_unknown_argument_with_exit_2() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_redstep"))
        .arg("--bogus")
        .status()
        .expect("spawn the redstep binary");
    assert_eq!(status.code(), Some(2));
}

/// Guard: the shipped binary links no `#[security_test]`, so every invocation
/// discovers nothing, and a run that discovered nothing must not exit 0
/// (CLAUDE.md row 6). Mutation: let `exit_code` pass an empty run, or make main
/// return `ExitCode::SUCCESS` regardless of the report -> the process exits 0
/// -> fails. This ties the process exit to the report's `exit_code`.
#[test]
fn cli_empty_run_does_not_exit_zero() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_redstep"))
        .args(["--allow", "web:80"])
        .status()
        .expect("spawn the redstep binary");
    assert_ne!(status.code(), Some(0));
}

/// Guard: `--json <path>` writes the canonical JSON, and it parses with the
/// contract's keys. The shipped binary links no test, so the findings are empty,
/// but the document and its keys are still present. Mutation: drop the
/// `--json` arm of `parse_args`, or the `fs::write` in main -> the file is absent
/// -> fails.
#[test]
fn cli_json_flag_writes_the_canonical_json() {
    let path = std::env::temp_dir().join(format!("redstep-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_redstep"))
        .args(["--json".as_ref(), path.as_os_str()])
        .status()
        .expect("spawn the redstep binary");
    assert!(!status.success(), "an empty run is still non-zero");

    let written = std::fs::read_to_string(&path).expect("the JSON was written");
    let value: serde_json::Value = serde_json::from_str(&written).expect("valid JSON");
    assert!(value.get("findings").is_some(), "the contract has findings");
    assert!(value.get("evidence").is_some(), "the contract has evidence");
    assert!(
        value.get("exit_code").is_some(),
        "the contract has exit_code"
    );
    let _ = std::fs::remove_file(&path);
}

/// Guard: the public items are reachable on an external crate path. Mutation:
/// demote any of these to `pub(crate)` -> this test crate fails to compile.
#[test]
fn public_api_items_are_reachable() {
    fn takes_run(_: fn(Scope) -> Result<RunSummary, redstep::RunError>) {}
    takes_run(run);

    let scope = redstep::Scope::builder()
        .allow("web:80")
        .expect("valid spec")
        .build();
    let ctx = redstep::TestContext::new(scope);
    let target = ctx.resolve("web:80").expect("web:80 is allowed");
    let _: &str = target.host();
}
