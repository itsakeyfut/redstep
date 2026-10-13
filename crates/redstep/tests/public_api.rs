//! End-to-end tests of the authoring surface on an external crate path.
//!
//! These live here, not in a unit module, because a unit test resolves names
//! through the crate internals and a `pub` demoted to `pub(crate)` would still
//! compile; only an external path enforces `pub` (docs/rules/test.md). They
//! also exercise the full `#[security_test]` expansion, which references this
//! crate as `::redstep`.

use redstep::{
    Confidence, Observation, RunSummary, Scope, TestContext, Verdict, run, security_test,
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
    assert!(
        value.get("schema_version").is_some(),
        "the contract is versioned"
    );
    assert!(value.get("results").is_some(), "the contract has results");
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
