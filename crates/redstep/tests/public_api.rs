//! End-to-end tests of the authoring surface on an external crate path.
//!
//! These live here, not in a unit module, because a unit test resolves names
//! through the crate internals and a `pub` demoted to `pub(crate)` would still
//! compile; only an external path enforces `pub` (docs/rules/test.md). They
//! also exercise the full `#[security_test]` expansion, which references this
//! crate as `::redstep`.

use redstep::{Outcome, RunSummary, Scope, TestContext, run, security_test};

/// A tautology: should pass.
#[security_test]
async fn tautology_demo(ctx: &TestContext) -> redstep::Result<()> {
    ctx.check(true, "a tautology holds")?;
    Ok(())
}

/// A failed check: should map to Failed.
#[security_test]
async fn failing_demo(ctx: &TestContext) -> redstep::Result<()> {
    ctx.check(false, "deliberately false")?;
    Ok(())
}

/// A panic: should be caught and mapped to Errored, not abort the run.
#[security_test]
async fn panicking_demo(_ctx: &TestContext) -> redstep::Result<()> {
    panic!("deliberate panic in a demo test");
}

/// Resolving an out-of-scope target under the empty default scope errors before
/// acting; that error maps to Errored.
#[security_test]
async fn out_of_scope_demo(ctx: &TestContext) -> redstep::Result<()> {
    let _target = ctx.resolve("db:5432")?;
    Ok(())
}

/// Guard: every `#[security_test]` is discovered by the runner and its result
/// maps to the right outcome, including a panic caught without aborting the
/// run. Mutation: make the macro omit its `inventory::submit!` -> the demos are
/// absent from the summary -> the lookups panic -> fails.
#[test]
fn registered_tests_are_discovered_and_executed_with_mapped_outcomes() {
    let summary: RunSummary = run(Scope::default()).expect("the runtime starts");

    let outcome = |suffix: &str| -> &Outcome {
        &summary
            .runs
            .iter()
            .find(|r| r.name.ends_with(suffix))
            .unwrap_or_else(|| panic!("test {suffix} was not discovered"))
            .outcome
    };

    // Discovery and outcome mapping. Mutation: make the macro omit its
    // `inventory::submit!` -> the demos are absent -> the lookups panic. The
    // caught panic (panicking_demo) does not abort the run, so the later
    // tautology_demo still reports Passed.
    assert_eq!(*outcome("::tautology_demo"), Outcome::Passed);
    assert!(matches!(outcome("::failing_demo"), Outcome::Failed(_)));
    assert!(matches!(outcome("::panicking_demo"), Outcome::Errored(_)));
    assert!(matches!(
        outcome("::out_of_scope_demo"),
        Outcome::Errored(_)
    ));
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
