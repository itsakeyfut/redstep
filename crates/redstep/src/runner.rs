//! Discovering and executing the registered security tests.
//!
//! Two entry points run the same registered tests. [`run`] runs them
//! host-in-process over a [`Scope`], building its own current-thread runtime.
//! [`run_in_lab`] (with [`run_in_running_lab`], #28) stands a lab up, gates on
//! the boundary self-check, and runs the tests from the attacker's vantage on the
//! caller's runtime. Both go through [`finalize_test`], so the verdict and the
//! evidence-id resolution cannot diverge between the paths.
//!
//! Execution is sequential, in name order, one test at a time: deterministic and
//! safe against a shared lab target. Each test runs inside a `catch_unwind`
//! (`std::panic::catch_unwind` around `block_on` on the host path, the async
//! [`FutureExt::catch_unwind`](futures_util::FutureExt) on the lab path), so one
//! test's panic cannot abort the run and is never read as a pass. Each test gets
//! its own `TestContext`, so the judgements it records are its own.

use crate::TestContext;
use crate::environment::Environment;
use crate::error::Error;
use crate::evidence::{EvidenceId, EvidenceStore};
use crate::expectation::Judgement;
use crate::orchestrator::{RunningLab, boundary_self_check, bring_up};
use crate::registry;
use crate::scope::Scope;
use crate::verdict::Verdict;
use bollard::Docker;
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;

/// One test's name, its verdict, and why: the judgements its expectations
/// produced, and a message when it failed a bare check or could not run.
#[derive(Debug)]
pub struct TestRun {
    /// The fully-qualified test name.
    pub name: &'static str,
    /// The test's verdict.
    pub verdict: Verdict,
    /// The judgements recorded by `expect`, in the order declared.
    pub judgements: Vec<Judgement>,
    /// A message for a bare `check` failure, an error, or a panic.
    pub error: Option<String>,
}

/// The result of running every discovered test.
#[derive(Debug)]
pub struct RunSummary {
    /// One entry per test, in the order they ran (sorted by name).
    pub runs: Vec<TestRun>,
    /// Every evidence record produced during the run, in execution order: the
    /// single source of truth the reports and the canonical JSON project from
    /// (ADR-0004, ADR-0005).
    pub evidence: EvidenceStore,
}

impl RunSummary {
    /// `0` only when at least one test ran and every verdict is `Pass`;
    /// non-zero otherwise.
    ///
    /// `Fail`, `Error`, and `Inconclusive` are all non-zero. Inconclusive is
    /// non-zero on purpose: an unconfirmed result must not read as a green gate
    /// (CLAUDE.md row 6). An empty run is not a pass either: "nothing was
    /// discovered" must not read as "all clear" (a vacuous `all()` over no runs
    /// would return `0`), and the shipped binary links no tests.
    pub fn exit_code(&self) -> i32 {
        if !self.runs.is_empty() && self.runs.iter().all(|r| r.verdict == Verdict::Pass) {
            0
        } else {
            1
        }
    }
}

/// A fatal error that stops the whole run before any test verdict exists.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RunError {
    /// The async runtime could not be started.
    #[error("failed to start the async runtime: {0}")]
    Runtime(#[source] std::io::Error),
    /// The lab could not be stood up, or its declared boundaries were not
    /// actually blocked (the boundary self-check refused the run): the run never
    /// reached a verdict. A refused run returns this, never a [`RunSummary`], so a
    /// broken lab cannot report PASS (ADR-0011 step 4).
    #[error("the run could not proceed against the lab: {0}")]
    Lab(#[source] crate::Error),
}

/// Discover every registered test and run it, each against its own context over
/// a clone of `scope`. The evidence each test produced is collected into one
/// run-level [`EvidenceStore`], in test-then-execution order; the store assigns
/// the ids and stamps the timestamps from this runner's clock (ADR-0004).
pub fn run(scope: Scope) -> std::result::Result<RunSummary, RunError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(RunError::Runtime)?;

    let tests = ordered(registry::all().collect());

    let mut runs = Vec::with_capacity(tests.len());
    let mut evidence = EvidenceStore::new();
    for test in tests {
        let ctx = TestContext::new(scope.clone());
        // AssertUnwindSafe is sound here: `ctx`'s sinks are only ever touched by
        // `record`/`take_judgements` and the draft push/`take_evidence_drafts`,
        // which borrow, mutate and drop within one statement and never across an
        // `.await`, so an unwind cannot leave a `RefCell` borrowed or
        // half-written.
        let result =
            std::panic::catch_unwind(AssertUnwindSafe(|| runtime.block_on((test.run)(&ctx))));
        runs.push(finalize_test(test.name, result, &ctx, &mut evidence));
    }

    Ok(RunSummary { runs, evidence })
}

/// Stand the lab up, run the registered tests from the attacker's vantage, and
/// tear it down, returning the run summary (#28). This is the lab-wired
/// counterpart of [`run`]: it composes [`bring_up`], the boundary self-check
/// gate, [`Scope::from_environment`] and the vantage execution path, which `run`
/// (the host-in-process `--allow` path) does not.
///
/// It is `async`: the caller owns the runtime (unlike `run`, which builds its
/// own), because the lab lifecycle is already async. Teardown runs on every path
/// this function returns from, including a self-check refusal or a test panic
/// (caught per test). The `RunningLab` `Drop` backstop (#18) is the last resort
/// for the paths that never reach the `teardown` call: an unwind or cancellation
/// before it, such as a panic in the self-check (which runs outside the per-test
/// `catch_unwind`) or this future being dropped at an earlier `.await`. A
/// teardown that ran to completion and failed is warned, not retried by the
/// backstop: the failure goes to stderr, not the return, because a leaked
/// egress-less lab is a row-5 cleanup concern, not a wrong verdict, and returning
/// it as `RunError` would demote a recorded `Fail` or hide a refusal.
pub async fn run_in_lab(
    docker: &Docker,
    env: &Environment,
) -> std::result::Result<RunSummary, RunError> {
    let lab = bring_up(docker, env).await.map_err(RunError::Lab)?;
    let outcome = run_in_running_lab(docker, env, &lab).await;
    if let Err(e) = lab.teardown().await {
        eprintln!("redstep: lab teardown after the run failed: {e}");
    }
    outcome
}

/// Gate on the boundary self-check, then run the registered tests against an
/// already-stood-up `lab` from its attacker vantage. `pub` and split from
/// [`run_in_lab`] so the refusal path is testable: the connected-lab test breaks
/// the lab *between* `bring_up` and the gate, which `run_in_lab` cannot express
/// because it owns the whole lifecycle. **A direct caller owns teardown** on both
/// the `Ok` and the `Err` return (`run_in_lab` is the caller that does it), with
/// the `RunningLab` `Drop` backstop behind it.
///
/// The self-check runs before any test and refuses the run on failure (ADR-0011
/// step 4), so a lab whose declared boundary is not actually blocked never
/// executes a test and cannot report PASS. Each test runs over a
/// [`TestContext::new_in_lab`] bound to the vantage segment's network, so
/// [`TestContext::connect_from_vantage`](crate::TestContext::connect_from_vantage) acts from inside the lab.
pub async fn run_in_running_lab(
    docker: &Docker,
    env: &Environment,
    lab: &RunningLab,
) -> std::result::Result<RunSummary, RunError> {
    boundary_self_check(docker, env, lab)
        .await
        .map_err(RunError::Lab)?;

    let scope = Scope::from_environment(env);
    let vantage = lab
        .networks()
        .iter()
        .find(|n| n.segment() == env.vantage_segment())
        .cloned()
        .ok_or_else(|| {
            RunError::Lab(Error::LabUnavailable {
                reason: format!(
                    "no network for the vantage segment {:?} in the running lab",
                    env.vantage_segment()
                ),
            })
        })?;

    let tests = ordered(registry::all().collect());
    let mut runs = Vec::with_capacity(tests.len());
    let mut evidence = EvidenceStore::new();
    for test in tests {
        let ctx = TestContext::new_in_lab(scope.clone(), docker.clone(), vantage.clone());
        // Catch a test panic on the async path too (the sync `run` uses
        // `catch_unwind` around `block_on`), so one test's panic is never read as
        // a pass. `AssertUnwindSafe` is sound for the same reason as in `run`: the
        // context sinks are borrow/push/drop, never held across an `.await`.
        let result = AssertUnwindSafe((test.run)(&ctx)).catch_unwind().await;
        runs.push(finalize_test(test.name, result, &ctx, &mut evidence));
    }

    Ok(RunSummary { runs, evidence })
}

/// Drain one finished test's context into a [`TestRun`]: append its evidence
/// drafts to the run store, resolve each judgement's per-test `DraftRef` to the
/// run-scoped [`EvidenceId`] the store just assigned (`base` is the id of this
/// test's first draft, so `DraftRef(i)` maps to `EvidenceId(base + i)`, issue
/// #14), and classify the caught result against the recorded judgements. Shared
/// by [`run`] (host) and [`run_in_running_lab`] (vantage), which produce the same
/// `std::thread::Result` so the resolution cannot diverge between the paths.
fn finalize_test(
    name: &'static str,
    result: std::thread::Result<crate::Result<()>>,
    ctx: &TestContext,
    evidence: &mut EvidenceStore,
) -> TestRun {
    let recorded = ctx.take_judgements();
    let base = evidence.len();
    for draft in ctx.take_evidence_drafts() {
        evidence.append(draft, now_ms());
    }
    let judgements: Vec<Judgement> = recorded
        .into_iter()
        .map(|(mut judgement, draft_ref)| {
            judgement.evidence =
                draft_ref.map(|reference| EvidenceId((base + reference.index()) as u64));
            judgement
        })
        .collect();
    let (verdict, error) = classify(result, &judgements);
    TestRun {
        name,
        verdict,
        judgements,
        error,
    }
}

/// The current time as epoch milliseconds, the one wall-clock read in the crate.
/// The store takes the timestamp as a parameter so it stays pure; this supplies
/// it. A clock before the Unix epoch (not reachable in practice) stamps `0`.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Order tests by name, so a run reports in a stable, deterministic order
/// rather than the registry's (unspecified) submission order. Pure, so the
/// ordering is tested without the registry.
fn ordered(mut tests: Vec<&registry::RegisteredTest>) -> Vec<&registry::RegisteredTest> {
    tests.sort_by_key(|t| t.name);
    tests
}

/// Turn a caught test result and its recorded judgements into a verdict and an
/// optional message. Pure, so the mapping is tested without a runtime.
///
/// A recorded `Fail` dominates: a confirmed finding stands even if the body
/// then errored or panicked, so a breach is never demoted to `Error`. Otherwise
/// a panic or a non-`Check` error is `Error` (the test could not run to a
/// verdict), a bare `check` failure is `Fail`, and a clean body takes the
/// aggregate of its judgements.
fn classify(
    result: std::thread::Result<crate::Result<()>>,
    judgements: &[Judgement],
) -> (Verdict, Option<String>) {
    let recorded = aggregate(judgements);
    match result {
        Ok(Ok(())) => (recorded, None),
        Ok(Err(Error::Check(message))) => (worse_of(recorded, Verdict::Fail), Some(message)),
        Ok(Err(other)) => (worse_of(recorded, Verdict::Error), Some(other.to_string())),
        Err(panic) => (
            worse_of(recorded, Verdict::Error),
            Some(panic_message(panic)),
        ),
    }
}

/// Aggregate a test's judgements into the most severe. A test that recorded
/// none is `Inconclusive`, not `Pass`: nothing was proven, so it must not read
/// as safe (CLAUDE.md row 6). Non-empty takes the max over `Verdict::severity`,
/// which is where the fail-closed ordering lives.
fn aggregate(judgements: &[Judgement]) -> Verdict {
    judgements
        .iter()
        .map(|j| j.verdict)
        .max_by_key(|verdict| verdict.severity())
        .unwrap_or(Verdict::Inconclusive)
}

/// The more severe of two verdicts (see `Verdict::severity`), so a recorded
/// `Fail` is not demoted by a later `Error`.
fn worse_of(a: Verdict, b: Verdict) -> Verdict {
    if a.severity() >= b.severity() { a } else { b }
}

/// Recover a readable message from a panic payload.
fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "test panicked".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::Confidence;

    fn run_of(name: &'static str, verdict: Verdict) -> TestRun {
        TestRun {
            name,
            verdict,
            judgements: Vec::new(),
            error: None,
        }
    }

    fn judged(verdict: Verdict) -> Judgement {
        Judgement {
            verdict,
            expected: "x".to_owned(),
            actual: "y".to_owned(),
            confidence: Confidence::High,
            evidence: None,
            diagnostic: None,
        }
    }

    /// Guard: the summary exits zero only when every verdict is Pass. Mutation:
    /// treat Fail as Pass in `exit_code` -> a failing run exits zero -> fails.
    #[test]
    fn fail_run_exits_nonzero() {
        let summary = RunSummary {
            runs: vec![run_of("a", Verdict::Pass), run_of("b", Verdict::Fail)],
            evidence: EvidenceStore::new(),
        };
        assert_ne!(summary.exit_code(), 0);
    }

    /// Guard: an Inconclusive run exits non-zero, like Fail (an unconfirmed pass
    /// is not a green gate, CLAUDE.md row 6). Mutation: treat Inconclusive as
    /// Pass in `exit_code` -> exits zero -> fails.
    #[test]
    fn inconclusive_run_exits_nonzero() {
        let summary = RunSummary {
            runs: vec![
                run_of("a", Verdict::Pass),
                run_of("b", Verdict::Inconclusive),
            ],
            evidence: EvidenceStore::new(),
        };
        assert_ne!(summary.exit_code(), 0);
    }

    /// Guard: an errored run exits non-zero. Mutation: treat Error as Pass ->
    /// exits zero -> fails.
    #[test]
    fn errored_run_exits_nonzero() {
        let summary = RunSummary {
            runs: vec![run_of("a", Verdict::Error)],
            evidence: EvidenceStore::new(),
        };
        assert_ne!(summary.exit_code(), 0);
    }

    /// Guard: an all-passed run exits zero. Mutation: make `exit_code` always
    /// return 1 -> fails.
    #[test]
    fn all_passed_run_exits_zero() {
        let summary = RunSummary {
            runs: vec![run_of("a", Verdict::Pass)],
            evidence: EvidenceStore::new(),
        };
        assert_eq!(summary.exit_code(), 0);
    }

    /// Guard: an empty run is not a pass. Mutation: drop the `!is_empty()` term
    /// -> an empty run exits zero -> fails.
    #[test]
    fn empty_run_does_not_pass() {
        let summary = RunSummary {
            runs: vec![],
            evidence: EvidenceStore::new(),
        };
        assert_ne!(summary.exit_code(), 0);
    }

    /// Guard: a clean body takes the aggregate (an empty body is Inconclusive),
    /// a Check failure is Fail, and a non-Check error or panic is Error.
    /// Mutation: map the Check arm to Error, or the Ok arm to a constant Pass ->
    /// fails.
    #[test]
    fn classify_maps_result_to_verdict() {
        assert_eq!(classify(Ok(Ok(())), &[]).0, Verdict::Inconclusive);
        assert_eq!(
            classify(Ok(Err(Error::Check("nope".into()))), &[]),
            (Verdict::Fail, Some("nope".to_owned()))
        );
        assert_eq!(
            classify(
                Ok(Err(Error::OutOfScope {
                    spec: "db:5432".into()
                })),
                &[]
            )
            .0,
            Verdict::Error
        );
        let panic: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(classify(Err(panic), &[]).0, Verdict::Error);
    }

    /// Guard: a recorded Fail is not demoted by a later error or panic (a
    /// confirmed breach stands). Mutation: drop `worse_of` and return `Error`
    /// directly in the error/panic arms -> the recorded Fail is lost -> fails.
    #[test]
    fn recorded_fail_survives_a_later_error_or_panic() {
        let fail = [judged(Verdict::Fail)];
        assert_eq!(
            classify(
                Ok(Err(Error::OutOfScope {
                    spec: "db:5432".into()
                })),
                &fail,
            )
            .0,
            Verdict::Fail
        );
        let panic: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(classify(Err(panic), &fail).0, Verdict::Fail);
        // An Inconclusive does NOT survive an error (could-not-run dominates):
        let inconclusive = [judged(Verdict::Inconclusive)];
        let panic2: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(classify(Err(panic2), &inconclusive).0, Verdict::Error);
    }

    /// Guard: a test that recorded no judgement is Inconclusive, not Pass:
    /// nothing was proven (CLAUDE.md row 6). Mutation: make `aggregate(&[])`
    /// return Pass -> fails.
    #[test]
    fn no_judgement_is_inconclusive() {
        assert_eq!(aggregate(&[]), Verdict::Inconclusive);
    }

    /// Guard: the aggregate is fail-closed: Fail dominates Inconclusive
    /// dominates Pass. Mutation: reorder the precedence (Inconclusive before
    /// Fail, or ignore Fail) -> fails.
    #[test]
    fn aggregate_is_fail_closed() {
        assert_eq!(aggregate(&[judged(Verdict::Pass)]), Verdict::Pass);
        assert_eq!(
            aggregate(&[judged(Verdict::Pass), judged(Verdict::Inconclusive)]),
            Verdict::Inconclusive
        );
        assert_eq!(
            aggregate(&[
                judged(Verdict::Pass),
                judged(Verdict::Inconclusive),
                judged(Verdict::Fail),
            ]),
            Verdict::Fail
        );
    }

    /// Guard: `ordered` sorts tests by name regardless of input order.
    /// Mutation: drop the `sort_by_key` -> the unsorted input comes back
    /// unsorted -> this fails.
    #[test]
    fn ordered_sorts_by_name() {
        fn stub(_: &TestContext) -> registry::TestFuture<'_> {
            Box::pin(async { Ok(()) })
        }
        let c = registry::RegisteredTest {
            name: "c",
            run: stub,
        };
        let a = registry::RegisteredTest {
            name: "a",
            run: stub,
        };
        let b = registry::RegisteredTest {
            name: "b",
            run: stub,
        };

        let names: Vec<&str> = ordered(vec![&c, &a, &b]).iter().map(|t| t.name).collect();
        assert_eq!(names, ["a", "b", "c"]);
    }
}

/// Capability-driven evidence collection and judgement linking, exercised through
/// the public `run` path. These were external-crate tests (`tests/public_api.rs`)
/// until the `Capability` trait was sealed (#9): an external crate can no longer
/// implement it, so a stub capability that drives `run` must live in-crate. The
/// run-level pub surface (`run`, `TestContext`, evidence access) is still proven
/// external by `public_api_items_are_reachable`; these prove the runner's
/// behaviour, which does not depend on the external path.
#[cfg(test)]
mod evidence_integration_tests {
    use super::run;
    use crate::capability::{Authorized, Capability};
    use crate::evidence::{EvidenceDraft, EvidenceId, Reproduction};
    use crate::intensity::Intensity;
    use crate::observation::{Confidence, Observation};
    use crate::scope::Scope;
    use crate::{TestContext, Verdict};

    /// A Safe stub capability that observes a reachable target with no socket, so
    /// `run` has deterministic evidence to collect. The target is a field so one
    /// test can run it twice with distinct records. It bypasses scope on purpose
    /// (it holds a literal, not a `ScopedTarget`): scope-by-type is not enforced
    /// trait-wide yet (#9), and these tests exercise evidence, not scope.
    struct StubReachable {
        target: &'static str,
    }

    impl crate::capability::sealed::Sealed for StubReachable {}
    impl Capability for StubReachable {
        type Value = bool;

        fn name(&self) -> &'static str {
            "stub_reachable"
        }

        fn intensity(&self) -> Intensity {
            Intensity::Safe
        }

        async fn execute(
            &self,
            _authorized: Authorized,
        ) -> crate::Result<(Observation<bool>, EvidenceDraft)> {
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
                    source: None,
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
    #[redstep::security_test]
    async fn records_evidence_demo(ctx: &TestContext) -> crate::Result<()> {
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
    /// `base` is always 0 and dropping it changes nothing (RK-004).
    #[redstep::security_test]
    async fn aaa_earlier_evidence_demo(ctx: &TestContext) -> crate::Result<()> {
        let recorded = ctx
            .run(StubReachable {
                target: "stub:earlier",
            })
            .await?;
        ctx.expect(&recorded).to_be(true);
        Ok(())
    }

    /// Guard: a run collects every capability execution's evidence into the summary's
    /// store, in execution order, with run-scoped sequential ids and a real clock
    /// timestamp (ADR-0004). The two registered demos produce evidence:
    /// `aaa_earlier_evidence_demo` (sorts first) once, then `records_evidence_demo`
    /// twice, so the store holds `earlier`, `alpha`, `beta` at ids 0, 1, 2.
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
            assert_eq!(record.id, EvidenceId(index as u64));
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
    /// `base` offset load-bearing (RK-004).
    /// Mutations caught: drop `base` in the remap (`EvidenceId(index)`) -> the second
    /// demo's first judgement resolves to id 0 (`stub:earlier`, another test's
    /// record) -> the `stub:alpha` assert fails; an index off-by-one or reversal ->
    /// the wrong target -> fails; make `Recorded` carry no reference, or `check` carry
    /// one -> the counts or the `check` assert fail.
    #[test]
    fn run_links_judgements_to_their_evidence() {
        let summary = run(Scope::default()).expect("the runtime starts");

        let resolve = |id: EvidenceId| {
            summary
                .evidence
                .records()
                .iter()
                .find(|e| e.id == id)
                .unwrap_or_else(|| panic!("evidence id {id:?} does not resolve"))
        };
        let links = |suffix: &str| -> Vec<EvidenceId> {
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
            later[0] != EvidenceId(0),
            "the later test's link must carry the per-test base, not start at 0"
        );
        assert_eq!(resolve(later[0]).target, "stub:alpha");
        assert_eq!(resolve(later[1]).target, "stub:beta");

        // The later producer verdicts Pass (the stub observes reachable, the
        // expectation matches), so the linked evidence belongs to a passing run.
        let verdict = summary
            .runs
            .iter()
            .find(|r| r.name.ends_with("::records_evidence_demo"))
            .expect("discovered")
            .verdict;
        assert_eq!(verdict, Verdict::Pass);
    }
}
