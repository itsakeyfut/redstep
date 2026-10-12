//! Discovering and executing the registered security tests.
//!
//! Execution is sequential, in name order, one test at a time on a single
//! current-thread runtime: deterministic and safe against a shared lab target.
//! Each test runs inside `catch_unwind`, so one test's panic cannot abort the
//! run and is never read as a pass. Each test gets its own `TestContext`, so the
//! judgements it records are its own.

use crate::TestContext;
use crate::error::Error;
use crate::evidence::{EvidenceId, EvidenceStore};
use crate::expectation::Judgement;
use crate::registry;
use crate::scope::Scope;
use crate::verdict::Verdict;
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
    /// (Decision D, E).
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
}

/// Discover every registered test and run it, each against its own context over
/// a clone of `scope`. The evidence each test produced is collected into one
/// run-level [`EvidenceStore`], in test-then-execution order; the store assigns
/// the ids and stamps the timestamps from this runner's clock (Decision D).
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
        let recorded = ctx.take_judgements();
        // Append this test's drafts, then resolve each judgement's per-test
        // reference to the run-scoped id the store just assigned. `base` is the
        // id of this test's first draft, so a `DraftRef(i)` maps to
        // `EvidenceId(base + i)` (issue #14).
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
        runs.push(TestRun {
            name: test.name,
            verdict,
            judgements,
            error,
        });
    }

    Ok(RunSummary { runs, evidence })
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
