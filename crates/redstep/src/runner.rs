//! Discovering and executing the registered security tests.
//!
//! Execution is sequential, in name order, one test at a time on a single
//! current-thread runtime: deterministic and safe against a shared lab target.
//! Each test runs inside `catch_unwind`, so one test's panic cannot abort the
//! run and is never read as a pass. Each test gets its own `TestContext`, so the
//! judgements it records are its own.

use crate::TestContext;
use crate::error::Error;
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
/// a clone of `scope`.
pub fn run(scope: Scope) -> std::result::Result<RunSummary, RunError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(RunError::Runtime)?;

    let tests = ordered(registry::all().collect());

    let runs = tests
        .into_iter()
        .map(|test| {
            let ctx = TestContext::new(scope.clone());
            let result =
                std::panic::catch_unwind(AssertUnwindSafe(|| runtime.block_on((test.run)(&ctx))));
            let judgements = ctx.take_judgements();
            let (verdict, error) = classify(result, &judgements);
            TestRun {
                name: test.name,
                verdict,
                judgements,
                error,
            }
        })
        .collect();

    Ok(RunSummary { runs })
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
/// A panic or a non-`Check` error means the test could not run to a verdict:
/// `Error`. A bare `check` failure is `Fail`. Otherwise the verdict is the
/// aggregate of the recorded judgements.
fn classify(
    result: std::thread::Result<crate::Result<()>>,
    judgements: &[Judgement],
) -> (Verdict, Option<String>) {
    match result {
        Err(panic) => (Verdict::Error, Some(panic_message(panic))),
        Ok(Err(Error::Check(message))) => (Verdict::Fail, Some(message)),
        Ok(Err(other)) => (Verdict::Error, Some(other.to_string())),
        Ok(Ok(())) => (aggregate(judgements), None),
    }
}

/// Aggregate a test's judgements: a `Fail` dominates, then an `Inconclusive`,
/// else `Pass` (including a test that recorded none). Fail-closed: an
/// unconfirmed judgement never upgrades to Pass.
fn aggregate(judgements: &[Judgement]) -> Verdict {
    if judgements.iter().any(|j| j.verdict == Verdict::Fail) {
        Verdict::Fail
    } else if judgements
        .iter()
        .any(|j| j.verdict == Verdict::Inconclusive)
    {
        Verdict::Inconclusive
    } else {
        Verdict::Pass
    }
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
        }
    }

    /// Guard: the summary exits zero only when every verdict is Pass. Mutation:
    /// treat Fail as Pass in `exit_code` -> a failing run exits zero -> fails.
    #[test]
    fn fail_run_exits_nonzero() {
        let summary = RunSummary {
            runs: vec![run_of("a", Verdict::Pass), run_of("b", Verdict::Fail)],
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
        };
        assert_ne!(summary.exit_code(), 0);
    }

    /// Guard: an errored run exits non-zero. Mutation: treat Error as Pass ->
    /// exits zero -> fails.
    #[test]
    fn errored_run_exits_nonzero() {
        let summary = RunSummary {
            runs: vec![run_of("a", Verdict::Error)],
        };
        assert_ne!(summary.exit_code(), 0);
    }

    /// Guard: an all-passed run exits zero. Mutation: make `exit_code` always
    /// return 1 -> fails.
    #[test]
    fn all_passed_run_exits_zero() {
        let summary = RunSummary {
            runs: vec![run_of("a", Verdict::Pass)],
        };
        assert_eq!(summary.exit_code(), 0);
    }

    /// Guard: an empty run is not a pass. Mutation: drop the `!is_empty()` term
    /// -> an empty run exits zero -> fails.
    #[test]
    fn empty_run_does_not_pass() {
        let summary = RunSummary { runs: vec![] };
        assert_ne!(summary.exit_code(), 0);
    }

    /// Guard: a panic or a non-Check error is Error, a Check failure is Fail,
    /// and a clean body takes the aggregate of its judgements. Mutation: map the
    /// Check arm to Error, or the panic arm to Pass -> fails.
    #[test]
    fn classify_maps_result_to_verdict() {
        assert_eq!(classify(Ok(Ok(())), &[]).0, Verdict::Pass);
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

    /// Guard: the aggregate is fail-closed: Fail dominates, then Inconclusive,
    /// else Pass. Mutation: reorder the precedence (Inconclusive before Fail, or
    /// default to Pass ignoring Fail) -> fails.
    #[test]
    fn aggregate_is_fail_closed() {
        assert_eq!(aggregate(&[]), Verdict::Pass);
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
