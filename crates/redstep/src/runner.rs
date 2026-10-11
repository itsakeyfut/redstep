//! Discovering and executing the registered security tests.
//!
//! Execution is sequential, in name order, one test at a time on a single
//! current-thread runtime: deterministic and safe against a shared lab target.
//! Each test runs inside `catch_unwind`, so one test's panic cannot abort the
//! run and is never read as a pass.

use crate::TestContext;
use crate::error::Error;
use crate::registry;
use crate::scope::Scope;
use std::panic::AssertUnwindSafe;

/// What became of one test.
///
/// `#[non_exhaustive]` for downstream matches, but matched totally inside this
/// crate (no `_` arm) so a new variant is a compile error at every decision
/// site (docs/rules/design.md section 5).
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The test returned `Ok(())`.
    Passed,
    /// The test returned [`Error::Check`]: an assertion did not hold.
    Failed(String),
    /// The test returned any other error, or panicked. A test that could not
    /// run is never a pass (CLAUDE.md row 6).
    Errored(String),
}

impl Outcome {
    /// A short label for a report line (`ok` / `FAIL` / `ERROR`). Matched
    /// totally here, in the crate that owns `Outcome`, so a new variant is a
    /// compile error at this site rather than a silently unlabelled outcome.
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Passed => "ok",
            Outcome::Failed(_) => "FAIL",
            Outcome::Errored(_) => "ERROR",
        }
    }

    /// The failure reason, if this outcome carries one.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Outcome::Passed => None,
            Outcome::Failed(reason) | Outcome::Errored(reason) => Some(reason),
        }
    }
}

/// One test's name and outcome.
#[derive(Debug)]
pub struct TestRun {
    /// The fully-qualified test name.
    pub name: &'static str,
    /// What became of it.
    pub outcome: Outcome,
}

/// The result of running every discovered test.
#[derive(Debug)]
pub struct RunSummary {
    /// One entry per test, in the order they ran (sorted by name).
    pub runs: Vec<TestRun>,
}

impl RunSummary {
    /// `0` only when every test passed; non-zero when any failed or errored.
    /// Errored is non-passing on purpose: a test that could not run must not
    /// read as safe.
    pub fn exit_code(&self) -> i32 {
        if self.runs.iter().all(|r| r.outcome == Outcome::Passed) {
            0
        } else {
            1
        }
    }
}

/// A fatal error that stops the whole run before any test outcome exists.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RunError {
    /// The async runtime could not be started.
    #[error("failed to start the async runtime: {0}")]
    Runtime(#[source] std::io::Error),
}

/// Discover every registered test and run it against a context over `scope`.
pub fn run(scope: Scope) -> std::result::Result<RunSummary, RunError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(RunError::Runtime)?;
    let ctx = TestContext::new(scope);

    let tests = ordered(registry::all().collect());

    let runs = tests
        .into_iter()
        .map(|test| {
            let result =
                std::panic::catch_unwind(AssertUnwindSafe(|| runtime.block_on((test.run)(&ctx))));
            TestRun {
                name: test.name,
                outcome: classify(result),
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

/// Map a caught test result to an [`Outcome`]. Pure, so the mapping is tested
/// without a runtime or the registry.
fn classify(result: std::thread::Result<crate::Result<()>>) -> Outcome {
    match result {
        Ok(Ok(())) => Outcome::Passed,
        Ok(Err(Error::Check(message))) => Outcome::Failed(message),
        Ok(Err(other)) => Outcome::Errored(other.to_string()),
        Err(panic) => Outcome::Errored(panic_message(panic)),
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

    /// Guard: the summary exits zero only when every test passed. Mutation:
    /// change `all` to `any` in `exit_code` -> a summary with one failure
    /// exits zero -> fails.
    #[test]
    fn failed_run_exits_nonzero() {
        let summary = RunSummary {
            runs: vec![
                TestRun {
                    name: "a",
                    outcome: Outcome::Passed,
                },
                TestRun {
                    name: "b",
                    outcome: Outcome::Failed("x".into()),
                },
            ],
        };
        assert_ne!(summary.exit_code(), 0);
    }

    /// Guard: an errored test makes the run exit non-zero, exactly like a
    /// failure (CLAUDE.md row 6). Mutation: treat `Errored` as passing in
    /// `exit_code` -> this exits zero -> fails.
    #[test]
    fn errored_run_exits_nonzero() {
        let summary = RunSummary {
            runs: vec![
                TestRun {
                    name: "a",
                    outcome: Outcome::Passed,
                },
                TestRun {
                    name: "b",
                    outcome: Outcome::Errored("boom".into()),
                },
            ],
        };
        assert_ne!(summary.exit_code(), 0);
    }

    /// Guard: an all-passed summary exits zero. Mutation: make `exit_code`
    /// always return 1 -> fails.
    #[test]
    fn all_passed_run_exits_zero() {
        let summary = RunSummary {
            runs: vec![TestRun {
                name: "a",
                outcome: Outcome::Passed,
            }],
        };
        assert_eq!(summary.exit_code(), 0);
    }

    /// Guard: classify maps `Ok(Ok(()))` to Passed. Mutation: map it to Failed
    /// -> fails.
    #[test]
    fn classify_ok_is_passed() {
        assert_eq!(classify(Ok(Ok(()))), Outcome::Passed);
    }

    /// Guard: classify maps a `Check` error to Failed carrying its message.
    /// Mutation: map `Check` to Errored -> fails.
    #[test]
    fn classify_check_error_is_failed() {
        assert_eq!(
            classify(Ok(Err(Error::Check("nope".into())))),
            Outcome::Failed("nope".into())
        );
    }

    /// Guard: classify maps any non-`Check` error to Errored. Mutation: map it
    /// to Failed or Passed -> fails.
    #[test]
    fn classify_other_error_is_errored() {
        let out = classify(Ok(Err(Error::OutOfScope {
            spec: "db:5432".into(),
        })));
        assert!(matches!(out, Outcome::Errored(_)));
    }

    /// Guard: classify maps a panic to Errored carrying the panic message.
    /// Mutation: map the panic arm to Passed -> a panicking test reads as safe
    /// -> fails.
    #[test]
    fn classify_panic_is_errored() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("kaboom");
        assert_eq!(classify(Err(payload)), Outcome::Errored("kaboom".into()));
    }

    /// Guard: each outcome has its own report label. Mutation: return the same
    /// label for every variant (e.g. `""`) -> this fails. The label is what a
    /// reader greps a run's output for.
    #[test]
    fn outcome_labels_are_distinct() {
        assert_eq!(Outcome::Passed.label(), "ok");
        assert_eq!(Outcome::Failed("x".into()).label(), "FAIL");
        assert_eq!(Outcome::Errored("y".into()).label(), "ERROR");
    }

    /// Guard: only a failed or errored outcome carries a reason, and it is the
    /// carried string. Mutation: return `Some` for Passed, or `None` for a
    /// failure -> this fails.
    #[test]
    fn outcome_reason_is_the_failure_message() {
        assert_eq!(Outcome::Passed.reason(), None);
        assert_eq!(Outcome::Failed("boom".into()).reason(), Some("boom"));
        assert_eq!(Outcome::Errored("boom".into()).reason(), Some("boom"));
    }

    /// Guard: `ordered` sorts tests by name regardless of input order.
    /// Mutation: drop the `sort_by_key` -> the unsorted input comes back
    /// unsorted -> this fails. An end-to-end order check cannot catch this: the
    /// registry's iteration order is unspecified and happened to be sorted.
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
