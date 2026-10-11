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
/// `#[non_exhaustive]`, so a downstream match needs a wildcard. Inside this
/// crate `label` and `reason` match it totally, so a new variant is a compile
/// error there (docs/rules/design.md section 5). `RunSummary::exit_code` does
/// not match it; it compares to `Passed`, so it fails closed, counting any new
/// variant as non-passing until that site is updated. The names (`Outcome`,
/// `Passed`/`Failed`/`Errored`) are MVP placeholders to reconcile with the
/// verdict model (Decision J) and `Evidence`'s own `Outcome` (Decision D) when
/// those land.
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
    /// `0` only when at least one test ran and every one passed; non-zero when
    /// any failed or errored, and non-zero for an empty run.
    ///
    /// An empty run is not a pass. "Nothing was discovered" must not read as
    /// "all clear": a vacuous `all()` over no tests would return `0`, and since
    /// the shipped binary links no tests and any discovery failure yields an
    /// empty run, that would turn a non-run into a green CI gate (a false PASS,
    /// CLAUDE.md row 6). Errored is non-passing for the same reason: a test that
    /// could not run must not read as safe.
    pub fn exit_code(&self) -> i32 {
        if !self.runs.is_empty() && self.runs.iter().all(|r| r.outcome == Outcome::Passed) {
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

    /// Guard: an empty run (nothing discovered) is not a pass. Mutation: drop
    /// the `!is_empty()` term from `exit_code` -> a run that discovered nothing
    /// exits zero -> fails. This is the row-6 false PASS an empty discovery
    /// (the shipped binary, a broken registration, a filter that matches
    /// nothing) would otherwise report as all-clear.
    #[test]
    fn empty_run_does_not_pass() {
        let summary = RunSummary { runs: vec![] };
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

    /// Guard: classify maps a `&str` panic to Errored carrying the message.
    /// Mutation: map the panic arm to Passed -> a panicking test reads as safe
    /// -> fails.
    #[test]
    fn classify_panic_is_errored() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("kaboom");
        assert_eq!(classify(Err(payload)), Outcome::Errored("kaboom".into()));
    }

    /// Guard: a `String` panic payload keeps its message. Mutation: replace the
    /// `String` arm of `panic_message` -> the message is lost -> fails.
    /// `panic!("{}", x)` produces a `String`, not a `&str`, so this arm is the
    /// common one.
    #[test]
    fn classify_string_panic_keeps_message() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(String::from("owned boom"));
        assert_eq!(
            classify(Err(payload)),
            Outcome::Errored("owned boom".into())
        );
    }

    /// Guard: a non-string panic payload still errors, with a generic message.
    /// Mutation: change the fallback string -> fails; map the fallback to Passed
    /// -> a `panic_any(non_string)` reads as safe -> fails.
    #[test]
    fn classify_nonstring_panic_is_generic_errored() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(42_i32);
        assert_eq!(
            classify(Err(payload)),
            Outcome::Errored("test panicked".into())
        );
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
