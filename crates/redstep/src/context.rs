//! The entry point a security test is handed.
//!
//! For the runner MVP it holds the scope and offers resolution and a minimal
//! assertion. The capability registry (Decision B) and the evidence sink
//! (Decision D) are later fields; they are deliberately absent here.

use crate::error::{Error, Result};
use crate::scope::{Scope, ScopedTarget};

/// What a `#[security_test]` receives: `async fn NAME(ctx: &TestContext) -> redstep::Result<()>`.
pub struct TestContext {
    scope: Scope,
}

impl TestContext {
    /// Build a context over a resolved scope. The runner builds one per run;
    /// a test constructs one directly.
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    /// Resolve a `host:port` target through the scope gate. An out-of-scope or
    /// malformed target is an error before any action (docs/rules/security.md
    /// section 2).
    pub fn resolve(&self, spec: &str) -> Result<ScopedTarget> {
        self.scope.resolve(spec)
    }

    /// The minimal assertion for the runner MVP: `Ok(())` when the condition
    /// holds, [`Error::Check`] otherwise. The verdict oracle (Decision J)
    /// replaces this with Observation and Expectation; it exists now so a test
    /// can fail as an `Err` rather than a panic.
    pub fn check(&self, condition: bool, message: &str) -> Result<()> {
        if condition {
            Ok(())
        } else {
            Err(Error::Check(message.to_owned()))
        }
    }
}
