//! redstep: author a security test as an async function, have it discovered and
//! executed, and get a per-test result.
//!
//! This crate is the runner MVP (Decision A). A test is written as:
//!
//! ```ignore
//! #[redstep::security_test]
//! async fn db_is_unreachable(ctx: &redstep::TestContext) -> redstep::Result<()> {
//!     let target = ctx.resolve("db:5432")?;
//!     ctx.check(target.port() == 5432, "resolved the declared port")?;
//!     Ok(())
//! }
//! ```
//!
//! The `Capability` trait (Decision B), the verdict oracle (Decision J), the
//! evidence record (Decision D) and the environment (Decision C) are later
//! units; this crate leaves a named seam for each.

// Lets the `#[security_test]` expansion refer to this crate as `::redstep`
// even when a test is written inside this crate (tests, examples).
extern crate self as redstep;

mod context;
mod error;
pub mod registry;
mod runner;
mod scope;

pub use context::TestContext;
pub use error::{Error, Result};
pub use redstep_macros::security_test;
pub use runner::{Outcome, RunError, RunSummary, TestRun, run};
pub use scope::{Scope, ScopeBuilder, ScopedTarget};
