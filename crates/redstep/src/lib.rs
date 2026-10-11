//! redstep: author a security test as an async function, have it discovered and
//! executed, and get a per-test result.
//!
//! This crate is the runner MVP (Decision A). A test is written as:
//!
//! ```ignore
//! #[redstep::security_test]
//! async fn db_is_unreachable(ctx: &redstep::TestContext) -> redstep::Result<()> {
//!     let target = ctx.resolve("db:5432")?;
//!     let (observation, _evidence) = ctx.run(redstep::TcpConnect::new(target)).await?;
//!     ctx.check(!observation.value, "the DB is not reachable from the attacker")?;
//!     Ok(())
//! }
//! ```
//!
//! The `Capability` trait (Decision B) and a minimal `Evidence` (Decision D)
//! exist here; the verdict oracle's corroboration (Decision J), the append-only
//! evidence store (Decision D) and the environment (Decision C) are later
//! units, and this crate leaves a named seam for each.

// Lets the `#[security_test]` expansion, which refers to this crate as
// `::redstep`, compile from inside this crate's own `src/`. A test written in
// an integration test or an external crate does not need this (it sees
// `redstep` as an ordinary dependency); it is here so an in-crate unit test or
// a doctest could use the macro too.
extern crate self as redstep;

mod capability;
mod context;
mod error;
mod evidence;
mod expectation;
mod intensity;
mod observation;
// `#[doc(hidden)]`: the `#[security_test]` expansion reaches these by path, but
// they are not a surface for a downstream crate to build on. See registry.rs.
#[doc(hidden)]
pub mod registry;
mod runner;
mod scope;
mod verdict;

pub use capability::{Capability, TcpConnect};
pub use context::{ExpectationBuilder, TestContext};
pub use error::{Error, Result};
pub use evidence::Evidence;
pub use expectation::{Expectation, Judgement, judge};
pub use intensity::Intensity;
pub use observation::{Confidence, Observation};
pub use redstep_macros::security_test;
pub use runner::{RunError, RunSummary, TestRun, run};
pub use scope::{Scope, ScopeBuilder, ScopedTarget};
pub use verdict::Verdict;
