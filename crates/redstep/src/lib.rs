//! redstep: author a security test as an async function, have it discovered and
//! executed, and get a per-test result.
//!
//! This crate is the runner MVP (ADR-0001). A test is written as:
//!
//! ```ignore
//! #[redstep::security_test]
//! async fn attacker_cannot_connect_to_db(ctx: &redstep::TestContext) -> redstep::Result<()> {
//!     let target = ctx.resolve("db:5432")?;
//!     let recorded = ctx.run(redstep::TcpConnect::new(target)).await?;
//!     ctx.expect(&recorded).to_be(false); // require High confidence by default
//!     Ok(())
//! }
//! ```
//!
//! The `Capability` trait (ADR-0002), the verdict oracle (ADR-0010) and the
//! append-only evidence store (ADR-0004) exist here; the oracle's corroboration
//! (ADR-0010) and the environment (ADR-0003) are later units, and this crate
//! leaves a named seam for each.

// Lets the `#[security_test]` expansion, which refers to this crate as
// `::redstep`, compile from inside this crate's own `src/`. A test written in
// an integration test or an external crate does not need this (it sees
// `redstep` as an ordinary dependency); it is here so an in-crate unit test or
// a doctest could use the macro too.
extern crate self as redstep;

mod capability;
mod context;
mod environment;
mod error;
mod evidence;
mod expectation;
mod intensity;
mod observation;
mod orchestrator;
// `#[doc(hidden)]`: the `#[security_test]` expansion reaches these by path, but
// they are not a surface for a downstream crate to build on. See registry.rs.
#[doc(hidden)]
pub mod registry;
/// The canonical JSON and its terminal renderer (ADR-0005, ADR-0009).
pub mod report;
mod runner;
mod scope;
mod verdict;

pub use capability::{Capability, TcpConnect};
pub use context::{Expectable, ExpectationBuilder, Recorded, TestContext};
pub use environment::{Boundary, Environment, EnvironmentBuilder, Segment, Workload};
pub use error::{Error, Result};
pub use evidence::{
    DraftRef, Evidence, EvidenceDraft, EvidenceId, EvidenceStore, NodeRef, Reproduction,
};
pub use expectation::{Diagnostic, Expectation, Judgement, judge};
pub use intensity::Intensity;
pub use observation::{Confidence, Observation};
pub use orchestrator::{LabContainer, LabNetwork, RunningLab, boundary_self_check, bring_up};
pub use redstep_macros::security_test;
pub use runner::{RunError, RunSummary, TestRun, run, run_in_lab, run_in_running_lab};
pub use scope::{Scope, ScopeBuilder, ScopedTarget};
pub use verdict::Verdict;
