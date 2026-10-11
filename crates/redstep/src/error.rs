//! The error a security test can return.
//!
//! This is the pure model layer: no I/O, no runtime. A message never carries a
//! secret (docs/rules/error-handling.md), and a `host:port` spec is not one.

/// A failure surfaced from inside a security test.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The target was not in the scope allowlist. Resolution yields no
    /// `ScopedTarget`, so nothing can act on it (docs/rules/security.md section
    /// 2); the runner maps a test that returns this to `Errored`. A test that
    /// matches on the `Result` could handle it instead of propagating, but it
    /// can never turn it into a reachable target.
    #[error("target {spec:?} is out of scope")]
    OutOfScope {
        /// The rejected target specification, as given.
        spec: String,
    },

    /// A target specification could not be parsed as `host:port`.
    #[error("invalid target {spec:?}: {reason}")]
    InvalidTarget {
        /// The specification that failed to parse.
        spec: String,
        /// Why it failed.
        reason: String,
    },

    /// A `TestContext::check` assertion did not hold. This is the minimal
    /// assertion channel for the runner MVP; the verdict oracle (Decision J)
    /// supersedes it.
    #[error("check failed: {0}")]
    Check(String),

    /// A capability was run at an intensity that is not unlocked. Only `Safe`
    /// is exercisable yet; `Controlled` and `Aggressive` require the
    /// authorization and isolation proof a later unit adds (See Decision F).
    /// Carried here, in the model error, because it names only `Intensity` (a
    /// model type), so the dependency still points downward.
    #[error("intensity {got:?} is not unlocked; only Safe runs in this build")]
    IntensityRefused {
        /// The intensity the capability reported.
        got: crate::intensity::Intensity,
    },
}

/// The result type carried through a security test.
pub type Result<T> = std::result::Result<T, Error>;
