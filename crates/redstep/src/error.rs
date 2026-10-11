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
    /// 2); the runner maps a test that returns this to `Verdict::Error`. A test
    /// that matches on the `Result` could handle it instead of propagating, but
    /// it can never turn it into a reachable target.
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

    /// A `TestContext::check` assertion did not hold, stopping the test. `check`
    /// is the bare-boolean channel; the oracle's `expect` (Decision J) is the
    /// path for an assertion over an observation, with the confidence gate.
    #[error("check failed: {0}")]
    Check(String),

    /// A capability was run at an intensity that is not permitted. Only `Safe`
    /// is allowed yet; `Controlled` and `Aggressive` require the authorization
    /// and isolation proof a later unit adds (See Decision F), not a different
    /// build. Carried here, in the model error, because it names only
    /// `Intensity` (a model type), so the dependency still points downward.
    #[error(
        "capability intensity {got:?} is not permitted; only Safe is allowed until authorization and an isolation proof are in place"
    )]
    IntensityRefused {
        /// The intensity the capability reported.
        got: crate::intensity::Intensity,
    },
}

/// The result type carried through a security test.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intensity::Intensity;

    /// Guard: the refusal message names the offending intensity and the allowed
    /// one, so a user reads what to do. Mutation: drop `{got:?}` or the "Safe"
    /// mention -> this fails.
    #[test]
    fn intensity_refused_message_names_the_intensity_and_safe() {
        let message = Error::IntensityRefused {
            got: Intensity::Aggressive,
        }
        .to_string();
        assert!(
            message.contains("Aggressive"),
            "names the intensity: {message:?}"
        );
        assert!(
            message.contains("Safe"),
            "names the allowed rung: {message:?}"
        );
    }
}
