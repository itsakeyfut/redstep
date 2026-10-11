//! The security verdict: whether what was observed is acceptable (Decision J).
//!
//! Pure model type, and the sign-inverted counterpart of an observation. An
//! observation says what happened (reachable, a row returned); a verdict says
//! whether that is acceptable, and the sign flips: an attack that succeeded is
//! a `Fail`, a boundary that held is a `Pass`. It is three-valued plus `Error`
//! so a weak or conflicting signal lands in `Inconclusive` rather than a false
//! `Pass` or `Fail` (See Decision J).

/// Whether what a test observed is acceptable.
///
/// `#[non_exhaustive]`, so a downstream match needs a wildcard; inside this
/// crate the matches are total, so a new variant is a compile error at each
/// decision site (docs/rules/design.md section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// What was observed is acceptable: the boundary held, the attack failed.
    Pass,
    /// What was observed is not acceptable: the attack succeeded, the boundary
    /// did not hold.
    Fail,
    /// The signal was too weak or conflicting to conclude. Not a `Pass`: an
    /// unconfirmed result must not read as safe (CLAUDE.md row 6).
    Inconclusive,
    /// The test could not run to a verdict: it errored or panicked.
    Error,
}

impl Verdict {
    /// A short label for a report line.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Inconclusive => "INCONCLUSIVE",
            Verdict::Error => "ERROR",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard: each verdict has its own label. Mutation: return the same label
    /// for every variant -> fails. The label is what a reader greps for.
    #[test]
    fn verdict_labels_are_distinct() {
        assert_eq!(Verdict::Pass.label(), "PASS");
        assert_eq!(Verdict::Fail.label(), "FAIL");
        assert_eq!(Verdict::Inconclusive.label(), "INCONCLUSIVE");
        assert_eq!(Verdict::Error.label(), "ERROR");
    }
}
