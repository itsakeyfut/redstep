//! The security verdict: whether what was observed is acceptable (Decision J).
//!
//! Pure model type, and the sign-inverted counterpart of an observation. An
//! observation says what happened (reachable, a row returned); a verdict says
//! whether that is acceptable, and the sign flips: an attack that succeeded is
//! a `Fail`, a boundary that held is a `Pass`. It is three-valued plus `Error`
//! so a weak signal lands in `Inconclusive` rather than a false `Pass` or
//! `Fail` (See Decision J). Conflict handling across several signals is
//! deferred (that is corroboration, Decision J); here a single signal's
//! confidence is what distinguishes a weak one.

/// Whether what a test observed is acceptable.
///
/// `#[non_exhaustive]`, so a downstream match needs a wildcard. Inside this
/// crate `label` and `severity` match it totally, so a new variant is a compile
/// error there (docs/rules/design.md section 5), and `aggregate` and the run
/// precedence are built on `severity` rather than on an open `else`, so a new
/// variant cannot silently fall through to `Pass`. `exit_code` compares to
/// `Pass` and so fails closed for any new variant.
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

    /// How much a verdict dominates when results combine: a confirmed `Fail`
    /// outranks an `Error` (a finding is worse than a run that could not
    /// finish), which outranks `Inconclusive` (could not run beats proved
    /// nothing), which outranks `Pass`. The aggregate and the run precedence are
    /// the max over this, so the fail-closed ordering is in one place and a new
    /// `Verdict` variant is a compile error here rather than a silent `Pass`.
    pub(crate) fn severity(self) -> u8 {
        match self {
            Verdict::Fail => 3,
            Verdict::Error => 2,
            Verdict::Inconclusive => 1,
            Verdict::Pass => 0,
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

    /// Guard: a confirmed Fail dominates Error dominates Inconclusive dominates
    /// Pass, so the fail-closed ordering holds wherever results combine.
    /// Mutation: give Pass a higher severity than Fail, or flatten two ranks ->
    /// fails.
    #[test]
    fn severity_is_fail_over_error_over_inconclusive_over_pass() {
        assert!(Verdict::Fail.severity() > Verdict::Error.severity());
        assert!(Verdict::Error.severity() > Verdict::Inconclusive.severity());
        assert!(Verdict::Inconclusive.severity() > Verdict::Pass.severity());
    }
}
