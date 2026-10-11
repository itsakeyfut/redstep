//! What a test expects of an observation, and the oracle that judges it
//! (Decision J).
//!
//! Pure model layer. An [`Expectation`] is the declared, acceptable value plus
//! an optional minimum confidence. [`judge`] compares an [`Observation`] against
//! it and yields a [`Judgement`]: a [`Verdict`] and the machine-readable reason
//! (expected vs actual) the report renders.

use std::fmt::Debug;

use crate::observation::{Confidence, Observation};
use crate::verdict::Verdict;

/// What a test declares it expects: the acceptable value, and how confident the
/// observation must be before a verdict rests on it.
///
/// The sign is here. A test declares the *safe* value (for the boundary demo,
/// `reachable` to be `false`), so an attack that succeeded (`reachable == true`)
/// is a mismatch and a `Fail`. See Decision J.
pub struct Expectation<T> {
    expected: T,
    min_confidence: Confidence,
}

impl<T> Expectation<T> {
    /// Expect this value, accepting any confidence (the gate is off).
    pub fn to_be(expected: T) -> Self {
        Self {
            expected,
            min_confidence: Confidence::Low,
        }
    }

    /// Require at least this confidence; a weaker observation is `Inconclusive`.
    pub fn min_confidence(mut self, minimum: Confidence) -> Self {
        self.min_confidence = minimum;
        self
    }
}

/// A judged expectation: the verdict and why, in a form a report can render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    /// The verdict this expectation produced (`Pass`, `Fail`, or `Inconclusive`;
    /// never `Error`, which is a run-level state the runner sets).
    pub verdict: Verdict,
    /// The expected value, as the test declared it.
    pub expected: String,
    /// The observed value.
    pub actual: String,
    /// The confidence of the observation.
    pub confidence: Confidence,
}

/// Compare an observation against an expectation.
///
/// A signal below the required confidence is `Inconclusive`, whatever its value,
/// so a weak signal cannot read as a confident `Pass` or `Fail`. Otherwise a
/// value that matches the expectation is a `Pass`, and a mismatch is a `Fail`.
pub fn judge<T: PartialEq + Debug>(
    observation: &Observation<T>,
    expectation: &Expectation<T>,
) -> Judgement {
    let verdict = if !observation.confidence.meets(expectation.min_confidence) {
        Verdict::Inconclusive
    } else if observation.value == expectation.expected {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    Judgement {
        verdict,
        expected: format!("{:?}", expectation.expected),
        actual: format!("{:?}", observation.value),
        confidence: observation.confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(value: bool, confidence: Confidence) -> Observation<bool> {
        Observation { value, confidence }
    }

    /// Guard: an attack that succeeded (an observation that does not match the
    /// safe expected value) is a Fail, and a boundary that held is a Pass.
    /// Mutation: flip the `==` in `judge` -> both of these fail.
    #[test]
    fn attack_success_is_fail_and_boundary_hold_is_pass() {
        let expect_unreachable = Expectation::to_be(false);
        assert_eq!(
            judge(&observed(true, Confidence::High), &expect_unreachable).verdict,
            Verdict::Fail,
            "reachable=true against expected-false is a security FAIL"
        );
        assert_eq!(
            judge(&observed(false, Confidence::High), &expect_unreachable).verdict,
            Verdict::Pass,
            "reachable=false against expected-false is a PASS"
        );
    }

    /// Guard: an observation below the required confidence is Inconclusive, not
    /// a Pass or Fail. Mutation: drop the `meets` gate in `judge` -> a Low
    /// observation becomes a confident Pass/Fail -> fails. (The AC case.)
    #[test]
    fn below_min_confidence_is_inconclusive() {
        let strict = Expectation::to_be(false).min_confidence(Confidence::High);
        // A Low observation that would otherwise Pass:
        assert_eq!(
            judge(&observed(false, Confidence::Low), &strict).verdict,
            Verdict::Inconclusive
        );
        // and one that would otherwise Fail:
        assert_eq!(
            judge(&observed(true, Confidence::Low), &strict).verdict,
            Verdict::Inconclusive
        );
    }

    /// Guard: the judgement records the expected and actual values for the
    /// report. Mutation: swap `expected` and `actual` in `judge` -> fails.
    #[test]
    fn judgement_carries_expected_and_actual() {
        let judgement = judge(
            &observed(true, Confidence::High),
            &Expectation::to_be(false),
        );
        assert_eq!(judgement.expected, "false");
        assert_eq!(judgement.actual, "true");
        assert_eq!(judgement.confidence, Confidence::High);
    }
}
