//! A normalized signal from a capability, and how much to trust it.
//!
//! Pure model type. This is the minimal shape of Decision J's observation: a
//! typed value plus a confidence. Corroboration across individual signals
//! (deferred, Decision J) will later raise or lower the confidence; for now a
//! capability sets it directly.

/// How much to trust an observation. A single weak signal is `Low`, so the
/// oracle requires `High` by default before a conclusion rests on it, and a
/// transient result (a timeout) cannot read as a confident answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Unambiguous for the capability that set it: a completed handshake, or a
    /// connection the target explicitly refused. Corroboration across signals
    /// (deferred, Decision J) is not yet a source of this.
    High,
    /// Plausible, not certain.
    Medium,
    /// A single weak or transient signal.
    Low,
}

impl Confidence {
    /// Whether this is at least as strong as `minimum`. The variants are
    /// declared strongest first, so a derived `Ord` would be reversed; this
    /// ranks them explicitly instead (`High` > `Medium` > `Low`).
    pub fn meets(self, minimum: Confidence) -> bool {
        self.rank() >= minimum.rank()
    }

    fn rank(self) -> u8 {
        match self {
            Confidence::High => 3,
            Confidence::Medium => 2,
            Confidence::Low => 1,
        }
    }
}

/// What a capability observed, and how much to trust it. For a reachability
/// capability `T` is `bool`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation<T> {
    /// The observed value.
    pub value: T,
    /// How much to trust it.
    pub confidence: Confidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard: `meets` is "at least as strong", not reversed. Mutation: derive
    /// `Ord` on the strongest-first declaration and compare with `>=`, or flip
    /// the `rank` order -> `High.meets(Low)` and `Low.meets(High)` swap -> fails.
    #[test]
    fn confidence_meets_is_not_reversed() {
        assert!(Confidence::High.meets(Confidence::Low));
        assert!(Confidence::High.meets(Confidence::High));
        assert!(!Confidence::Low.meets(Confidence::High));
        assert!(Confidence::Medium.meets(Confidence::Low));
        assert!(!Confidence::Low.meets(Confidence::Medium));
        // High outranks Medium (so a High/Medium rank swap is caught):
        assert!(Confidence::High.meets(Confidence::Medium));
        assert!(!Confidence::Medium.meets(Confidence::High));
    }
}
