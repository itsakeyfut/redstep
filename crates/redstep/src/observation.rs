//! A normalized signal from a capability, and how much to trust it.
//!
//! Pure model type. This is the minimal shape of Decision J's observation: a
//! typed value plus a confidence. The oracle unit (#4) enriches it with the
//! individual signals and the corroboration that raise or lower the confidence;
//! here a capability sets the confidence directly.

/// How much to trust an observation. A single weak signal is `Low`, so the
/// oracle (#4) can require `High` before a conclusion rests on it, and a
/// transient result (a timeout) cannot read as a confident answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Unambiguous for the capability that set it: a completed handshake, or a
    /// connection the target explicitly refused. Corroboration across signals,
    /// which the oracle (#4) adds, is not yet a source of this.
    High,
    /// Plausible, not certain.
    Medium,
    /// A single weak or transient signal.
    Low,
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
