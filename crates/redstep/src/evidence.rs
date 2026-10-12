//! The immutable, capability-neutral record one capability execution emits, and
//! the append-only store a run collects them into (Decision D).
//!
//! Decision D makes the evidence record the single source of truth: every report
//! and the later attack graph are projections of it, so it serializes (Decision
//! E's canonical JSON is its export form). The record is capability-neutral: the
//! observed value is erased to a `serde_json::Value`, so a capability whose
//! observation is not a bool stores it without a lossy coercion (this is the
//! reshape #10 asked for, away from the #3 placeholder's `reachable: bool`).
//!
//! The record holds the observed *fact*, not a verdict: per Decision J a `Verdict`
//! is the oracle's judgement over an observation, and the same observation can be
//! a `Pass` or a `Fail` depending on the expectation, so a verdict cannot live in
//! the fact. Decision D's planned `result: Outcome` is retired here rather than
//! renamed; the link from a judgement back to its evidence is a later step before
//! reporting (Decision J's forward note), not this unit.
//!
//! A capability cannot know the id or the timestamp of its own record, so it
//! produces a pure [`EvidenceDraft`] and the store stamps both on
//! [`EvidenceStore::append`]. That keeps the capability's output deterministic
//! and testable (the reason #4 kept a timestamp off the record), and puts the
//! two non-deterministic fields at the one place that owns them.

use serde::{Deserialize, Serialize};

use crate::intensity::Intensity;
use crate::observation::Confidence;

/// A record's identity within one run: a sequential index the store assigns on
/// append. Run-scoped and deterministic (not a UUID), so a success witness
/// (Decision V) can pin a stable reference and tests can assert it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceId(pub u64);

/// Enough to re-run the same action, which a success witness (Decision V) lifts
/// out wholesale. It restates the capability and target (also on the [`Evidence`])
/// on purpose, so the reproduction is self-contained rather than a reference into
/// its parent record. `params` is the capability-specific input, kept neutral as
/// a JSON value (for `TcpConnect`, `{"timeout_ms": N}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reproduction {
    /// The capability to re-run, e.g. `"tcp_connect"`.
    pub capability: String,
    /// The target to re-run it against, as `host:port`.
    pub target: String,
    /// The capability-specific inputs, neutral as a JSON value.
    pub params: serde_json::Value,
}

/// What one capability execution produces, before the store gives it an identity:
/// a pure, deterministic value with no id and no timestamp. The capability erases
/// its own observed value to a `serde_json::Value` (it knows the type), so the
/// draft is capability-neutral.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceDraft {
    /// The capability that produced it, e.g. `"tcp_connect"`.
    pub capability: &'static str,
    /// The target it acted on, as `host:port`.
    pub target: String,
    /// The force it applied.
    pub intensity: Intensity,
    /// The observed value, erased to a JSON value so any capability's observation
    /// fits the one record (Decision D). For a reachability capability this is a
    /// bool; for a credential find it is the found value.
    pub observed: serde_json::Value,
    /// How much to trust the observation (mirrors the [`Observation`](crate::Observation)).
    pub confidence: Confidence,
    /// A short human label for the observation, e.g. `"reachable"`.
    pub summary: String,
    /// Enough to re-run the action.
    pub reproduction: Reproduction,
}

/// The immutable record the store holds: an [`EvidenceDraft`] the store has given
/// an [`EvidenceId`] and a timestamp. The single source of truth every report and
/// the canonical JSON project from (Decision D, E), so it serializes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Its identity within the run.
    pub id: EvidenceId,
    /// When the store recorded it, as epoch milliseconds. The store stamps this
    /// from a clock the runner supplies on append.
    pub recorded_at_ms: u64,
    /// The capability that produced it.
    pub capability: String,
    /// The target it acted on, as `host:port`.
    pub target: String,
    /// The force it applied.
    pub intensity: Intensity,
    /// The observed value, neutral as a JSON value (Decision D).
    pub observed: serde_json::Value,
    /// How much to trust the observation.
    pub confidence: Confidence,
    /// A short human label for the observation.
    pub summary: String,
    /// Enough to re-run the action.
    pub reproduction: Reproduction,
}

/// A run's evidence: append-only, the single source of truth (Decision D).
///
/// Append-only by construction. The only way to add a record is the
/// crate-internal `append` (the runner's collection path), and there is no API to
/// remove or mutate one, so immutability is held by the compiler rather than by a
/// convention a reader has to trust. It serializes so a run's evidence round-trips
/// (Decision E).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EvidenceStore {
    records: Vec<Evidence>,
}

impl EvidenceStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a draft, stamping the next sequential [`EvidenceId`] and
    /// `recorded_at_ms`, and return the id. The timestamp is a parameter, not read
    /// from a clock here, so the store stays pure and deterministic: the runner
    /// owns the one `SystemTime::now()` call. Crate-internal, so a record can only
    /// enter the store through the runner's collection path.
    pub(crate) fn append(&mut self, draft: EvidenceDraft, recorded_at_ms: u64) -> EvidenceId {
        let id = EvidenceId(self.records.len() as u64);
        self.records.push(Evidence {
            id,
            recorded_at_ms,
            capability: draft.capability.to_owned(),
            target: draft.target,
            intensity: draft.intensity,
            observed: draft.observed,
            confidence: draft.confidence,
            summary: draft.summary,
            reproduction: draft.reproduction,
        });
        id
    }

    /// The records, in the order they were appended.
    pub fn records(&self) -> &[Evidence] {
        &self.records
    }

    /// How many records the store holds.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store holds no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A draft for `host:port` observing `value`, for the store tests.
    fn draft(target: &str, value: bool) -> EvidenceDraft {
        EvidenceDraft {
            capability: "tcp_connect",
            target: target.to_owned(),
            intensity: Intensity::Safe,
            observed: serde_json::Value::Bool(value),
            confidence: Confidence::High,
            summary: if value { "reachable" } else { "unreachable" }.to_owned(),
            reproduction: Reproduction {
                capability: "tcp_connect".to_owned(),
                target: target.to_owned(),
                params: serde_json::json!({ "timeout_ms": 5000 }),
            },
        }
    }

    /// Guard: the store assigns sequential, run-scoped ids starting at 0, and
    /// `append` returns the id it assigned. Mutation: make `append` use a constant
    /// id (e.g. `EvidenceId(0)`) -> the second id is not 1 -> fails; return a
    /// different id than it stored -> the stored record's id disagrees -> fails.
    #[test]
    fn evidence_ids_are_sequential() {
        let mut store = EvidenceStore::new();
        let first = store.append(draft("web:80", true), 1_000);
        let second = store.append(draft("db:5432", false), 2_000);

        assert_eq!(first, EvidenceId(0));
        assert_eq!(second, EvidenceId(1));
        assert_eq!(store.records()[0].id, EvidenceId(0));
        assert_eq!(store.records()[1].id, EvidenceId(1));
    }

    /// Guard: an appended record carries the draft's fields plus the stamped id
    /// and timestamp. Mutation: drop a field in the `Evidence` built by `append`
    /// (e.g. hard-code `summary`) -> this fails.
    #[test]
    fn append_stamps_identity_onto_the_draft() {
        let mut store = EvidenceStore::new();
        store.append(draft("web:80", true), 1_234);
        let record = &store.records()[0];

        assert_eq!(record.id, EvidenceId(0));
        assert_eq!(record.recorded_at_ms, 1_234);
        assert_eq!(record.capability, "tcp_connect");
        assert_eq!(record.target, "web:80");
        assert_eq!(record.observed, serde_json::Value::Bool(true));
        assert_eq!(record.summary, "reachable");
        assert_eq!(record.reproduction.target, "web:80");
    }

    /// Guard: a record round-trips through JSON unchanged, so no field is dropped
    /// from the canonical JSON Decision E treats as a published contract.
    /// Mutation: add `#[serde(skip)]` to any `Evidence` field -> the field is lost
    /// on the way out and defaults back on the way in -> the equality fails.
    #[test]
    fn evidence_round_trips_through_json() {
        let mut store = EvidenceStore::new();
        store.append(draft("web:80", false), 42);
        let record = store.records()[0].clone();

        let json = serde_json::to_string(&record).expect("serialize");
        let back: Evidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    /// Guard: the whole store round-trips (Decision E projects it), so a run's
    /// evidence survives serialization. Mutation: `#[serde(skip)]` on
    /// `EvidenceStore::records` -> the records are lost -> fails.
    #[test]
    fn store_round_trips_through_json() {
        let mut store = EvidenceStore::new();
        store.append(draft("web:80", true), 1);
        store.append(draft("db:5432", false), 2);

        let json = serde_json::to_string(&store).expect("serialize");
        let back: EvidenceStore = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(store, back);
    }
}
