//! The immutable, capability-neutral record one capability execution emits, and
//! the append-only store a run collects them into (ADR-0004).
//!
//! ADR-0004 makes the evidence record the single source of truth: every report
//! and the later attack graph are projections of it, so it serializes (Decision
//! E's canonical JSON is its export form). The record is capability-neutral: the
//! observed value is erased to a `serde_json::Value`, so a capability whose
//! observation is not a bool stores it without a lossy coercion (this is the
//! reshape #10 asked for, away from the #3 placeholder's `reachable: bool`).
//!
//! The record holds the observed *fact*, not a verdict: per ADR-0010 a `Verdict`
//! is the oracle's judgement over an observation, and the same observation can be
//! a `Pass` or a `Fail` depending on the expectation, so a verdict cannot live in
//! the fact. ADR-0004's planned `result: Outcome` is retired here rather than
//! renamed; the link from a judgement back to its evidence is built on top in #14
//! (the [`DraftRef`] a judgement carries, resolved by the runner; see the
//! ADR-0010 note), not by this record itself.
//!
//! A capability cannot know the id or the timestamp of its own record, so it
//! produces a pure [`EvidenceDraft`] and the store stamps both on append: the id
//! is the next sequential index, and the timestamp is a clock value the runner
//! supplies when it drains the test's drafts (so the store itself stays pure and
//! testable, the reason #4 kept a timestamp off the record). The id is therefore
//! deterministic, and the timestamp is *collection* time, not the time the action
//! ran: all of a test's drafts are stamped together after the body returns.
//! `EvidenceId`, not the timestamp, is the ordering key.

use serde::{Deserialize, Serialize};

use crate::intensity::Intensity;
use crate::observation::Confidence;

/// A record's identity within one run: a sequential index the store assigns on
/// append. Run-scoped and deterministic (not a UUID), so a success witness
/// (ADR-0022) can pin a stable reference and tests can assert it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceId(pub u64);

/// A per-test reference to a draft a capability produced, before the store mints
/// its run-scoped [`EvidenceId`]. Opaque: only `run` creates one (the index into
/// the test's draft sink) and only the runner resolves it, mapping it to the id
/// the store assigned when it drained that test's drafts. It links a judgement to
/// the evidence it rests on without the judgement having to know the run-scoped
/// id, which is not assigned until drain time (issue #14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DraftRef(usize);

impl DraftRef {
    /// The index of this draft within its test, assigned by `run` as it records.
    pub(crate) fn new(index: usize) -> Self {
        Self(index)
    }

    /// The per-test index, which the runner offsets by the test's base id.
    pub(crate) fn index(self) -> usize {
        self.0
    }
}

/// Enough to re-run the same action, which a success witness (ADR-0022) lifts
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
    /// fits the one record (ADR-0004). For a reachability capability this is a
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
/// the canonical JSON project from (ADR-0004, ADR-0005), so it serializes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Its identity within the run.
    pub id: EvidenceId,
    /// When the store *recorded* it, as epoch milliseconds, stamped from a clock
    /// the runner supplies on append. This is collection time, not the time the
    /// action ran: all of a test's records are stamped together when the runner
    /// drains them, so a consumer must order by [`EvidenceId`], not by this.
    pub recorded_at_ms: u64,
    /// The capability that produced it.
    pub capability: String,
    /// The target it acted on, as `host:port`.
    pub target: String,
    /// The force it applied.
    pub intensity: Intensity,
    /// The observed value, neutral as a JSON value (ADR-0004).
    pub observed: serde_json::Value,
    /// How much to trust the observation.
    pub confidence: Confidence,
    /// A short human label for the observation.
    pub summary: String,
    /// Enough to re-run the action.
    pub reproduction: Reproduction,
}

/// A run's evidence: append-only, the single source of truth (ADR-0004).
///
/// Append-only by construction. The only way to add a record is the
/// crate-internal `append` (the runner's collection path), and there is no API to
/// remove or mutate one, so no code can rewrite or drop an earlier record of a
/// store built in process. This holds for a live store; it is not a claim about a
/// store read back from JSON, whose ids are trusted as produced and not
/// re-validated against their positions. It serializes so a run's evidence
/// round-trips (ADR-0005).
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

    /// Guard: the store assigns sequential, run-scoped ids starting at 0, grows
    /// with each append, and `append` returns the id it assigned. Mutation: make
    /// `append` use a constant id -> the second id is not 1 -> fails; return a
    /// different id than it stored -> fails; make `len` return `len()+1` or
    /// `is_empty` return a constant -> the size assertions fail.
    #[test]
    fn evidence_ids_are_sequential() {
        let mut store = EvidenceStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        let first = store.append(draft("web:80", true), 1_000);
        let second = store.append(draft("db:5432", false), 2_000);

        assert_eq!(first, EvidenceId(0));
        assert_eq!(second, EvidenceId(1));
        assert_eq!(store.records()[0].id, EvidenceId(0));
        assert_eq!(store.records()[1].id, EvidenceId(1));
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
    }

    /// Guard: an appended record carries *every* draft field verbatim plus the
    /// stamped id and timestamp. The draft uses non-default values (`Controlled`,
    /// `Medium`, a reproduction whose capability differs from the record's and
    /// distinctive params) so a hard-coded value cannot pass as a copied one.
    /// Mutation: hard-code any field in the `Evidence` built by `append` (e.g.
    /// `intensity: Safe`, `confidence: High`, or replace the reproduction) ->
    /// this fails.
    #[test]
    fn append_stamps_identity_onto_the_draft() {
        let mut store = EvidenceStore::new();
        let drafted = EvidenceDraft {
            capability: "http_header",
            target: "api:443".to_owned(),
            intensity: Intensity::Controlled,
            observed: serde_json::json!({ "header": "X-Frame-Options", "present": false }),
            confidence: Confidence::Medium,
            summary: "missing security header".to_owned(),
            reproduction: Reproduction {
                capability: "http_header_probe".to_owned(),
                target: "api:443".to_owned(),
                params: serde_json::json!({ "header": "X-Frame-Options" }),
            },
        };
        store.append(drafted, 1_234);
        let record = &store.records()[0];

        assert_eq!(record.id, EvidenceId(0));
        assert_eq!(record.recorded_at_ms, 1_234);
        assert_eq!(record.capability, "http_header");
        assert_eq!(record.target, "api:443");
        assert_eq!(record.intensity, Intensity::Controlled);
        assert_eq!(
            record.observed,
            serde_json::json!({ "header": "X-Frame-Options", "present": false })
        );
        assert_eq!(record.confidence, Confidence::Medium);
        assert_eq!(record.summary, "missing security header");
        assert_eq!(record.reproduction.capability, "http_header_probe");
        assert_eq!(record.reproduction.target, "api:443");
        assert_eq!(
            record.reproduction.params,
            serde_json::json!({ "header": "X-Frame-Options" })
        );
    }

    /// Guard: a record round-trips through JSON unchanged, so no field is dropped
    /// from the canonical JSON ADR-0005 treats as a published contract.
    /// Mutation: add `#[serde(skip)]` to any `Evidence` field -> the field is
    /// dropped on the way out, and on the way in the deserialize either fails (a
    /// field whose type has no `Default`, like `Intensity`) or round-trips to a
    /// different value -> this fails either way.
    #[test]
    fn evidence_round_trips_through_json() {
        let mut store = EvidenceStore::new();
        store.append(draft("web:80", false), 42);
        let record = store.records()[0].clone();

        let json = serde_json::to_string(&record).expect("serialize");
        let back: Evidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    /// Guard: the whole store round-trips (ADR-0005 projects it), so a run's
    /// evidence survives serialization. Mutation: `#[serde(skip)]` on
    /// `EvidenceStore::records` -> the records are lost and the deserialize either
    /// fails or produces an empty store -> fails.
    #[test]
    fn store_round_trips_through_json() {
        let mut store = EvidenceStore::new();
        store.append(draft("web:80", true), 1);
        store.append(draft("db:5432", false), 2);

        let json = serde_json::to_string(&store).expect("serialize");
        let back: EvidenceStore = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(store, back);
    }

    /// Guard: the record's exact JSON shape, the contract ADR-0005 treats as
    /// published. Round-trip alone cannot catch a renamed key or enum variant
    /// (the rename is symmetric), so this pins every key and the `Intensity` /
    /// `Confidence` variant spellings against a literal. It also exercises
    /// `Controlled` and `Medium`, which no other test serializes. Mutation:
    /// `#[serde(rename = ...)]` on any field (e.g. `recorded_at_ms`) or on
    /// `Intensity::Controlled` / `Confidence::Medium` -> the key or spelling
    /// changes -> fails.
    #[test]
    fn evidence_serializes_to_the_expected_json_shape() {
        let mut store = EvidenceStore::new();
        store.append(
            EvidenceDraft {
                capability: "http_header",
                target: "api:443".to_owned(),
                intensity: Intensity::Controlled,
                observed: serde_json::Value::Bool(false),
                confidence: Confidence::Medium,
                summary: "missing".to_owned(),
                reproduction: Reproduction {
                    capability: "probe".to_owned(),
                    target: "api:443".to_owned(),
                    params: serde_json::json!({ "k": 1 }),
                },
            },
            1_700_000_000_000,
        );

        let value = serde_json::to_value(&store.records()[0]).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({
                "id": 0,
                "recorded_at_ms": 1_700_000_000_000u64,
                "capability": "http_header",
                "target": "api:443",
                "intensity": "Controlled",
                "observed": false,
                "confidence": "Medium",
                "summary": "missing",
                "reproduction": { "capability": "probe", "target": "api:443", "params": { "k": 1 } }
            })
        );
    }
}
