---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Record evidence as an append-only atomic fact, and project the attack graph from it

## Context and Problem Statement

What data model holds an attack result? The core of "evidence over simple PASS/FAIL". The two capability kinds (native, tool) must normalize into one container, and both a detailed evidence record (HTTP bodies, logs, pcap, reproduction) and an attack graph (facts joined into a structure) are needed, which are different things.

## Decision Drivers

* Evidence is an atomic fact; an attack graph is a structure over facts; keeping one loses the other.
* Making evidence the single source of truth lets reports, JSON, SARIF, and the graph all be projections of one layer, the least breakable shape.
* It must receive the output of the unified `Capability` (ADR-0002).

## Considered Options

* Option 1: a flat log (loses the graph).
* Option 2: graph-first (thins the atomic evidence).
* Option 3: layered, an append-only immutable evidence record as the single truth, with the attack graph a projection whose nodes/edges reference evidence ids.

## Decision Outcome

Chosen: Option 3. The lower layer is the append-only, immutable `Evidence` record, one atomic fact per capability execution, normalized identically for native and tool paths. The upper layer is the attack graph, a projection that only references evidence ids. MVP emits evidence records only; the graph is derived for scenarios later.

MVP shape (first built here): a capability produces a pure `EvidenceDraft` (capability, target, intensity, observed, confidence, summary, reproduction) with no id or timestamp. The run-level `EvidenceStore::append` stamps a run-scoped sequential `EvidenceId` and a timestamp (the runner supplies the clock, so the store stays pure), producing the immutable `Evidence`; the store exposes append (crate-internal) and read only, so the append-only invariant is compiler-held. The observed value is capability-neutral (`serde_json::Value` + `Confidence` + summary), not a `TcpConnect`-specific bool. The record holds the observation, not a verdict (the `Verdict` lives in `Judgement`, ADR-0010, linked by evidence id). `source` is a `NodeRef` set by its producer: the vantage probe records `Some(NodeRef::Vantage { segment })` and a host-run native record `None` (#29); `artifacts` and the full node taxonomy (host, privilege, credential) stay deferred to their producers.

### Confirmation

The exact JSON shape is pinned by `evidence_serializes_to_the_expected_json_shape` in `crates/redstep/src/evidence.rs`, which now also pins the `source` key and the `NodeRef::Vantage` wire shape (a renamed key or variant fails it, where a round-trip would not). That the vantage producer sets `source` is guarded by `vantage_draft_names_its_source_and_witness` in `orchestrator.rs` (mutation: `source: None` in `vantage_draft` -> it fails). The append-only invariant is compiler-held (no mutate/remove method on `EvidenceStore`). One-draft-per-execution is guarded by `run_records_exactly_one_evidence_draft` in `context.rs`, and the run-scoped id resolution by `run_links_judgements_to_their_evidence` in `tests/public_api.rs` (mutation: drop the per-test base, so a later test's link resolves to id 0).

### Consequences

* Good, one source of truth; every output is a projection, so formats cannot drift.
* Bad, `artifacts` and the full node taxonomy are placeholders until their producers exist; `source` is set by the vantage producer (#29) but not yet by others.
* What would reverse this: a flat log or a graph-first model proving enough (each loses one half).

## Pros and Cons of the Options

### Option 1 (flat log)

* Good, simple. Bad, no structure, so no attack graph.

### Option 2 (graph-first)

* Good, structure is primary. Bad, the atomic evidence (bodies, pcap, reproduction) is thinned.

### Option 3 (layered)

* Good, keeps both and makes every output a projection. Bad, two layers to keep in correspondence.

## More Information

Was "Decision D" in the retired `design-decisions.md`; the record reshaped in #5, the judgement link in #14. Code: `crates/redstep/src/evidence.rs`, `crates/redstep/src/context.rs`. Open: the artifact and reproduction types, the graph node taxonomy, persistence beyond in-memory + JSON.
