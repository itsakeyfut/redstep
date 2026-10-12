---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Render every report from one canonical JSON

## Context and Problem Statement

From the evidence (the single truth, ADR-0004), how are the human-readable report, JSON, SARIF, and the attack-graph view generated? SARIF is built for static analysis and does not natively express a multi-step attack path, which has to be handled.

## Decision Drivers

* Each output must be a projection of the one truth, so formats cannot drift.
* A general template engine is more than the MVP needs; it can be added over the canonical JSON later.
* The canonical JSON itself is the external-integration API and the CI gate's input.

## Considered Options

* Option 1: direct renderers, each output built straight from the evidence store (they drift).
* Option 2: canonical JSON pivot, serialize evidence and graph to one canonical schema and render every format from it.
* Option 3: a general template engine.

## Decision Outcome

Chosen: Option 2. Evidence and graph serialize to one canonical JSON, the single intermediate representation; terminal, SARIF, and HTML are thin renderers over it. The canonical JSON is the integration API, and the CI merge gate judges from its exit code. SARIF mapping: one FAILed expectation is one SARIF `result`, each attack step a `codeFlows[].threadFlows[].locations[]`, reproduction and evidence id in `properties`. MVP: terminal + canonical JSON only; SARIF and HTML are Phase 6.

MVP shape (first built here): `report::build` projects one `Report { schema_version, results, evidence, exit_code }` from a `RunSummary`; `report::to_json` and `report::render_terminal` are the two renderers over it, so the file and the terminal cannot diverge. The published types carry `schema_version` and are `#[non_exhaustive]`. A `TestResult` is one test (`test`, `verdict` as the `Verdict::label` string, `reasons`, `error`, `evidence_ids` as a list, so corroboration does not force a scalar-to-array break later). `exit_code` is carried from `RunSummary::exit_code`, so a CI gate does not re-derive the fail-closed rule.

### Confirmation

Guarded in `crates/redstep/src/report.rs` (and `tests/public_api.rs`): `canonical_json_pins_the_results` pins the wire shape, `report_exit_code_matches_the_verdicts` holds that `exit_code` comes from the summary (mutation: re-derive it differently in `build`), `terminal_matches_the_snapshot` holds the two renderers against one `Report`, and `every_cited_evidence_id_resolves` holds that each cited id resolves to a record. SARIF and HTML are not built, so nothing confirms them (Phase 6).

### Consequences

* Good, one intermediate representation, so no format can disagree with another; the JSON is a stable integration/gate surface.
* Bad, the canonical schema is now a published contract (`schema_version`, `#[non_exhaustive]`), so it must grow compatibly.
* What would reverse this: direct renderers proving sufficient (they drift, the fatal weakness) or a template engine becoming warranted (addable on top later).

## Pros and Cons of the Options

### Option 1 (direct renderers)

* Good, fewer layers. Bad, formats drift, the fatal weakness.

### Option 2 (canonical JSON pivot)

* Good, one representation, no drift, a gate surface. Bad, a contract to version.

### Option 3 (template engine)

* Good, flexible. Bad, over-engineered for the MVP; addable later over the JSON.

## More Information

Was "Decision E" in the retired `design-decisions.md`; settled in #6. Code: `crates/redstep/src/report.rs`, `crates/redstep/src/main.rs`. Open: the SARIF severity mapping, the HTML implementation, CI annotation formats.
