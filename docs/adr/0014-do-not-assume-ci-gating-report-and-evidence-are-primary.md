---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Do not assume CI gating; make report and evidence the primary output

## Context and Problem Statement

With non-deterministic, slow real attack tools, what execution and trust model does redstep offer? A flaky green/red merge gate does not fit tools that misfire and take time.

## Decision Drivers

* Real attack tools are inherently flaky and slow, so they do not suit a `cargo test`-style merge gate that blocks a merge on red.
* A flaky signal must fall to `Inconclusive` (ADR-0010), not a false Fail.
* Determinism aids (seed, timeout, retry, scan profiles) can be offered but not guaranteed.

## Considered Options

* Option 1: a required CI gate, like `cargo test`.
* Option 2: no CI at all.
* Option 3: CI gating not assumed; report + evidence are the primary output, CI integration is optional and informational.

## Decision Outcome

Chosen: Option 3. The primary output is the report and evidence (ADR-0004, ADR-0005); running in CI is supported but optional and informational, not a required gate. Flaky signals fall to `Inconclusive` rather than a false Fail. This downgrades the earlier "CI-native required gate" to optional informational integration. ADR-0022 (the pinned replay) refines this into two layers: discovery is non-gating, but a pinned replay of a captured success witness is deterministic and *can* gate, so CI can reliably catch a known-vulnerability regression. So: discovery = non-gating, regression of a known condition = gatable.

### Confirmation

The deterministic runner's exit is realized and held by the ADR-0010 exit guards in `crates/redstep/src/runner.rs` (`Inconclusive` is non-zero, fail-closed, so a flaky result does not read as a green gate). The informational-discovery vs gatable-replay split is not built (no flaky real tools yet, no replay pipeline); it lands with ADR-0022 in Phase 5, confirmed by nothing yet.

### Consequences

* Good, the framework does not force flaky tools into a brittle gate, yet the deterministic parts (and later the pinned replay) can still gate reliably.
* Bad, the discovery/replay two-layer treatment is deferred until the replay pipeline exists.
* What would reverse this: real tools proving deterministic enough for a required gate (they are not), or dropping CI support (it stays, as informational).

## Pros and Cons of the Options

### Option 1 (required gate)

* Good, familiar. Bad, a flaky tool makes the gate itself flaky and untrusted.

### Option 3 (report-first, optional CI)

* Good, honest about flakiness, and the deterministic/replay parts still gate. Bad, two treatments to keep straight.

## More Information

Was "Decision O" in the retired `design-decisions.md`. Open: the default Inconclusive aggregation for CI, the informational display, how far a replay seed carries. See ADR-0010 (the three-valued verdict) and ADR-0022 (the pinned replay that restores gatable regression).
