---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Capture a success witness and generate a pinned replay from it

## Context and Problem Statement

Real tools make discovery flaky, but if the exact conditions of the moment an attack succeeded are captured and pinned, re-verifying them is deterministic. The core principle: finding an attack path is non-deterministic, but re-checking a found condition is deterministic (like finding a proof versus checking one).

## Decision Drivers

* Discovery (fuzzing, brute force, AI free exploration) is slow and flaky, so it stays informational (ADR-0014).
* A captured success condition replays deterministically and can gate, restoring the regression value ADR-0014 set aside.
* The witness is exactly the ADR-0004 evidence `reproduction`; the ADR-0015 promotion codifies the replay.

## Considered Options

* Option 1: treat every attack test as flaky and never gate.
* Option 2: a two-layer model, discovery (flaky, non-gating) and replay (deterministic, gatable), with a captured success witness and an auto-generated pinned replay.

## Decision Outcome

Chosen: Option 2. A discovery test finds the success condition (flaky, informational). When the oracle (ADR-0010) observes an attack success (a security FAIL), it captures the success witness: the minimal exact condition to reproduce it (endpoint, payload, foothold/credentials used, data-pack version, seed). The witness is the ADR-0004 `reproduction`. A pinned replay test is auto-generated from it (ADR-0015's codify step), and because it is deterministic it can gate, so CI catches a known-vulnerability regression. Caveat: a genuine race/timing attack may still be probabilistic even pinned, so its witness is still captured and reported but its replay is informational, not gating; the framework classifies whether a replay is deterministic. This is a later M1 slice and Phase 5; #29 (a first-class evidence `source` and a faithful replay witness) is its first piece.

### Confirmation

Nothing yet. No witness capture or replay generation is built; #29 is the first piece, and the `reproduction` field on the evidence record (ADR-0004) is the foundation it will build on. When built, the ADR names the guard (a pinned replay re-run reproduces the same observation).

### Consequences

* Good, the deterministic part of attack testing becomes a reliable regression gate, recovering the CI value ADR-0014 set aside, and discovery feeds it through ADR-0015.
* Bad, the witness schema, its minimization, the deterministic-replay classification, and the replay's generated form are undesigned; the current evidence `reproduction` is not yet a faithful replay witness (#29).
* What would reverse this: discovery proving deterministic enough to gate directly (it is not), which is why the witness/replay split exists.

## Pros and Cons of the Options

### Option 1 (never gate)

* Good, honest about flakiness. Bad, loses all regression gating, even for known conditions.

### Option 2 (witness + pinned replay)

* Good, discovery stays informational while a pinned replay gates a known vulnerability. Bad, the witness and replay machinery is deferred design.

## More Information

Was "Decision V" in the retired `design-decisions.md`; its first piece is #29. Code foundation: `crates/redstep/src/evidence.rs` (`Reproduction`). Open: the witness schema, minimization, deterministic-replay classification, the generated replay form. See ADR-0010 (the oracle that captures it), ADR-0004 (the reproduction it is), ADR-0014 (the gating it restores), ADR-0015 (the promotion that codifies it).
