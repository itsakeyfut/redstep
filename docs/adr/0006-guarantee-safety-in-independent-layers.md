---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Guarantee safety in independent layers, not one check

## Context and Problem Statement

The framework runs real attack weapons (metasploit, hydra, VPN and crypto cracking). A misfire is a real attack. What safety device reconciles "ruthless attacks in isolation" with "a legitimate test that never touches production"? This is the most important decision.

## Decision Drivers

* Entrusting safety to one check is inconsistent with running real weapons.
* Releasing a ruthless attack safely requires, at the base, that the attack physically cannot leave the lab.
* "Full force in isolation, never aimed at production" is only clean with independent layers.

## Considered Options

* Option 1: a single scope check.
* Option 2: scope plus an intensity flag.
* Option 3: defense-in-depth, independent layers where one failing still leaves another to stop the action.

## Decision Outcome

Chosen: Option 3. Four independent layers: (1) network isolation, the framework's ephemeral environment has no route to the internet or production by default (bollard builds egress-less networks, ADR-0003), so attack packets cannot leave; (2) the scope gate, every capability resolves its target through the scope resolver and a raw IP/URL is forbidden by type; (3) the intensity ladder, `Aggressive` runs only with explicit opt-in and an isolation proof, so it can never be aimed at a user-supplied external endpoint; (4) safe-by-default, default intensity `Safe`, default scope deny. MVP requires layers 1, 2, 4; the full layer 3 (the isolation-proof binding of Aggressive) lands with the Phase 4 tool adapters.

MVP shape (first built here): `Scope::from_environment(&Environment)` builds the allowlist from the lab's workload names, host membership on any port, because the lab is egress-less so any port on an in-lab host is still inside it. A target whose host is not a declared workload is `Error::OutOfScope`. The gate is membership, not reachability, and must not pre-enforce a boundary: a blocked path is observed as unreachable at run time by the capability (ADR-0011), never denied at the gate, because denying it would turn a scope denial into a false "the boundary held".

### Confirmation

The scope gate's exact membership is guarded in `crates/redstep/src/scope.rs`: `out_of_scope_target_is_rejected`, `empty_scope_should_allow_nothing`, and `environment_scope_denies_a_target_not_in_the_lab` with near-miss hosts (prefix, extension, substring, case). Mutation: `if true || allowed` in `resolve` fails all five. The intensity gate (layer 3's `Safe`-only rung) is compiler-held *outside* the crate (#9): the `Capability` trait is sealed and `execute` requires an `IntensityCleared` token whose field is private and whose constructor `issue` is crate-private, so external code can neither implement a capability (`E0277`) nor mint a token to run one; `compile_fail` doctests on `Capability` pin all three. In-crate the token is not bound to the capability's intensity, so the `Safe`-only rung is `run`'s convention (it mints from `capability.intensity()`), guarded by `non_safe_capability_is_refused` / `aggressive_capability_is_refused` in `context.rs` (mutation: `issue` returns `Ok` unconditionally); binding the token and gating the ungated vantage path (`connect_from_vantage`) are deferred to the first non-`Safe` capability. Layer 2's scope gate is type-enforced for `TcpConnect` (it holds a `ScopedTarget`) but not yet trait-wide; sealing the trait keeps that safe to defer (no external capability can hold a raw address), and the trait-wide requirement waits for the second capability. Layer 1 (egress-less) is held structurally by `brings_up_and_tears_down_the_mvp_lab` (`internal == Some(true)`). Layer 3's full Aggressive binding (the isolation proof) is not built, so nothing confirms it yet (Phase 4).

### Consequences

* Good, no single check carries safety; a misfire has to pass several independent layers, and the base layer makes an escaped packet physically impossible.
* Bad, Aggressive stays unreleased until the isolation proof is built (acceptable, the MVP needs no Aggressive).
* What would reverse this: nothing short of abandoning real-tool attacks; a single check is refused for a project that runs weapons. An action escaping the lab is this project's off-scale failure, which this decision exists to make impossible.

## Pros and Cons of the Options

### Option 1 (single scope check)

* Good, simple. Bad, one bug is a real attack; no physical backstop.

### Option 2 (scope + intensity)

* Good, two checks. Bad, still software-only; no isolation base.

### Option 3 (defense-in-depth)

* Good, independent layers with a physical base. Bad, more to build; the isolation proof is non-trivial.

## More Information

Was "Decision F" in the retired `design-decisions.md`; the layer-2 scope gate settled in #20. Code: `crates/redstep/src/scope.rs`, `crates/redstep/src/context.rs`, `crates/redstep/src/orchestrator.rs`. Open: the isolation proof, side-channel/DNS leak closure, the Aggressive opt-in UX.
