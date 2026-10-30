---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Unify native primitives and tool adapters behind one Capability trait, gated by Intensity

## Context and Problem Statement

Attack capabilities range from fast, deterministic checks (reachability, segmentation, HTTP-spec, authorization) to heavy real tools (nmap, hydra, sqlmap, metasploit, VPN and crypto cracking). How are they implemented so the safe checks stay cheap enough to run every CI pass while the heavy tools are still available, and so both produce the same evidence and pass the same safety gates?

## Decision Drivers

* Reimplementing hydra/metasploit/VPN cracking in Rust is unrealistic; making every capability an external process makes the cheap Safe checks heavy.
* A single evidence schema and a single safety device (Intensity x Scope) must cover both kinds.
* "Ruthless" attacks must be possible in isolation yet impossible to aim at production by mistake.

## Considered Options

* Option 1: native Rust only.
* Option 2: everything through external tools.
* Option 3: hybrid, native Rust primitives plus tool adapters behind one `Capability` abstraction, normalized to one evidence model and tagged with an Intensity level.

## Decision Outcome

Chosen: Option 3. A `Capability` trait abstracts both kinds; native primitives (reachability, segmentation, HTTP-spec) are fast and run every pass, tool adapters wrap real tools. Both normalize to the same evidence (ADR-0004) and carry an `Intensity` (`Safe` / `Controlled` / `Aggressive`); "ruthless" is `Aggressive`, released only explicitly and only against a framework-isolated target (ADR-0006). The attacker base image is Kali-family from the start. MVP builds the native Safe layer only; tool adapters are Phase 4+.

MVP shape (first built here): the `Capability` trait has an associated `Value` and `async fn execute(&self) -> Result<(Observation<Value>, EvidenceDraft)>`, used through a generic `TestContext::run` (no `dyn` registry yet). A capability holds a `ScopedTarget` (type-enforced scope gate) and reports its `Intensity`; `run` refuses any intensity but `Safe` (`Error::IntensityRefused`). `TcpConnect` maps an opened connection to reachable/High, a refusal to unreachable/High, a timeout to unreachable/Low (a transient failure must not read as a confident boundary hold). A reachability capability is executed *from the attacker's vantage*, not the host (the host reaches every segment and would read a vacuous PASS, RK-008): `orchestrator::tcp_reachable_from` runs a busybox `nc` connect from a container on a vantage network and reuses `tcp_connect`'s classification, recording a distinct `tcp_connect_vantage` capability so the in-lab probe is not mistaken for a host connect.

### Confirmation

The intensity gate is compiler-held *outside* the crate (#9): the `Capability` trait is sealed (a private `Sealed` supertrait), so an external crate cannot implement it (`E0277`), and `execute` requires an `IntensityCleared` token whose field is private and whose only constructor `issue` is crate-private, so external code can neither add a capability nor mint a token to run one. `compile_fail` doctests on `Capability` pin all three (an external impl, a forged `IntensityCleared(())`, and an external `IntensityCleared::issue(..)` each fail to compile; loosening any of the three keywords makes the matching doctest compile and the test fail). In-crate it is not fully compiler-held: the token is not bound to the capability's intensity, so `run` minting it from `capability.intensity()` is a convention guarded by `non_safe_capability_is_refused` and `aggressive_capability_is_refused` in `crates/redstep/src/context.rs` (mutation: make `issue` return `Ok` unconditionally, and both panicking stubs run). Binding the token, and gating the vantage path (`connect_from_vantage` runs ungated), are deferred to the first non-`Safe` capability. Scope through the type stays per-capability: `TcpConnect` holds a `ScopedTarget`, but the trait does not require one, and the trait-wide requirement is deferred to the second capability. The native classification is guarded by `connect_outcome_classifies_each_result` and `classify_connect_maps_outcome_to_confidence` in `crates/redstep/src/capability/tcp_connect.rs` (mutation: widen the refusal arm, or raise the Indeterminate confidence). The vantage path is guarded by `nc_result_reads_a_finished_probe_and_fails_closed`, `nc_cmd_is_argv_not_a_shell_line`, and `tcp_reachable_from_sees_a_listener_on_its_own_network_only` in `orchestrator.rs` (the last is Docker, confirmed on the CI Linux leg). The tool adapters are not built, so nothing confirms them yet (Phase 4+).

### Consequences

* Good, one evidence schema and one safety device cover native and tool paths alike; the cheap checks stay cheap.
* Bad, the `Capability` trait's in-container execution seam is not yet designed; the one MVP vantage capability is a bespoke method (`tcp_reachable_from`), and generalizing it waits for the v0.4.0 tool adapters (an interface with no caller is not invented early).
* What would reverse this: a single kind of capability (all native, or all tool) proving sufficient. Not expected; the project needs both.

## Pros and Cons of the Options

### Option 1 (native only)

* Good, fast and deterministic. Bad, cannot run hydra/metasploit-class attacks at all.

### Option 2 (all tools)

* Good, real attacks. Bad, the Safe checks become heavy, so CI cannot run them every pass.

### Option 3 (hybrid)

* Good, each kind where it belongs, one gate and one evidence model. Bad, two execution mechanisms to normalize.

## More Information

Was "Decision B" in the retired `design-decisions.md`; the native layer settled in #3, the vantage refinement in #27. Code: `crates/redstep/src/capability/`, `crates/redstep/src/orchestrator.rs`. Open: the capability/evidence schema details, the in-container seam for tool adapters, the Kali image size strategy.
