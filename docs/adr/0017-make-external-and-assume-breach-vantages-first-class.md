---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Make both external and assume-breach vantages first-class

## Context and Problem Statement

Where can an attack start? External only (internet origin), or also assume-breach (starting already inside, from a compromised internal host)?

## Decision Drivers

* Real advanced testing cares not only about preventing entry but about blast radius once breached; assume-breach measures that directly.
* ADR-0012 made the initial foothold first-class, so placing it internally is a natural extension.

## Considered Options

* Option 1: external attacker only.
* Option 2: external and assume-breach both first-class.

## Decision Outcome

Chosen: Option 2. External: the initial foothold is the attacker box in the internet segment. Assume-breach: the initial foothold can be placed on any internal segment/host (for example a DMZ web host already taken), to measure "if this is taken, how far inside can they get". Both are expressed by where ADR-0012's initial foothold is placed, and several origin scenarios can be defined in parallel. MVP realizes the external vantage (the boundary demo runs from the internet segment); assume-breach placement is M1 skeleton, its full pivot Phase 5.

MVP shape (first built here): the `Environment` carries a vantage segment (`vantage_segment`), validated at build; the lab-wired run binds a `TestContext` to that segment's network and the attack executes from there (`connect_from_vantage`, ADR-0002/ADR-0011). The boundary demo `attacker_cannot_connect_to_db` is an external-vantage attack: the attacker in `internet` cannot reach `db` in `internal`.

### Confirmation

The external vantage is guarded on the CI Linux leg by `run_in_lab_passes_the_boundary_demo` and `a_connected_lab_is_refused_before_any_test_runs` in `crates/redstep/tests/environment.rs` (the attack runs from the `internet` vantage), and `tcp_reachable_from_sees_a_listener_on_its_own_network_only` in `orchestrator.rs` (the probe acts from the vantage network). `vantage_segment_must_be_set_and_declared` in `environment.rs` guards the vantage's validation offline. Assume-breach placement is not built, so nothing confirms it yet (its full pivot is Phase 5).

### Consequences

* Good, both "can they get in" and "how far once in" are measurable, reusing the foothold model.
* Bad, assume-breach's initial assets (which privilege/credentials/session to grant) and its relation to the boundary self-check are undesigned.
* What would reverse this: deciding assume-breach is out of scope (it is the blast-radius measure the project wants).

## Pros and Cons of the Options

### Option 1 (external only)

* Good, simplest. Bad, cannot measure blast radius after a breach.

### Option 2 (both first-class)

* Good, measures prevention and containment; reuses the foothold model. Bad, assume-breach's starting assets are deferred design.

## More Information

Was "Decision P" in the retired `design-decisions.md`; the external vantage is used by #27/#28. Code: `crates/redstep/src/environment.rs` (`vantage_segment`), `crates/redstep/src/runner.rs`, `crates/redstep/src/context.rs`. Open: assume-breach's initial assets, per-vantage expected results (blast radius), assume-breach vs the boundary self-check. See ADR-0012 (the foothold this places).
