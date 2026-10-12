---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Model the attacker's state as a growing asset set, identified with the attack graph

## Context and Problem Statement

In a multi-step attack, what the attacker gains (credentials, sessions, shells, reach, privileges) has to carry between steps. A pivot needs not just reach but a foothold it can execute from. How is that state modelled?

## Decision Drivers

* A pivot requires a foothold (a place attacks can be executed from), distinct from mere reachability.
* The state's growth history is exactly the attack graph (ADR-0004), so modelling them twice is waste.
* Lateral movement and privilege escalation must ride on it.

## Considered Options

* Option 1: carry a flat bag of acquired values.
* Option 2: a dedicated scenario state machine.
* Option 3: an attacker state graph, a monotonically growing asset set identified with the ADR-0004 attack graph.

## Decision Outcome

Chosen: Option 3. `AttackerState` = footholds + credentials + sessions + privileges + knowledge; a `Foothold` is an execution origin (initially the attacker's own box, later a shell on web, a container exec), distinct from "reachable"; a step is a transition (`foothold.execute(capability)`) that, on success, extends the state; acquired assets reference ADR-0004 evidence, so the temporal projection of `AttackerState` is the attack graph. MVP builds only the skeleton (the initial foothold = the attacker box, plus recorded reach/credentials), because the First-Prototype PoC is single-step; real shell-yielding pivots are Phase 5+ (with metasploit).

### Confirmation

Nothing yet beyond the skeleton. The MVP uses the initial foothold (the attacker's vantage) implicitly; multi-step pivots are Phase 5. When a pivot yields a foothold, its ADR names the guard.

### Consequences

* Good, the state is first-class and identical to the attack graph, so no double bookkeeping, and lateral movement/privesc ride on the same model.
* Bad, the foothold abstraction (shell vs container-exec vs network position) and the asset types are not yet designed.
* What would reverse this: a flat asset bag proving enough (it loses the foothold/pivot structure) or a separate state machine being cleaner (it double-models the graph).

## Pros and Cons of the Options

### Option 1 (flat bag)

* Good, simple. Bad, no foothold, so no faithful pivot.

### Option 3 (attacker state graph)

* Good, foothold-based pivots, unified with the attack graph. Bad, the abstractions are real design, deferred.

## More Information

Was "Decision L" in the retired `design-decisions.md`. Open: the foothold abstraction, the asset types, the AttackerState-to-AttackGraph correspondence, privilege escalation. See ADR-0004 (the attack graph this is identified with) and ADR-0017 (where the initial foothold is placed).
