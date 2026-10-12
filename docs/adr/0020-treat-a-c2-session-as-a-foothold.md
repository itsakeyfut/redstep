---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Treat a C2 session as a foothold and integrate C2 through the plugin mechanism

## Context and Problem Statement

How are C2 frameworks (Sliver, Mythic, Havoc) handled for multi-step Level-3 attacks? C2 is stateful and long-running (implant, callback/beacon, session, operations), unlike a one-shot capability.

## Decision Drivers

* C2 does not fit a one-shot capability, but a dedicated subsystem would duplicate the ADR-0007 plugin mechanism and the ADR-0012 state model.
* A C2 session is naturally a kind of ADR-0012 foothold: implant delivery yields a foothold, beaconed operations are capability executions from it.
* ADR-0006's egress block keeps the callback inside the isolated network.

## Considered Options

* Option 1: force C2 into one-shot capabilities.
* Option 2: a dedicated C2 subsystem.
* Option 3: integrate C2 through the ADR-0007 plugin, model a C2 session as an ADR-0012 foothold, and add only a thin implant-lifecycle layer.

## Decision Outcome

Chosen: Option 3. C2 integrates through the plugin mechanism (a Capability adapter), no parallel subsystem. A C2 session is an ADR-0012 foothold (`C2Session`): implant delivery is `yields_foothold`, beaconed operations are capabilities executed from that foothold, so it rides on the attacker state graph. Only the part a one-shot capability lacks, the implant/session lifecycle (deliver, await callback, maintain, tear down), is added as a thin orchestration layer. The C2 server runs in the attacker segment and the callback stays inside the isolated network (ADR-0006's egress block prevents a real external callback). Policy settled; implementation is Phase 9.

### Confirmation

Nothing yet. No C2 integration is built (Phase 9). When built, the ADR names the guard. The callback's containment rests on ADR-0006's isolation, which has its own guards.

### Consequences

* Good, C2 reuses the plugin and the state model rather than duplicating them, and the callback is contained by isolation.
* Bad, the async callback-wait integration into the state model and the implant-lifecycle API are undesigned.
* What would reverse this: C2 fitting one-shot capabilities (it does not) or a dedicated subsystem proving cleaner (it duplicates the plugin and state model).

## Pros and Cons of the Options

### Option 1 (one-shot)

* Good, no new concept. Bad, cannot hold a stateful session.

### Option 2 (dedicated subsystem)

* Good, purpose-built. Bad, duplicates the plugin and the attacker state model.

### Option 3 (foothold + plugin + thin lifecycle)

* Good, reuses both, contained by isolation. Bad, async lifecycle is deferred design.

## More Information

Was "Decision S" in the retired `design-decisions.md`. Open: integrating the async callback-wait into the state model, which C2 first (Sliver), the implant-lifecycle API. See ADR-0007 (the plugin), ADR-0012 (the foothold), ADR-0006 (the containment).
