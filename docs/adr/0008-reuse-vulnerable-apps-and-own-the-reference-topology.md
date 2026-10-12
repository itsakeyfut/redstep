---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Reuse existing vulnerable apps, own the reference topology, and build no education layer

## Context and Problem Statement

How are the vulnerable targets provided, the ones that let redstep demonstrate a real cracker against a corporate network? And should the framework carry an education layer (per-test explanatory metadata)?

## Decision Drivers

* Existing vulnerable apps already carry deep app-layer vulnerabilities; reinventing them is waste.
* The corporate-network topology (segments, boundaries, VPN, multi-step paths) is the framework's own object and must be its reference implementation.
* "Education" is the project's motive, not a system feature.

## Considered Options

* Option 1: build bespoke vulnerable apps.
* Option 2: only reference existing apps.
* Option 3: hybrid, reuse existing apps for contents, own the reference topology, add thin bespoke internal services for the lateral-movement relays existing apps lack; no education layer.

## Decision Outcome

Chosen: Option 3, without an education layer. Existing vulnerable apps (Juice Shop, DVWA) are workload contents; the framework provides the reference corporate topology (internet/dmz/internal, boundaries, VPN, multi-step paths) and thin bespoke internal services (admin API, secrets store) for relays the apps lack. It rides on the ADR-0003 environment model. The previously-planned education layer (explanatory metadata per test) is cut from scope: education is the motive (developers coming to care about security), not a feature to build. MVP is a small bespoke three-tier (`web -> internal-api -> db`) only; Juice Shop/DVWA come in Phase 5; the reference network is built up across Phases 5 to 9.

### Confirmation

Nothing yet. The MVP's three-tier stand-ins exist as test fixtures, but the vulnerable-playground proper is Phase 5+. When it lands, its ADR names the guard. That no education layer exists is held by its absence, which this record states.

### Consequences

* Good, borrows the depth of existing apps, owns the topology under test, and keeps the system free of an education layer that would be metadata nobody maintains.
* Bad, the thin bespoke relays and the reference topology are real build work, deferred.
* What would reverse this: deciding the framework should ship its own deep vulnerable apps (it borrows them instead) or that education is a feature (it is the motive).

## Pros and Cons of the Options

### Option 1 (bespoke apps)

* Good, full control. Bad, reinvents deep app vulnerabilities that already exist.

### Option 3 (hybrid, no education layer)

* Good, reuse plus owned topology, no metadata layer to rot. Bad, the reference topology and relays are deferred work.

## More Information

Was "Decision H" in the retired `design-decisions.md`. Open: the reference topology, the bespoke relay scope, the licence check on the apps reused. See ADR-0003 (the environment model the playground rides on).
