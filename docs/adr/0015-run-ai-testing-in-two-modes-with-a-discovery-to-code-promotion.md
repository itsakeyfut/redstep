---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Run AI security testing in two modes with a discovery-to-code promotion

## Context and Problem Statement

How is AI (Claude, OpenAI) positioned for security testing: let it attack freely without constraint, or only through prepared methods? The safety premise is ADR-0006: the environment is egress-less, so the AI's freedom is freedom of method choice, not freedom to break isolation.

## Decision Drivers

* Free-only accumulates no reusable assets; curated-only discovers nothing new; connecting them is a virtuous cycle.
* The freedom is safe because ADR-0006's isolation already contains it.
* The AI provider must be swappable, not fixed to one vendor.

## Considered Options

* Option 1: curated only (AI uses the typed capabilities).
* Option 2: free only (AI attacks unconstrained).
* Option 3: two modes plus a discovery-to-code pipeline.

## Decision Outcome

Chosen: Option 3. A Verification mode (curated) is the default human workflow: typed capabilities through the scope/intensity/oracle/evidence gates. An Exploration mode (free) lets the AI choose methods freely inside the isolated environment, capturing raw logs + pcap as evidence; it is used mainly for framework development (discovering new methods) and is opt-in for users against their own isolated environment. A promotion mechanism turns a discovered attack into a structured report, an issue, and codified capability/scenario. The AI is behind a swappable AI Operator abstraction. All of this is Phase 5 (M5).

### Confirmation

Nothing yet. No AI operator, mode, or promotion is implemented (M5). When built, the ADR names the guard. The safety of free mode already rests on ADR-0006's isolation, which has its own guards.

### Consequences

* Good, Exploration finds the unknown and Promotion turns it into a reusable Verification test, a cycle neither mode gives alone, and it is safe because isolation contains it.
* Bad, the promotion schema, the raw-log-to-evidence meaning, the tool-use interface, and AI cost management are all undesigned.
* What would reverse this: deciding free attack is unsafe (isolation makes it safe) or that curated-only suffices (it discovers nothing new).

## Pros and Cons of the Options

### Option 1 (curated only)

* Good, stable and gated. Bad, no discovery of unknown attacks.

### Option 2 (free only)

* Good, discovery. Bad, no reusable assets accumulate.

### Option 3 (two modes + promotion)

* Good, discovery feeds reusable tests; isolation keeps free mode safe. Bad, the pipeline is large, deferred design.

## More Information

Was "Decision U" in the retired `design-decisions.md`. Open: the promotion schema and issue integration, raw-log-to-evidence meaning, the AI tool-use interface, cost, and how much privilege free mode is given. See ADR-0006 (the isolation that makes free attack safe) and ADR-0022 (the witness promotion builds on).
