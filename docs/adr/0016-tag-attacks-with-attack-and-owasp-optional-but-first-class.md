---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Tag attacks with ATT&CK and OWASP, optional but first-class, and allow unmapped

## Context and Problem Statement

How are the attack methods mapped to existing standards? MITRE ATT&CK is the common language and aids interoperability, but ADR-0015 (AI discovers unknown attacks) means some attacks will not fit an existing id.

## Decision Drivers

* ATT&CK/OWASP mapping has real value for coverage views, SOC dialogue, and report interoperability.
* A mandatory mapping would make an unknown attack (ADR-0015) impossible to register.
* ATT&CK is the main axis; the application layer also uses OWASP.

## Considered Options

* Option 1: a bespoke taxonomy only.
* Option 2: a mandatory ATT&CK mapping.
* Option 3: optional-but-first-class tagging (ATT&CK primary, OWASP for the app layer), with `unmapped` and bespoke tags allowed.

## Decision Outcome

Chosen: Option 3. The taxonomy is a first-class model but tagging is optional (recommended). A capability/scenario may carry an ATT&CK Technique id (plus OWASP for the app layer); coverage views, reports (ADR-0005), and an ATT&CK-Navigator-style heatmap are generated from the tags; `unmapped` and bespoke tags are legitimate, so an ADR-0015 discovery registers as "provisional or unmapped" and is promoted to a formal id later. This is Phase 2 (M2).

### Confirmation

Nothing yet. No tagging model or coverage view is implemented (M2). When built, the ADR names the guard.

### Consequences

* Good, standard tags give coverage/interop while `unmapped` keeps an unknown attack registrable, so this connects ADR-0015's discovery to ADR-0005's reporting.
* Bad, the tagging model and coverage computation are undesigned.
* What would reverse this: a bespoke-only taxonomy (loses interop) or a mandatory mapping (loses unknown-attack registration).

## Pros and Cons of the Options

### Option 1 (bespoke only)

* Good, simple. Bad, no coverage/interop with standards.

### Option 2 (mandatory mapping)

* Good, uniform. Bad, an unknown attack cannot be registered.

### Option 3 (optional, first-class, unmapped allowed)

* Good, standards plus registrable unknowns plus promotion. Bad, deferred model and coverage design.

## More Information

Was "Decision K" in the retired `design-decisions.md`. Open: which ATT&CK matrices, the coverage definition, promoting tagging in practice, the unmapped-to-formal-id workflow (with ADR-0015). See ADR-0015 (unknown-attack discovery) and ADR-0005 (reports that render the tags).
