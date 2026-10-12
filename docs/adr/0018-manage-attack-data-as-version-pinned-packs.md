---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Manage attack data as version-pinned packs, updated explicitly

## Context and Problem Statement

How are wordlists, Nuclei templates, Exploit-DB, payloads, and vulnerability DBs handled, trading freshness against reproducibility? A decisive constraint: ADR-0006 makes the test environment egress-less, so fetching the latest data during a run is impossible.

## Decision Drivers

* Egress-less isolation (ADR-0006) rules out fetching data at run time.
* Bundling everything whole bloats the image and cannot be partially updated.
* The data version used must be recorded in the evidence (ADR-0004) for reproducibility.

## Considered Options

* Option 1: bundle all data into the image.
* Option 2: fetch the latest at run time (incompatible with ADR-0006).
* Option 3: named, version-pinned data packs injected at environment-build time, updated explicitly outside isolation.

## Decision Outcome

Chosen: Option 3. Data is managed as named, version-pinned packs (`wordlists@2026.09`, `nuclei-templates@v10.x`, `exploit-db@<date>`, `vuln-db@<snapshot>`), injected from a cache/staging at environment-build time (no egress needed at run time). Updating is explicit: outside isolation, bump the manifest to a new pinned snapshot. The pack versions used are recorded in the evidence, so a result is traceable to the data it ran against. Large data (rockyou) is injected on demand. This is Phase 4+ (alongside the tool adapters that consume it).

### Confirmation

Nothing yet. No data-pack mechanism is implemented. When built, the ADR names the guard (for example that a run records the pack versions in its evidence).

### Consequences

* Good, reproducible (pinned + recorded) and compatible with egress-less isolation, while still updatable by an explicit bump.
* Bad, the distribution/cache substrate, pack granularity, and licence redistribution are undesigned.
* What would reverse this: run-time fetch becoming acceptable (it breaks isolation) or whole-bundling proving fine (it bloats and cannot be partially updated).

## Pros and Cons of the Options

### Option 1 (bundle whole)

* Good, always present. Bad, image bloat, no partial update.

### Option 2 (fetch at run time)

* Good, fresh. Bad, needs egress, which ADR-0006 forbids.

### Option 3 (pinned packs)

* Good, reproducible, isolation-compatible, updatable explicitly. Bad, deferred substrate design.

## More Information

Was "Decision Q" in the retired `design-decisions.md`. Open: the distribution/cache substrate, pack granularity, licences, overlap with the Kali-bundled tools (ADR-0019). See ADR-0006 (the isolation this works within) and ADR-0004 (the evidence that records the version).
