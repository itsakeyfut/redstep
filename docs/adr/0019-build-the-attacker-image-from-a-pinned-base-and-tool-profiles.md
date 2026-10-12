---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Build the attacker image from a digest-pinned base and composable tool profiles

## Context and Problem Statement

How is the Kali-based attacker container (ADR-0002) composed, and how are its trust and licensing assured? ADR-0015's two modes bear on it: Verification needs only the adapter tools, Exploration finds more with a broader toolset.

## Decision Drivers

* ADR-0015's two modes want two image variants: a lean, reproducible, CI-friendly one and a broad one for free exploration.
* A full everything-image is huge, unauditable, and impractical to licence-check; a minimal hand-picked one starves exploration.
* Supply-chain trust needs a pinned base plus a reproducible build plus an SBOM.

## Considered Options

* Option 1: one full everything-image.
* Option 2: one minimal hand-picked image.
* Option 3: a digest-pinned minimal Kali base plus composable tool profiles, yielding a lean and a full variant.

## Decision Outcome

Chosen: Option 3. Compose from tool profiles (`core` / `web` / `network` / `cloud` / `ad`); the lean image (Verification) is the needed profiles only, the full image (Exploration) is broad or all profiles. Each image pins the base by digest and builds reproducibly from a declared manifest (same pinning idea as ADR-0018), carries an SBOM, and is licence-reviewed per profile (metasploit BSD ok, Cobalt Strike excluded, Nessus is interop). This is Phase 4+.

### Confirmation

Nothing yet. No attacker image or profile mechanism is built. When built, the ADR names the guard (for example that the image resolves to the pinned digest and its SBOM lists what is inside).

### Consequences

* Good, lean-vs-full matches ADR-0015's modes, and digest-pinning + SBOM + per-profile licence review make the image auditable and redistributable.
* Bad, the profile granularity, the base source, the SBOM format, and the update cadence are undesigned.
* What would reverse this: a full image proving auditable enough (it is not) or a minimal one proving sufficient for exploration (it starves discovery).

## Pros and Cons of the Options

### Option 1 (full image)

* Good, everything present. Bad, huge, unauditable, licence-impractical.

### Option 2 (minimal image)

* Good, small and auditable. Bad, starves free exploration.

### Option 3 (pinned base + profiles)

* Good, both variants, auditable, licence-reviewed per profile. Bad, deferred design.

## More Information

Was "Decision R" in the retired `design-decisions.md`. Open: profile granularity, the base source, the SBOM format (SPDX/CycloneDX), the digest-bump workflow, the full-image size cap. See ADR-0002 (the Kali base), ADR-0015 (the two modes), ADR-0021 (the licensing governance).
