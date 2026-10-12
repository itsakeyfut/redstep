---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Govern distribution by risk tier, connected at the scope gate

## Context and Problem Statement

Distributing a framework that bundles attack tools and runs real attacks means turning "legitimate security testing only" into concrete mechanism and documents. ADR-0006 is the technical safety device; this is the legal, governance, and documentation layer above it.

## Decision Drivers

* Documentation alone is weak and carries no real-environment consent; a uniform mandate adds friction even to safe mock/isolated use.
* Governance strength should scale with risk, matching ADR-0006's intensity ladder and ADR-0013's mock/real split.
* High-risk consent recorded in the evidence (ADR-0004) shows afterward that the test was legitimate.

## Considered Options

* Option 1: documentation only.
* Option 2: a uniform authorization mandate for all use.
* Option 3: risk-tiered governance.

## Decision Outcome

Chosen: Option 3. A baseline always: SECURITY.md, a stated purpose, an ACCEPTABLE_USE, LICENSE (with the bundled tools' licences), and a disclaimer. Low risk (mock/isolated/Safe): baseline acceptance only, near-zero friction. High risk (aimed at a real environment / Aggressive): explicit scope authorization, an authorization file declaring the target is owned or permitted, plus a confirm gate, which is the human-side entry to ADR-0006's scope gate. High-risk runs record who/when/which-scope in the evidence. Dual-use stance: methods are not hidden, but safe-by-default and isolation-first, with responsible-disclosure guidance. Worldwide, with US and Japan law prioritized first. MVP carries the baseline documents and the low-risk scope acceptance; the high-risk machinery is later.

### Confirmation

Nothing enforced in code yet; the baseline documents are the artifact and the high-risk authorization/confirm machinery is later. When the authorization file and confirm gate are built, the ADR names the guard (the human-side scope gate refusing an unauthorized high-risk run). The low-risk path already rides on ADR-0006's scope gate, which has its own guards.

### Consequences

* Good, friction scales with risk, and the technical gate (ADR-0006) and the legal gate meet at one scope-gate point, with consent recorded as evidence.
* Bad, the authorization-file schema, the acceptable-use text, and the multi-jurisdiction legal review are not done.
* What would reverse this: documentation-only proving responsible enough (no real-environment consent) or a uniform mandate being chosen (it taxes safe mock use).

## Pros and Cons of the Options

### Option 1 (docs only)

* Good, lightest. Bad, weak, no real-environment consent.

### Option 2 (uniform mandate)

* Good, uniform. Bad, friction on safe mock/isolated use.

### Option 3 (risk-tiered)

* Good, matches the intensity ladder and mock/real split; one scope-gate point joins technical and legal. Bad, schema and legal review deferred.

## More Information

Was "Decision T" in the retired `design-decisions.md`. Open: the authorization-file schema and UX, the ACCEPTABLE_USE text, US (CFAA) and Japan (Unauthorized Computer Access Law) points, the responsible-disclosure guidance, the bundled-tool licence terms. See ADR-0006 (the scope gate this is the human entry to), ADR-0013 (the mock/real split), ADR-0019 (the bundled-tool licences).
