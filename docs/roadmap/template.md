<!--
Template for a milestone definition file under docs/roadmap/.

How to use it:
  1. Copy this file to docs/roadmap/v-<major>-<minor>-<patch>.md (e.g. v-0-2-0.md).
  2. Keep the headings and their order, so every milestone reads the same way.
  3. Fill each section; delete the square-bracket [ ... ] placeholders and this
     whole set of guidance (the HTML comments).

Repo docs are English (CLAUDE.md). The existing roadmap.md and mvp.md are Japanese
for now; new milestone files are written in English and the older two are expected
to follow as they are revised.
-->

# v0.0.0 — [theme name, 3-6 words]

- **Version**: `v0.0.0`
- **Status**: planned | in-progress | released (pick one)
- **Theme**: [short name, e.g. "Native Web/API security checks"]
- **Released**: [YYYY-MM-DD, or — if not released]

> **In one sentence**: [what a user can truthfully claim once this ships. The outcome from the user's side, not a feature list. This is the "達成で言えること" column of roadmap.md.]

## Goal

<!-- One short paragraph: the problem this milestone closes, and why it is the next
     increment. Why this, why now, ahead of what comes after. -->

[body]

## Scope

<!-- What this milestone delivers, one bullet per coherent capability. Name the
     Phase(s) and ADR(s) each bullet realizes, so the milestone traces back to the
     settled reasoning. Only what is actually in this version: a promise, not a wish. -->

- [capability] — realizes `Phase N` / `ADR-XXXX`.

## Attack coverage

<!-- The attack techniques this version targets: the set it intends to move from
     `capability: none` to a real capability in docs/attacks/. One bullet per
     technique, linking its catalog entry and naming the capability it sets. Only
     techniques this version commits to; the rest stay backlog in the catalog
     (capability: none), which is the authoritative coverage view. At bump, the
     CHANGELOG lists which techniques actually landed; one that slips moves to a
     later version rather than being back-dated here. A full catalog stocktake
     (every technique -> a target version, backlog, or permanently out of scope)
     is run before a bump or when checking coverage, against the catalog's
     `capability` fields. Write "None" if this version adds no attack technique.
     Format each bullet as a Markdown link from the technique name to its
     docs/attacks/ entry, an em dash, then the backticked capability; see the filled
     v-0-2-0.md for the exact shape. -->

- [technique name] — `[capability]`

## Out of scope

<!-- What this milestone deliberately does NOT do, and where it goes instead (a later
     version, or "unscheduled"). Silence here is how scope creeps. "None" if none. -->

- [deferred item] — deferred to `v0.0.0` / unscheduled.

## Depends on

<!-- The earlier milestones or capabilities this builds on; "None" if it stands
     alone. A milestone must not assume work that is not yet delivered. -->

[body, or "None"]

## Release criteria

<!-- The checklist that must hold to tag this version: the Definition of Done. Each
     item is observable (a passing command, a test that fails on a mutation, a shipped
     artifact, a written document), never a feeling. For a released milestone, check
     the items that were met. The GitHub milestone's closing condition mirrors this. -->

- [ ] [observable criterion]

## Work

<!-- How the work is tracked. The GitHub milestone of the same version holds the
     sub-issues; link it, and optionally list the headline issues. This file is the
     narrative (why, what); the milestone is the issue list (which). -->

- GitHub milestone: `v0.0.0`

## Risks and open questions

<!-- What could change this plan: an unproven assumption, a dependency on an external
     tool's behaviour, a cross-cutting decision not yet an ADR. Empty is fine; if so,
     write "None". -->

[body, or "None"]

## Links

- [Roadmap](./roadmap.md) — the milestone sequence this file is one entry of.
- [ADR index](../adr/README.md) — the settled cross-cutting decisions.
