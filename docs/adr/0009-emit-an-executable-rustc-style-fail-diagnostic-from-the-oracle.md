---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Emit an executable, rustc-style FAIL diagnostic from the oracle

## Context and Problem Statement

When a security test FAILs, should redstep guide the reader to what is wrong and how to fix it, the way a `rustc` compile error does? This is a cross-cutting diagnostic-quality policy, distinct from the (rejected) education-metadata layer (ADR-0008).

## Decision Drivers

* The built-in checks (reachability, segmentation, authorization) know what a FAIL means, so they can emit actionable guidance with no author input.
* A FAIL should carry at least: expected, actual, probable cause, remediation hint, and the evidence id.
* Author-written per-FAIL guidance would be an education-metadata layer, which is out of scope.

## Considered Options

* Option 1: a bare PASS/FAIL with no guidance.
* Option 2: author-written guidance per test (the education-layer shape, rejected).
* Option 3: framework-emitted, rustc-style diagnostics from the built-in checks, with an optional author `.hint()`.

## Decision Outcome

Chosen: Option 3. The built-in checks emit the diagnostic automatically; a FAIL carries expected / actual / probable cause / remediation / evidence id; an author may add an optional `.hint()` but it is never required. The diagnostic is a property of the oracle's output, not the renderer or the author.

MVP shape (first built here): `Judgement` carries `diagnostic: Option<Diagnostic { probable_cause, remediation }>`, filled by the built-in check on a `Fail` and left `None` otherwise; the renderer only displays it. Three fillers now exist: `judge` for a value expectation (generic expected-vs-observed text), `check` for a bare assertion, and a domain check that carries its own richer `Diagnostic` on the `Recorded` its capability returns, which `ExpectationBuilder::to_be` attaches on a `Fail`, replacing `judge`'s generic text (the SQLi check `exploit_sqli_from_vantage`, #50). The field lives on the oracle's output, so the richer text needs no renderer change, and the test author's API is unchanged (`expect(&r).to_be(false)`); the text is still the framework's, not author-written. `.hint()` is deferred (optional, no acceptance criterion needs it).

### Confirmation

Guarded by `check_failure_carries_a_diagnostic` in `crates/redstep/src/context.rs`: a failing `check` records a `Fail` carrying a diagnostic whose cause names the assertion, a passing one carries none. Mutation: leave `diagnostic` `None` on failure (the failing assert fails), or fill it unconditionally (the passing assert fails). The renderer-side display is held by the terminal snapshot in the report tests. The domain-check path is guarded by `to_be_attaches_a_carried_domain_diagnostic_on_fail_only` (the carried diagnostic replaces the generic text on a `Fail`, is dropped on a `Pass`, and a `Recorded` with none keeps `judge`'s generic text) and, end to end, by `sqli_check_flags_the_playground` (the SQLi check's `Fail` carries the parameterized-query remediation, not the generic text).

### Consequences

* Good, actionable FAIL output with no author burden, because the built-in check owns the meaning; richer domain diagnostics drop in without touching the renderer.
* Bad, remediation templates per built-in check are not yet filled in (the MVP text is generic).
* What would reverse this: deciding diagnostics belong in the renderer or must be author-written (each is rejected here).

## Pros and Cons of the Options

### Option 1 (bare PASS/FAIL)

* Good, minimal. Bad, the reader is left to diagnose a security failure unaided.

### Option 2 (author-written)

* Good, specific. Bad, it is the education-metadata layer this project cut; it rots and burdens authors.

### Option 3 (framework-emitted from the oracle)

* Good, automatic and actionable, renderer-agnostic. Bad, per-check remediation templates to maintain.

## More Information

Was "Decision H-2" in the retired `design-decisions.md`; settled in #6. Code: `crates/redstep/src/context.rs` (`Diagnostic`, `check`), `crates/redstep/src/expectation.rs` (`judge`), the `report` renderer. Open: the remediation templates, hint accuracy, i18n. See ADR-0005 (the report that displays it) and ADR-0010 (the oracle that produces it).
