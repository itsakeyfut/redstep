---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Separate observation from verdict, and require High confidence by default, fail-closed

## Context and Problem Statement

How does the framework decide "the attack succeeded / the boundary held" from the noisy output of real tools (sqlmap, hydra, metasploit)? This is the core of the user's goal, and the place a false answer does the most harm.

## Decision Drivers

* Two layers must not be mixed: the Observation (did the action technically succeed) and the Verdict (is that a PASS or a FAIL, with the sign inverted when a held boundary is a PASS).
* Real tools misfire constantly, so an un-corroborated observation yields false "attacked/defended" and destroys trust.
* A weak signal must land in Inconclusive, not a confident verdict (CLAUDE.md row 6, a false PASS, is the failure to avoid).

## Considered Options

* Option 1: a single boolean oracle (pattern match the tool output).
* Option 2: observation plus expectation, no corroboration.
* Option 3: a layered oracle, a per-capability signal extractor to a typed Observation with confidence, an expectation/assertion layer, and corroboration across signals.

## Decision Outcome

Chosen: Option 3. A signal extractor normalizes raw output to a typed `Observation` with `High`/`Medium`/`Low` confidence; an expectation layer declares the expected (safe) value and the oracle produces a `Verdict`; corroboration backs important verdicts with several signals. The verdict is three-valued plus `Error`: `Pass` / `Fail` / `Inconclusive`, so a weak or conflicting signal falls to `Inconclusive` rather than a false verdict. MVP builds the Observation type, the expectation judgement, and the three-valued verdict; corroboration is Phase 5 (when noisy real tools arrive).

MVP shape (first built here): `Verdict { Pass, Fail, Inconclusive, Error }`; `Expectation<T> { expected, min_confidence }` and the pure `judge(&Observation<T>, &Expectation<T>) -> Judgement`. The sign is in the expectation: the test declares the safe value, so a mismatch is a `Fail`. `min_confidence` defaults to **`High`, fail-closed**: an unqualified `expect(&obs).to_be(v)` on a weak signal is `Inconclusive`, and a test opts down explicitly with `min_confidence(Low)`. The runner aggregates a test's judgements by severity (`Fail` > `Error` > `Inconclusive` > `Pass`); a test that recorded nothing is `Inconclusive`, not `Pass`; a recorded `Fail` survives a later body error or panic. The exit code is zero only when at least one test ran and every verdict is `Pass`; `Inconclusive` is non-zero. The evidence id on a `Judgement` is resolved by the runner at drain time (ADR-0004).

### Confirmation

Guarded in `crates/redstep/src/expectation.rs` (`default_requires_high_confidence`: a weak signal is Inconclusive unless opted down) and `crates/redstep/src/runner.rs` (`aggregate_is_fail_closed`, `no_judgement_is_inconclusive`, `recorded_fail_survives_a_later_error_or_panic`, `inconclusive_run_exits_nonzero`). Mutations: default `min_confidence` to `Low` (a timeout reads as a confident PASS, failing `default_requires_high_confidence`); make `aggregate(&[])` `Pass` (fails `no_judgement_is_inconclusive`); treat `Inconclusive` as zero exit (fails `inconclusive_run_exits_nonzero`). Corroboration is Phase 5, confirmed by nothing yet.

### Consequences

* Good, the sign inversion is declarative, a weak signal cannot become a confident verdict, and the record (observation) and the verdict stay separate and linked.
* Bad, corroboration is deferred, so a self-consistent single-probe false signal is not yet cross-checked (a capability sets confidence directly for now).
* What would reverse this: a simpler single-boolean oracle proving trustworthy against real tools (it does not; false reports destroy the verification).

## Pros and Cons of the Options

### Option 1 (single boolean)

* Good, simple. Bad, real-tool misfires become false "attacked/defended", the core failure.

### Option 2 (observation + expectation, no corroboration)

* Good, separates observation and verdict. Bad, no cross-check for a confident-but-wrong single signal.

### Option 3 (layered oracle)

* Good, confidence + corroboration drop the ambiguous cases to Inconclusive. Bad, corroboration rules are real design, deferred.

## More Information

Was "Decision J" in the retired `design-decisions.md`; settled in #4, the evidence link in #14. Code: `crates/redstep/src/verdict.rs`, `expectation.rs`, `observation.rs`, `runner.rs`, `context.rs`. Open: per-capability signals and corroboration rules, confidence computation, the Inconclusive CI treatment (ADR-0014). See ADR-0004 (evidence) and ADR-0009 (the FAIL diagnostic).
