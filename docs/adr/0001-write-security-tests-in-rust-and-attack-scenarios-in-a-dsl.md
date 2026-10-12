---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Write security tests in Rust and attack scenarios in a declarative DSL

## Context and Problem Statement

A Security Test (a specific expected behaviour that needs logic, such as an authorization or IDOR check) and an Attack Scenario (a path, a topology, a multi-step chain) want different things from their notation. Forcing both into one notation distorts whichever it does not fit. What notation does each get?

## Decision Drivers

* A Security Test is an executable specification: dynamic logic.
* An Attack Scenario is a readable attack path: topology, from which an attack graph can be generated.
* Starting in Rust avoids stalling the project on language design.
* A pure DSL hits an expressiveness wall early on dynamic logic (IDOR, authorization).

## Considered Options

* Option 1: everything in Rust.
* Option 2: everything in a declarative DSL.
* Option 3: hybrid, Rust for tests and a DSL for scenarios, with a Rust escape hatch for steps the DSL cannot express.

## Decision Outcome

Chosen: Option 3. A Security Test is Rust (`#[security_test]` proc-macro plus a builder API); an Attack Scenario is a declarative DSL whose path reads at a glance and generates the attack graph; a step the DSL cannot express escapes to a Rust function (`action: custom`). The Rust side is built first so a `cargo test`-like experience arrives without a language-design detour; the DSL is deferred to Phase 3 as a thin declarative wrapper over the Rust builder's internal representation.

The MVP shape (first built here): `#[security_test]` is a proc-macro in its own crate `redstep-macros` (a proc-macro must), tests are discovered through `inventory`, and the workspace is `crates/redstep` plus `crates/redstep-macros`. A test is `async fn(ctx: &TestContext) -> redstep::Result<()>`, run sequentially in name order on one current-thread runtime; the runner maps `Ok` to Passed, `Err(Check)` to Failed, any other `Err` or a panic to Errored, and exits zero only when every test passed. Scope is resolved at run level; the CLI's `--allow host:port` is interim, the environment definition (ADR-0003) is the durable source, and a `ScopedTarget` is constructible only through the resolver (ADR-0006).

### Confirmation

The runner's shape is guarded by the tests in `crates/redstep/src/runner.rs`: `fail_run_exits_nonzero` (mutation: `exit_code` treats `Fail` as `Pass`), `empty_run_does_not_pass` (mutation: drop the `!is_empty()` term), and `classify_maps_result_to_verdict` (mutation: map the `Check` arm to `Error`). Discovery and the macro are exercised by `crates/redstep/tests/public_api.rs`. The DSL is not built, so nothing confirms it yet (Phase 3).

### Consequences

* Good, because a working, deterministic authoring experience arrived early, and the DSL can reuse the builder's representation when it lands.
* Bad, because once the DSL exists there are two authoring surfaces to keep aligned.
* What would reverse this: a single notation shown to serve both demands without distorting either. Not expected; the two demands diverge by construction.

## Pros and Cons of the Options

### Option 1 (all Rust)

* Good, one surface, full logic.
* Bad, an attack path is not readable at a glance and the attack graph is hand-built.

### Option 2 (all DSL)

* Good, paths read at a glance.
* Bad, hits a wall on dynamic authorization and IDOR logic.

### Option 3 (hybrid)

* Good, each notation fits its job; the escape hatch covers the gaps.
* Bad, two surfaces to align, and an escape-hatch boundary to keep honest.

## More Information

Was "Decision A" in the retired `design-decisions.md`; the MVP shape settled in #2. Code: `crates/redstep-macros/src/lib.rs`, `crates/redstep/src/runner.rs`, `crates/redstep/src/context.rs`. Open: the DSL format (YAML or custom), the escape-hatch boundary, the Rust-vs-DSL authoring guidance.
