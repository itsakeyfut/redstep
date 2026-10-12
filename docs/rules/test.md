# Testing Standards

## References

- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [proptest Book](https://proptest-rs.github.io/proptest/intro.html)

---

## Philosophy

Test **behaviour**. A good test breaks only when observable behaviour changes,
not when an internal field is renamed. And a test is real only if breaking the
code it names makes a named test fail: apply the mutation, watch it fail,
restore, and say the mutation in the test's doc comment. A test no mutation can
break is decoration, and the `coverage` skill exists to find it.

## Naming

```
<feature>_should_<expected_result>
```

```rust
fn db_unreachable_from_attacker_should_pass() { ... }
fn attack_success_should_verdict_fail() { ... }
fn out_of_scope_target_should_error_before_acting() { ... }
fn low_confidence_observation_should_be_inconclusive() { ... }
```

A test name is a full sentence held to what it asserts. A name claiming more than
the body proves is a trust defect, not a style one.

---

## Test layers

### 1. Unit tests (pure logic; primary)

`#[cfg(test)] mod tests` in the source. The model layer (verdict oracle,
observation and confidence, scope resolution, intensity gating, evidence
construction, canonical-JSON projection) is pure and must be covered here, with
no network, no Docker, no tool. These are fast, deterministic, and the bulk of
the suite.

Cover the truth table, both signs: an attack that succeeded verdicts FAIL, a
boundary that held verdicts PASS, a weak or conflicting signal verdicts
Inconclusive, an out-of-scope target errors before acting.

### 2. Integration tests (real tools, Docker, targets)

`tests/`. Drive a real capability against a playground target in an isolated
environment, or a real tool through its adapter. **Skip gracefully when the
dependency is unavailable**, so the suite still passes on a machine without
Docker or the tool:

```rust
fn docker_available() -> bool {
    std::process::Command::new("docker").arg("info").output()
        .map(|o| o.status.success()).unwrap_or(false)
}
```

**A test asserting an item is public belongs here**, because a unit test resolves
names through `use super::*` and sees crate-internal items, so a `pub use` demoted
to `pub(crate)` still compiles in one. Only an external crate path enforces `pub`.

### 3. Property tests (proptest)

Invariants on arbitrary input: a response parser never panics on arbitrary bytes
(security.md section 5), an observation's confidence stays in range, a scope
matcher never widens to a target outside the allowlist.

---

## Discovery is flaky; a pinned replay is the regression (ADR-0022, ADR-0014)

Two kinds of test behave differently and must not be confused.

- A **discovery** test (a real search, a brute force, an exploration) is
  non-deterministic and slow. It is informational: it does not gate, and a run
  that does not find the vulnerability this time is not a red build.
- A **replay** test, generated from a captured Success Witness, re-runs a known
  success condition deterministically. This is the regression guard and it may
  gate. A replay must reproduce exactly (the witness carries target, payload,
  foothold, credentials, data-pack versions); if it is flaky, the witness is
  incomplete, which is an `evidence-integrity` defect, not a test to retry.

A test that asserts a replay is deterministic asserts exactly that: run it twice
and get the same verdict.

---

## Tests never leave the lab

An integration test sends traffic only to a target it created inside an isolated
environment. A test that reaches a real host, a public service, or the internet
is a defect of the same class as the one `security.md` section 0 forbids, caught
in review as an `isolation-safety` finding. Aggressive-intensity actions stay off
by default in tests, as everywhere.

---

## Fixtures

- **The playground targets** (the deliberately vulnerable web / api / db) are the
  primary fixtures; define them as the environment the test brings up and tears
  down, not as committed binaries.
- **Small static inputs** (a recorded tool output to parse, a sample response)
  go under `tests/fixtures/`, and **must not contain a real secret** (use an
  obvious fake like `password123`). A fixture that must carry a key is the
  reviewed exception (security.md section 4).
- Use `tempfile` for temporary outputs; no test writes into the repository.

---

## What NOT to test

- Third-party internals (a tool's own correctness, Docker, a library).
- Exact output equality across tool versions; assert the field you read, with a
  tolerance or a shape check, not a byte-for-byte match of a tool's whole output.
- Trivial getters.

---

## CI notes

- The gate is `bash .claude/scripts/gate.sh` (fmt, clippy, doc, test). Integration
  tests self-skip where Docker or a tool is unavailable, so the sweep passes on a
  bare runner; the real attack paths run where the lab can be built.
- A discovery test does not belong in the gating suite; keep it `#[ignore]` or
  behind an explicit flag, and let the deterministic replays and unit tests be
  what the gate runs.
