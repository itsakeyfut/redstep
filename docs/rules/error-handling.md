# Error Handling

## Principles

- Implement error types with **`thiserror`** in every library crate.
- **Do not use `anyhow` in library crates.** The CLI binary may use `anyhow` for
  top-level contextual propagation.
- Separate **recoverable failures (`Result`)** from **invariant violations
  (panic)**.

---

## Result or panic

- **`Result` (recoverable)**: anything involving a target, a tool, Docker, the
  network, or the filesystem. A target is hostile and a tool is flaky by
  assumption, so a dropped connection, a timeout, a malformed response, a
  non-zero tool exit, a missing data pack, or a Docker error is an ordinary
  `Result::Err`, never a panic.
- **panic (invariant violation)**: a "cannot happen by construction" state in the
  pure model layer only. Even there, never panic on a path driven by target or
  tool input; return `Result` and let the caller decide.
- `unwrap()` / `expect()` are forbidden in library code and allowed only under
  `#[cfg(test)]`, with the one exception of a true, construction-guaranteed
  invariant using `expect` and an `// INVARIANT:` comment.

```rust
// Bad — forbidden in library code
let target = scope.resolve(name).unwrap();

// Good — propagate
let target = scope.resolve(name).ok_or(ScopeError::OutOfScope { name })?;

// OK — a true invariant only, with a reason
// INVARIANT: pushed just above, so the last element always exists.
let last = self.steps.last_mut().expect("step just pushed");
```

---

## A failure never leaks a secret

An error from a credential attack, a dumped file, or a captured handshake can
carry sensitive data. **Do not put a secret into an error message or a variant's
`Display`.** Carry an identifier or a fingerprint, not the plaintext, and redact
at the boundary. This is the error-handling half of
[security.md](./security.md) section 4.

```rust
// Bad — the message leaks the password
#[error("login succeeded with password {password}")]

// Good — say what happened, not the secret
#[error("weak credential accepted for user {user}")]
```

---

## Representing a tool's error

A child tool fails with an exit code and output. Keep both, so a caller can
branch and a report can show what happened, and treat the output as data
(security.md section 5).

```rust
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("{tool} exited with code {code}")]
    ToolFailed { tool: String, code: i32, stderr: String },

    #[error("{tool} is not available")]
    ToolMissing { tool: String },
    // ...
}
```

A missing or wrong-version tool is `ToolMissing`, an honest error, never a silent
skip that lets a run report PASS (verdict-soundness).

---

## Classifying errors: recoverable vs fatal

Classify an error by whether the operation can be retried without rebuilding.

- `Recoverable`: a corrupt or dropped response, a transient network fault, one
  target among many being down. Skip it, record it, continue.
- `Fatal`: the environment or a guarantee is broken. **A failed boundary
  self-check, a scope violation, or a lost isolation is always fatal**: the run
  stops, because continuing past it risks the one failure off the scale
  (security.md section 0).

Where a wrapper error type wraps a lower one with `#[from]`, delegate the
classification to the inner error.

---

## Nesting errors

### Wrap a lower layer's error with `#[from]`

```rust
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("environment: {0}")]
    Environment(#[from] EnvError),

    #[error("capability: {0}")]
    Capability(#[from] CapabilityError),
}
```

### Carry context in fields

Put the target, the step, or the path in the variant's fields so a failure says
where it happened, subject always to the no-secret rule above.

---

## Do not

- Do not use `unwrap()` / `expect()` in library code (tests and a true
  `// INVARIANT:` `expect` excepted).
- Do not put a secret, a credential, or captured plaintext in an error message.
- Do not silently swallow an error. If you must ignore one, `log::warn!` it
  (redacted). See [logging.md](./logging.md).
- Do not return string-only errors. Use a meaningful variant.
- Do not treat a scope or isolation failure as recoverable.
