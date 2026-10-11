# Logging

## Principles

- Use only the `log` crate (v0.4) in library code. Do not initialize a backend
  (`env_logger`, etc.) inside a library; that is the binary's job.
- Prefer a structured message: prose plus `key=value` pairs, keys snake_case.
- **Never log a secret.** This outranks every other logging rule.

---

## Never log sensitive data

A log line is the easiest place a credential leaks. Before a value is logged,
ask whether it is a secret: a password, a token, a key, a session cookie, a
captured hash or handshake, a response body that may contain any of these. If it
is, it does not go to the log, to stdout, or into a diagnostic. Log an
identifier or a fingerprint instead.

```rust
// Bad
log::info!("cracked user={user} password={password}");

// Good
log::info!("weak credential accepted user={user}");
```

When in doubt, redact. A value redacted that did not need to be is a minor loss;
a secret logged is a real one.

---

## Choosing a log level

### `log::error!`

A fatal condition the process cannot continue past. Rare in library code; prefer
returning `Result::Err`. A broken isolation or a scope violation is logged at
`error!` **and** ends the run (security.md section 0).

### `log::warn!`

- A single target among many was unreachable and skipped.
- A tool returned a partial or unparseable result and the observation was
  down-ranked to Inconclusive rather than trusted.
- An error was deliberately ignored.

```rust
log::warn!("target skipped target={target} reason=connection_reset");
```

### `log::info!`

Lifecycle: environment created, boundary self-check passed, a scenario started or
finished, a verdict reached.

```rust
log::info!("boundary self-check passed segments=3 denied_paths=2");
```

### `log::debug!`

Immediately before or after invoking a tool: the argv (redacted) and the exit
code. Do not log a per-connection line in a sweep; that volume is enormous.

### `log::trace!`

Fine-grained steps. Not for routine use.

---

## Message format

Prose plus `key=value`, keys snake_case, values as-is (no quotes), secrets never.

```
// Good
"capability executed cap=tcp_connect target=db:5432 observation=unreachable confidence=high"
"tool invoked tool=nmap exit=0 open_ports=2"

// Bad
"Did the scan"
"cracked password: hunter2"
```

---

## Do not

- Do not log, print, or diagnose a secret, a credential, or captured plaintext.
- Do not use `println!` / `eprintln!` in library code.
- Do not initialize a logging backend inside a library.
- Do not emit a log line per connection or per response in a sweep; aggregate, or
  use `trace!`.
- Do not swallow an error and log nothing; `log::warn!` it, redacted.
