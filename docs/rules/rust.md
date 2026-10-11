# Rust Coding Standards

## References

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)

---

## Formatting

- Use `rustfmt` with its default settings.
- The gate runs `cargo fmt --all --check` and blocks on violations.

## Naming

| Target | Convention | Example |
|---|---|---|
| Types / traits | UpperCamelCase | `Capability`, `AttackerState` |
| Functions / methods | snake_case | `resolve_target`, `run_scenario` |
| Constants | SCREAMING_SNAKE_CASE | `DEFAULT_INTENSITY` |
| Modules / files | snake_case | `scope_gate`, `scope_gate.rs` |

Use the domain's own words, fixed by `docs/specs/design-decisions.md`: verdict,
observation, expectation, evidence, success witness, capability, intensity,
scope, foothold, pivot, segment, boundary. Do not invent a synonym for one of
these; a second vocabulary is the `naming` lens's first finding.

## Module layout

```
src/
  lib.rs          <- public API surface (via `pub use`)
  error.rs        <- error type definitions
  {feature}/
    mod.rs        <- public types/functions
```

The pure model layer (evidence, verdict, scope, intensity) carries no I/O: no
`tokio`, no `bollard`, no process spawning. Keep network and Docker code in the
layers above it (see [design.md](./design.md)).

## Builder pattern

Consuming builders (they take `self`). `.build()` returns `Result<T, Error>`, and
for a safety-relevant object it is where the scope and intensity are resolved, so
an unvalidated one cannot exist. See [design.md](./design.md).

## Visibility

| Scope | Use |
|---|---|
| `pub` | exposed outside the crate |
| `pub(crate)` | used only within the crate |
| `pub(super)` | exposed only to the parent module |
| none | module-internal |

Keep the surface small. A capability's internals, an adapter's output parser, and
anything that holds a secret are not `pub`.

---

## Concurrency & runtime

- redstep is **async** where it waits on the network, Docker, or a child tool:
  use `tokio`. Keep blocking work (a CPU-bound parse, a child process that only
  offers a blocking API) off the async runtime with `spawn_blocking`.
- **Bound concurrency against a target.** Firing thousands of simultaneous
  connections at a lab target is a denial of service, not a test. Cap parallel
  actions per target; make the cap explicit, not accidental.
- Do not share a mutable tool session or a Docker handle across tasks without
  synchronization. Prefer giving each task what it owns.

---

## Cross-platform

The author's machine is Windows; CI and the lab are Linux. Keep code portable.

- File paths use `std::path::Path` / `PathBuf`. Never write OS separators as
  string literals.

```rust
// Bad
let p = dir.to_string() + "/evidence.json";
// Good
let p = dir.join("evidence.json");
```

- Localize an OS-specific branch behind an abstraction rather than scattering
  `cfg!(windows)` through the logic.

---

## Code quality

### Prefer iterators over manual loops

```rust
let open_ports: Vec<_> = results.iter()
    .filter(|r| r.reachable())
    .map(|r| r.port())
    .collect();
```

### Annotate non-obvious clones

```rust
// clone required: the spawned task needs an owned 'static value
let target = scoped.clone();
```

### `unsafe` requires justification

redstep is almost entirely safe code. Where `unsafe` is genuinely needed, every
block carries a `// SAFETY:` comment. Details in [unsafe.md](./unsafe.md).

### No dead code on committed branches

Remove unused `use` / functions / variables. `#[allow(dead_code)]` needs a reason
comment.

---

## Comments

- Comments explain **why**, not the obvious **what**. Where a decision settled it,
  name the decision (`See Decision J.`) rather than restating it.
- A comment is a claim (CLAUDE.md). If it says what a tool's output means, or that
  a target is unreachable, it is checkable, so check it.

```rust
// OK — non-obvious why
// A closed connection and a filtered port look the same from a bare connect;
// we down-rank the observation's confidence rather than call it unreachable.

// Bad — obvious what
// connect to the port
```

---

## Do not

- Do not use `unwrap()` / `expect()` in library code (under `src/`), except a
  true, construction-guaranteed invariant with an `// INVARIANT:` comment, or
  under `#[cfg(test)]`. See [error-handling.md](./error-handling.md).
- Do not use `println!` / `eprintln!` in library code; use `log::` and redact
  (see [logging.md](./logging.md)).
- Do not build a shell command from untrusted input, or let a raw address reach a
  capability. See [security.md](./security.md).
- Do not create circular dependencies; dependency direction is in
  [design.md](./design.md).
