# Unsafe Code Conventions

## Principles

- The default is **no `unsafe`**. Reach for a safe crate before a raw syscall:
  raw-socket and packet-crafting needs are met by maintained crates, and binding
  a C tool's library is a last resort behind a vetted `-sys` crate, not hand-
  rolled FFI.
- **The pure model layer contains no `unsafe`.** The verdict oracle, the evidence
  record, scope and intensity are safe Rust, full stop. `unsafe` there is a
  review stop.
- Where `unsafe` is unavoidable (a `-sys` binding, a raw socket that no safe
  wrapper covers), **isolate it** in a clearly named module kept `pub(crate)`,
  and do not leak it through a `pub` function: the external API stays entirely
  safe.
- Every `unsafe` block and `unsafe impl` has a `// SAFETY:` comment stating why
  it is sound. An `unsafe` block without one is a review stop.
- A change that adds or alters `unsafe` **logic** (ownership, lifetime, a raw
  pointer, `Send`/`Sync`) is a tier-2 review (`isolation-safety` and
  `verdict-soundness` both care, because a memory bug in a security tool is its
  own vulnerability).

## Lints

The workspace sets `unsafe_code = "warn"`, not `forbid`, because a future `-sys`
binding or a raw-socket primitive may legitimately need it. Keep it confined to
the one module that owns it; everything else stays `unsafe`-free. If a milestone
adds no such need, there is no `unsafe` in the tree and the warning never fires.

---

## SAFETY comments

Immediately before an `unsafe` block, write the soundness argument.

```rust
// SAFETY: `buf` is exactly `len` bytes, allocated just above and not aliased,
//         and the syscall writes at most `len` bytes into it.
let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), len, 0) };
```

A `// SAFETY:` comment is a claim (CLAUDE.md). If it states what a syscall or a
binding does, check it against the real contract, not a memory of it.

---

## Raw pointers and ownership (only where a binding forces it)

- Wrap a raw pointer in `Option<NonNull<T>>` or a newtype; do not hold a bare
  `*mut T` as a struct field.
- Free in `Drop`, and null the pointer with `take()` so it cannot be freed twice.
- On every early return and `?`, release any raw resource acquired earlier in the
  same function.

## Send / Sync

- Do not `unsafe impl Send`/`Sync` to paper over a sharing bug. If a type is not
  `Send`, give each task its own rather than forcing it across a boundary.
- Where a binding's type is movable between threads but not concurrently usable,
  `unsafe impl Send` with a SAFETY comment is allowed; do not then also claim
  `Sync`.

---

## Do not

- Do not add `unsafe` to the pure model layer.
- Do not expose `unsafe` through a `pub` function; keep the safe API safe.
- Do not write an `unsafe` block without a `// SAFETY:` comment.
- Do not hand-roll FFI or a raw syscall where a maintained safe crate exists.
