# redstep

A security-testing framework: drive real attacks against your own apps,
networks, containers and cloud inside an isolated lab, from an attacker's point
of view.

redstep runs real attacks, so it runs them only where they belong: an isolated
lab with no route to the internet or production, a scope gate that refuses any
target not on the allowlist, and an intensity ladder that keeps force behind an
explicit opt-in. Use it only against systems you own or are authorized to test.

You stand up a disposable, isolated copy of your own system and attack it from
the outside in. When an attack succeeds that is a security failure: redstep
captures a success witness, you apply a fix, and a pinned replay confirms the
attack is now blocked.

## Status

v0.1.0 is the first vertical slice (milestone M1): an isolated Docker lab, a
scope gate and intensity ladder, a native TCP reachability capability, a native
SQL-injection exploit -> fix -> replay loop over an HTTP vantage, a Pass / Fail /
Inconclusive verdict oracle, and append-only evidence rendered as canonical JSON
and a rustc-style diagnostic. The public API is not yet stable (pre-1.0).

Docker is required: the lab is built as Docker containers.

See the [repository](https://github.com/itsakeyfut/redstep) and its `docs/` for
the design, the roadmap, and the playground the demos run against.

## License

Dual-licensed under either of MIT or Apache-2.0, at your option.
