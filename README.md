# redstep

A security-testing framework: drive real attacks against your own apps,
networks, containers and cloud inside an isolated lab, from an attacker's point
of view, and find out how far an attacker could actually get.

## Safety first

redstep runs real attacks, so it is built to run them only where they belong.
Every action is confined by independent layers: an isolated lab with no route to
the internet or production, a scope gate that refuses any target not on the
allowlist, and an intensity ladder that keeps force behind an explicit opt-in.
Use it only against systems you own or are authorized to test.

## The idea

You stand up a disposable, isolated copy of your own system, attack it from the
outside in, and watch what a real attacker would reach. When an attack succeeds
that is a security failure, not a pass: redstep captures a success witness, you
apply a fix, and a pinned replay confirms the attack is now blocked.

## Status

v0.1.0 is the first vertical slice (milestone M1): one attack carried end to end,
with the machinery the rest of the project builds on. It ships:

- an isolated Docker lab (egress-less networks, a boundary self-check before any
  attack, automatic teardown);
- a scope gate and an intensity ladder (default-deny, default-safe);
- a native TCP reachability capability, behind the intensity-gated trait;
- a native SQL-injection check over an HTTP vantage, with a full exploit ->
  capture -> fix -> replay loop against a deliberately-vulnerable playground
  target;
- a Pass / Fail / Inconclusive verdict oracle that keeps a weak signal out of a
  confident answer;
- append-only evidence, one canonical JSON every report projects from, and a
  rustc-style failure diagnostic.

What is planned next is in [the roadmap](docs/roadmap/roadmap.md).

## Crates

- `redstep` - the framework (a library and the `redstep` binary).
- `redstep-macros` - its procedural-macro support; not used on its own.

## Requirements

Rust (edition 2024) and Docker (the lab is built as Docker containers).

## Documentation

`docs/` holds the specifications (`docs/specs/`), the roadmap (`docs/roadmap/`),
the settled cross-cutting decisions (`docs/adr/`) and the coding rules
(`docs/rules/`). The `playground/` directory is the vulnerable target the demos
run against.

## License

Dual-licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
