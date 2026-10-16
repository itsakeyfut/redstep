# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0, a breaking change raises the minor version, following Cargo's `0.x`
compatibility rule.

## [Unreleased]

## [0.1.0] - 2026-10-16

Initial release: the attack-to-prevention vertical slice. redstep drives a real
attack against a deliberately vulnerable target inside an isolated lab, captures
what succeeded, and proves that a fix closes it.

### Added

- Isolated Docker lab: per-segment `internal` networks with no egress, a boundary
  self-check that runs before any attack and refuses to proceed when isolation is
  broken, and RAII teardown that cleans up even on an interrupted run (ADR-0003,
  ADR-0006, ADR-0011).
- Scope gate: a capability receives its target only from the scope resolver, and an
  out-of-scope or unscoped target is a hard error before any action (ADR-0006,
  ADR-0021).
- Intensity ladder: a capability defaults to `Safe`; `Controlled` and `Aggressive`
  require an explicit, unforgeable opt-in (ADR-0002).
- A native TCP reachability capability behind one intensity-gated trait, and an HTTP
  vantage point used by the SQL-injection check.
- A native SQL-injection check with a full exploit -> capture -> fix -> replay loop
  against the playground target, including the redirect and request-authority guards
  that keep the probe inside its scope.
- Pass/Fail/Inconclusive oracle: the observation (what happened) is kept separate
  from the verdict (whether it is acceptable), and a weak or conflicting signal lands
  in Inconclusive rather than a confident PASS (ADR-0010).
- Append-only evidence, one canonical JSON that every report projects from, and an
  executable rustc-style failure diagnostic emitted by the oracle (ADR-0004,
  ADR-0005, ADR-0009).
- A Success Witness that captures enough to replay a success deterministically, with
  a pinned replay (ADR-0022).
- A deliberately-vulnerable playground target (database, API, web) built only as
  Docker images and excluded from the workspace, with a `fixed` build that patches
  the known vulnerabilities for the replay side of the loop.
- Continuous integration: fmt, clippy, doc and the test suite on Linux and Windows,
  plus a Linux leg that builds the playground images so the Docker-gated lab tests
  run instead of self-skipping.

[Unreleased]: https://github.com/itsakeyfut/redstep/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/itsakeyfut/redstep/releases/tag/v0.1.0
