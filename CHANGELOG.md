# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0, a breaking change raises the minor version, following Cargo's `0.x`
compatibility rule.

## [Unreleased]

## [0.2.0] - 2026-10-30

Native Web/API security checks. The single SQL-injection technique from v0.1.0
becomes a shared app-security seam, and the common Web/API techniques are built
on it, each as a real exploit -> capture -> fix -> replay loop against your own
app, recorded with ATT&CK/OWASP tags. It also adds the out-of-band canary channel
that makes a server-side-only success observable.

### Added

- Native path-traversal check, extracting a shared HTTP witness seam from the
  SQL-injection check so every body-marker technique runs one probe, marker
  witness, and scope path ([#63](https://github.com/itsakeyfut/redstep/issues/63)).
- Native IDOR / broken-access-control check ([#64](https://github.com/itsakeyfut/redstep/issues/64)).
- Native SSRF check, witnessed out-of-band by an in-lab canary that records a
  coerced callback and attributes the finding to the app rather than the canary
  ([#65](https://github.com/itsakeyfut/redstep/issues/65), ADR-0023).
- Native OS command injection check ([#85](https://github.com/itsakeyfut/redstep/issues/85)),
  and a blind, out-of-band variant whose success is a server-side callback to the
  canary rather than anything in the probe's own response
  ([#87](https://github.com/itsakeyfut/redstep/issues/87)).
- Native server-side template injection (SSTI) check ([#90](https://github.com/itsakeyfut/redstep/issues/90)).
- Each native check runs the full exploit -> capture -> fix -> replay loop against
  the playground, paired with a positive control that the fixed target still
  performs its benign function ([#66](https://github.com/itsakeyfut/redstep/issues/66)).
- An ATT&CK/OWASP attack catalog under `docs/attacks/`, naming each technique, its
  tags, and the capability that exercises it (ADR-0016).

### Changed

- Consolidated the body-marker and out-of-band witness classifiers into one
  fail-closed classifier, with a reusable canary-log poll primitive, so the
  verdict mapping the project most needs to protect lives in one place
  ([#75](https://github.com/itsakeyfut/redstep/issues/75)).
- The Docker-gated lab tests default-skip locally and are opted in by CI, so a
  routine local run creates no lab containers
  ([#98](https://github.com/itsakeyfut/redstep/issues/98)).

### Fixed

- The command-injection fix-replay positive control no longer passes over a
  broken endpoint ([#91](https://github.com/itsakeyfut/redstep/issues/91)).

### Internal

- Offline guards for the diagnostic gate and the draft capability across every
  native check, and a drifted cross-boundary constant fails a pure test rather
  than only a self-skipping Docker one
  ([#88](https://github.com/itsakeyfut/redstep/issues/88)).

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

[Unreleased]: https://github.com/itsakeyfut/redstep/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/itsakeyfut/redstep/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/itsakeyfut/redstep/releases/tag/v0.1.0
