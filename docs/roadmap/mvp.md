# MVP and viability

## Purpose

This document defines the MVP — how far the project goes before it is worth deciding whether to keep building it — and the criteria that decision rests on. It is the honest go/no-go checkpoint for a solo project: continue investing toward the long 1.0, or stop and re-scope. The per-release scope lives in the version files ([roadmap.md](./roadmap.md) is the index); this is the viability lens over them, not another scope list.

## What the MVP is

The MVP is the point where redstep can take a developer's **own** application, prove a real attack succeeds against it, and prove that a fix closes it, for the main Web/API techniques, safely inside an isolated lab. That is v0.1.0 (the attack-to-prevention vertical slice) extended by v0.2.0 (the native Web/API security checks).

Below that line there is not enough to judge whether the idea delivers: one technique against a bespoke target proves the machinery, not the value. At that line a developer can point redstep at their own app and get real findings with the fix proven. Above it the question is depth and reach (v0.3.0 onward), which is only worth building if the MVP proves out.

- Constituent releases: [v0.1.0](./v-0-1-0.md), [v0.2.0](./v-0-2-0.md).

## The viability decision (go / no-go)

Continue toward 1.0 only if, at the MVP, all of these hold:

- **Safety (non-negotiable)**: no action escapes its scope or the isolated lab, and there is no egress to real infrastructure. A single failure here is disqualifying regardless of everything else; this is the one property the project refuses to trade.
- **Value**: redstep finds real, actionable issues in a real application a developer would care to fix, not only in the bespoke playground.
- **Reproducibility**: a recorded success replays deterministically, and a fix flips the replay from exploitable to not-exploitable.
- **Performance**: bringing the lab up and running a check completes in a time a developer tolerates in their edit loop and in CI.
- **Sustainable effort**: the per-release cost is sustainable for one developer, because the design (native-first, one shared check seam, one evidence model every report projects from) keeps each new technique cheap to add rather than a bespoke build.

If these do not hold at the MVP, that is the signal to stop or re-scope, not to push on to v0.3.0 and beyond.

## Performance verification

Measured against the playground and against at least one real application, not only the bespoke target:

- Lab bring-up time and per-check wall-clock time, local and in CI.
- Verdict quality on a real app: a false PASS (a missed finding reported as safe) is the failure the project exists to avoid, so it is weighed above a false FAIL; both are recorded.
- Replay determinism: the same witness replays to the same verdict against the same environment.
- The container cost of a run (so a routine run does not exhaust a developer's machine).

## What the MVP is not

- Not the full feature set: network depth, real external tooling, multi-step pivots, cloud and Windows/AD platforms, and AI-driven testing are all post-MVP (v0.3.0 onward), built only if the MVP proves out.
- Not 1.0: 1.0 is a separate and far maturity gate (a real adoption example, mature governance and supply chain), defined in [v-1-0-0.md](./v-1-0-0.md).

## Links

- [Roadmap](./roadmap.md) — the full release sequence and the thematic phases.
- [v0.1.0](./v-0-1-0.md) and [v0.2.0](./v-0-2-0.md) — the releases that constitute the MVP.
- [v1.0.0](./v-1-0-0.md) — the eventual maturity gate the go decision commits toward.
- [ADR index](../adr/README.md) — the settled cross-cutting decisions the MVP is built on.
