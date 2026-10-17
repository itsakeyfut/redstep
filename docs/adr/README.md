# Architecture Decision Records

A cross-cutting design decision's rationale lives here, in one record each, and
nowhere else. The documents in [`docs/`](../roadmap/roadmap.md) say what the
project wants to build, and the doc comments in the code say what each type is
and the local reason it is shaped that way. Neither repeats the reasoning: they
link here.

These records began as the lettered decisions A to V (plus H-2 and the MVP scope)
gathered in a single `docs/specs/design-decisions.md`. That file was retired and
each decision became an ADR; the lettered references in the code and the docs now
point at the record the decision became.

These records are written in **English**, like the code they constrain, because
they are read by contributors and tooling alike.

Format: [MADR 4.0](https://adr.github.io/madr/), the de facto Markdown ADR
standard. Copy [`adr-template.md`](./adr-template.md) to start one.

## Index

| # | Decision | Status | Confirmed by |
|---|---|---|---|
| [0001](./0001-write-security-tests-in-rust-and-attack-scenarios-in-a-dsl.md) | Write security tests in Rust and attack scenarios in a declarative DSL | accepted | the runner tests (exit code, classify) in `crates/redstep/src/runner.rs` and discovery in `tests/public_api.rs`; the DSL is Phase 3, confirmed by nothing yet |
| [0002](./0002-unify-capabilities-behind-one-trait-gated-by-intensity.md) | Unify native primitives and tool adapters behind one Capability trait, gated by Intensity | accepted | the intensity-gate and classification tests in `context.rs` and `capability/tcp_connect.rs`, and the vantage probe in `orchestrator.rs` (Docker, CI leg); tool adapters are Phase 4 |
| [0003](./0003-own-the-network-boundary-and-drive-docker-with-bollard.md) | Own the network boundary in the framework and drive Docker with bollard | accepted | environment validation in `environment.rs` and bring-up/teardown in `tests/environment.rs` (Docker, CI leg) |
| [0004](./0004-record-evidence-as-an-append-only-fact-project-the-graph-from-it.md) | Record evidence as an append-only atomic fact, and project the attack graph from it | accepted | the JSON-shape, append-only, and id-resolution guards in `evidence.rs`, `context.rs`, and `tests/public_api.rs` |
| [0005](./0005-render-every-report-from-one-canonical-json.md) | Render every report from one canonical JSON | accepted | the canonical-JSON, exit-code, and two-renderer guards in `report.rs` and `tests/public_api.rs` |
| [0006](./0006-guarantee-safety-in-independent-layers.md) | Guarantee safety in independent layers, not one check | accepted | the scope near-miss and intensity-gate guards in `scope.rs`/`context.rs`, and the egress-less structural guard in `tests/environment.rs` (Docker, CI leg) |
| [0007](./0007-integrate-tools-as-a-plugin-with-three-role-contracts.md) | Integrate existing tools as a plugin with three role contracts | accepted | nothing yet (Phase 4+); the first adapter's ADR will name the guard |
| [0008](./0008-reuse-vulnerable-apps-and-own-the-reference-topology.md) | Reuse existing vulnerable apps, own the reference topology, no education layer | accepted | nothing yet (Phase 5+); the MVP three-tier is a fixture |
| [0009](./0009-emit-an-executable-rustc-style-fail-diagnostic-from-the-oracle.md) | Emit an executable, rustc-style FAIL diagnostic from the oracle | accepted | `check_failure_carries_a_diagnostic` in `context.rs` (mutation: leave `diagnostic` None on a failing check) |
| [0010](./0010-separate-observation-from-verdict-and-default-to-high-confidence.md) | Separate observation from verdict, and require High confidence by default | accepted | `default_requires_high_confidence` in `expectation.rs`, `aggregate_is_fail_closed` / `inconclusive_run_exits_nonzero` in `runner.rs` |
| [0011](./0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md) | Enforce boundaries by membership, add a firewall only where needed, self-check before any test | accepted | `check_refuses_when_a_non_first_workload_is_reachable` and `a_connected_lab_is_refused_before_any_test_runs` (Docker, CI leg); `check_boundaries` offline with an injected prober |
| [0012](./0012-model-the-attacker-state-as-a-growing-asset-set.md) | Model the attacker's state as a growing asset set, identified with the attack graph | accepted | nothing yet beyond the skeleton (Phase 5) |
| [0013](./0013-handle-only-what-can-be-both-mocked-and-run-for-real.md) | Handle only what can be both mocked and run for real, two backends per workload | accepted | nothing yet (M4); the wireless non-goal is held by its absence |
| [0014](./0014-do-not-assume-ci-gating-report-and-evidence-are-primary.md) | Do not assume CI gating; report and evidence are primary | accepted | the deterministic runner exit (ADR-0010 guards); the discovery/replay split is Phase 5 |
| [0015](./0015-run-ai-testing-in-two-modes-with-a-discovery-to-code-promotion.md) | Run AI testing in two modes with a discovery-to-code promotion | accepted | nothing yet (M5) |
| [0016](./0016-tag-attacks-with-attack-and-owasp-optional-but-first-class.md) | Tag attacks with ATT&CK and OWASP, optional but first-class, unmapped allowed | accepted | nothing yet (M2) |
| [0017](./0017-make-external-and-assume-breach-vantages-first-class.md) | Make both external and assume-breach vantages first-class | accepted | the external vantage in `tests/environment.rs` (Docker, CI leg) and `vantage_segment_must_be_set_and_declared` offline; assume-breach is Phase 5 |
| [0018](./0018-manage-attack-data-as-version-pinned-packs.md) | Manage attack data as version-pinned packs, updated explicitly | accepted | nothing yet (Phase 4+) |
| [0019](./0019-build-the-attacker-image-from-a-pinned-base-and-tool-profiles.md) | Build the attacker image from a digest-pinned base and composable tool profiles | accepted | nothing yet (Phase 4+) |
| [0020](./0020-treat-a-c2-session-as-a-foothold.md) | Treat a C2 session as a foothold and integrate C2 via the plugin | accepted | nothing yet (Phase 9) |
| [0021](./0021-govern-distribution-by-risk-tier.md) | Govern distribution by risk tier, connected at the scope gate | accepted | nothing enforced yet; the baseline documents are the artifact |
| [0022](./0022-capture-a-success-witness-and-generate-a-pinned-replay.md) | Capture a success witness and generate a pinned replay from it | accepted | nothing yet (first piece is #29; Phase 5) |
| [0023](./0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md) | Capture an out-of-band witness at an in-lab canary | accepted | SSRF check (#65): ssrf_exploit_from + the canary, attributed to the target |

**By status**: accepted: 0001, 0002, 0003, 0004, 0005, 0006, 0007, 0008, 0009, 0010, 0011, 0012, 0013, 0014, 0015, 0016, 0017, 0018, 0019, 0020, 0021, 0022, 0023 · proposed: none · superseded: none

Records are numbered consecutively from `0001`. The lettered decisions A to V (with H-2) are now the records above; the retired `design-decisions.md`'s "Decision MVP" was scope, not a decision, and lives in [`docs/roadmap/mvp.md`](../roadmap/mvp.md).

## Where each kind of writing belongs

| Location | Holds | Does not hold |
|---|---|---|
| [`docs/*.md`](../roadmap/roadmap.md) (`specs/`, `roadmap/`, `research/`) | what the project wants to build: the concept, the safety and scope model, the architecture, the milestones | how a decision was reached. These are intent documents, not specifications, and a design may knowingly diverge from one. Say so in the record and update the document in the same change |
| doc comments in the code | what a type is, how to use it, and the local reason it is shaped that way | cross-cutting rationale; link to the ADR instead |
| `docs/adr/**` | why a cross-cutting decision was chosen, when, and what would reverse it | type or signature detail; link to the code |

## When to write one

A record is a cache of reasoning that the code cannot show. The question that
decides whether to open one is whether someone will later undo this in good
faith: reading the code, seeing something that looks better, and having no way to
find out what it costs.

* Two or more implementations are possible and one is chosen, especially when the
  choice shapes an interface that later milestones will be written against.
* A choice affects whether redstep can be *trusted about its own answer*:
  anything that decides when a result is PASS, FAIL or Inconclusive, what counts
  as enough signal to conclude, what evidence is recorded, or where an action is
  allowed to run or reach. Getting one of these wrong makes redstep report a
  false PASS, a missed finding dressed as safety (CLAUDE.md row 6), or lets an
  action escape its scope or the lab, which is off CLAUDE.md's scale entirely.
  These are the records worth the most.
* The code was knowingly left in a shape that looks wrong: a duplication kept on
  purpose, a slower path chosen for a reason, a guard that appears redundant.
  Without a record these are cleaned up by the next person to read them.
* An existing decision is reversed: write a new record, mark the old one
  `superseded by ADR-NNNN`, and note what changed.
* A design knowingly diverges from a document in `docs/`: record why, and update
  that document in the same change.
* You are about to write "undecided" into a doc comment: open one as `proposed`.

## When not to write one

A reason has cheaper places to live, and each of these is a complete answer on
its own:

1. Nothing. The decision is local and the code already shows it.
2. A comment where it happens.
3. A doc comment on the type or function it constrains.
4. A test whose name states the rule.
5. A record here.

Take the lowest one that holds. This repository leans hard on 4: a test named for
the rule it protects is how most decisions here are written down, and the
mutation that makes it fail is the proof it is a real rule (a guard the compiler
holds, an `E0004` or an `E0502`, is better still). Open a record only when the
reasoning does not fit into a name and an assertion, which usually means the
rejected alternatives are the part worth keeping.

Specifically, do not open one when:

* It affects one call site, or it is formatting.
* Reversing it would be cheap and local. The record earns its keep by making a
  reversal informed, so a reversal that costs an afternoon does not need one.
* A test name already says it, and someone who broke the rule would read that
  name and understand what they broke.
* The choice was made for us, by Docker or bollard's behaviour, by a tool's
  actual output, by a dependency's interface, or by the platform. Writing that
  down records a fact rather than a decision, and a fact belongs in the doc
  comment or the test that observed it.
* It is a performance choice a benchmark can settle. The benchmark is the record,
  and it stays true when the numbers change.

Naming is usually below the line too, but it rises above it when the name shapes
an API that the rest of the crate compares against or matches on, because those
are the names that go silently wrong.

**Expected rate.** M1 is dense because it is almost entirely interface, the
model, the capability trait, the evidence record, the runner the later milestones
are written against, and that is the phase where records are worth the most. It
does not continue. Most of what the environment and the tool adapters decide
later is settled by what Docker and the real tools actually do, verified rather
than assumed, or by a measurement. A few records per milestone is the shape to
expect. Weeks with none are the normal case, and several in a week is a sign the
bar has slipped rather than a sign of progress.

## Conventions

* Filename `NNNN-short-slug.md`, numbers consecutive.
* The four digits are there so that sorting the filenames as text puts them in
  the order they were written. They are not a limit. A number is never reused,
  never renumbered, and stays with a record that is superseded, because it is
  what every link, doc comment and commit message refers to. Widening the padding
  later would break all of those at once, so a log that ever reaches `9999`
  carries on into five digits and fixes its ordering in the index above. A log
  that large is a sign the bar in *When not to write one* was too low.
* MADR statuses: `proposed`, `accepted`, `rejected`, `deprecated`,
  `superseded by ADR-NNNN`.
* Every record fills in **Confirmation**: which test or guard fails if the
  decision is violated, **and the change to the code that makes it fail**. This
  repository verifies guards by breaking the code and watching a named test go
  red, so a record names that mutation. Where the only guard is an integration
  test that self-skips without a Linux Docker daemon, say so: it is confirmed on
  the CI leg, not on a bare `cargo test`. If nothing would fail, say so plainly; a
  decision that looks enforced and is not is worse than one that is honestly
  unenforced.
* A `proposed` status while the codebase already relies on the decision is itself
  a defect; say so in *Context and Problem Statement*.
* Keep the status in sync between an ADR's front matter and its row in this index.
* When a record says something is not yet enforced, and it then is, update
  **Confirmation** in the same change. That section answers what guards the
  decision now, not what was true when it was written, and a record that
  understates its own guards sends the next reader to redo finished work.
* When code a record names moves or is renamed, update the record's pointers to
  it. The reasoning is a record of what was thought at the time and is not
  rewritten, but the pointers are navigation rather than history, and a record
  whose pointers are dead is a record nobody can check.
* Prose here uses no em dashes.

## More Information

* [MADR 4.0](https://adr.github.io/madr/): the template this follows.
* [`adr-template.md`](./adr-template.md): copy this to start a new record.
* [`CLAUDE.md`](../../CLAUDE.md): the failure-row model the trust trigger above
  refers to, and the house style these records follow.
