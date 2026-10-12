# Architecture Decision Records

redstep keeps its design rationale in two tiers. The high-level architecture
decisions, the ones lettered A to V with their MVP notes, live in
[`docs/specs/design-decisions.md`](../specs/design-decisions.md): what shape the
system takes and why. The finer cross-cutting decisions, the ones an
implementation makes that a later milestone is then written against, live here,
one record each. The other documents in [`docs/`](../roadmap/roadmap.md) say what
the project wants to build, and the doc comments in the code say what each type
is and the local reason it is shaped that way. None of these repeats another's
reasoning: they link.

So a record here answers "why was this chosen, when, and what would reverse it"
for a decision too fine-grained to be one of the lettered architecture decisions
but too cross-cutting to live in a single doc comment. When a record refines one
of the A to V decisions, it says which and links to it.

These records are written in **English**, like the code they constrain, because
they are read by contributors and tooling alike.

Format: [MADR 4.0](https://adr.github.io/madr/), the de facto Markdown ADR
standard. Copy [`adr-template.md`](./adr-template.md) to start one.

## Index

| # | Decision | Status | Confirmed by |
|---|---|---|---|

No records yet. redstep's cross-cutting decisions so far are the lettered ones in
[`design-decisions.md`](../specs/design-decisions.md); the first finer decision
that earns a record starts this log at `0001`.

**By status**: accepted: none · proposed: none · superseded: none

Records are numbered consecutively from `0001`.

## Where each kind of writing belongs

| Location | Holds | Does not hold |
|---|---|---|
| [`docs/*.md`](../roadmap/roadmap.md) (`specs/`, `roadmap/`, `research/`) | what the project wants to build: the concept, the safety and scope model, the architecture, the milestones | how a decision was reached. These are intent documents, not specifications, and a design may knowingly diverge from one. Say so in the record and update the document in the same change |
| [`docs/specs/design-decisions.md`](../specs/design-decisions.md) | the high-level architecture decisions (A to V) and their MVP notes: the big cross-cutting choices the whole system rests on | a decision fine enough that it reads as one implementation's call rather than the system's shape; that is an ADR, which may link back to the letter it refines |
| doc comments in the code | what a type is, how to use it, and the local reason it is shaped that way | cross-cutting rationale; link to the ADR or the lettered decision instead |
| `docs/adr/**` | why a cross-cutting implementation decision was chosen, when, and what would reverse it | type or signature detail; link to the code |

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
* An existing decision is reversed. For a lettered architecture decision, that
  supersession happens in place in `design-decisions.md`, with the reason; for an
  ADR, write a new record, mark the old one `superseded by ADR-NNNN`, and note
  what changed.
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
* [`docs/specs/design-decisions.md`](../specs/design-decisions.md): the lettered
  architecture decisions (A to V) an ADR refines or sits beneath.
* [`CLAUDE.md`](../../CLAUDE.md): the failure-row model the trust trigger above
  refers to, and the house style these records follow.
