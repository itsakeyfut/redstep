---
status: "accepted"
date: 2026-11-13
decision-makers: the author
---

# Author out-of-crate attack capabilities behind a destination-fixed channel, so escape-scope stays compiler-held

## Context and Problem Statement

The attack techniques (SQLi, SSRF, blind command injection, path traversal, IDOR,
SSTI) are inherent `async fn` on `TestContext` in `crates/redstep/src/context.rs`,
gated at runtime by the crate-private `VantageCleared` proof, with a shared witness
seam in `orchestrator.rs`. #89 (the #110 finale) wants them aggregated into their
own crate, one module per technique, so the catalog in `docs/attacks/` and the code
line up and a later milestone can add techniques without touching the core.

The obstacle is a safety property, not an ergonomic one. The `Capability` trait
(ADR-0002) is sealed (`crates/redstep/src/capability/mod.rs`): an out-of-crate impl
is a compile error, which is what makes "no unreviewed capability can hold a raw
address or run ungated" a property the compiler holds rather than a promise (#9,
the off-scale escape-scope guard of ADR-0006). A sibling `redstep-attacks` crate is,
by definition, out of crate. So the split cannot be done by moving `Capability`
impls across the boundary: Rust has no "workspace-visible" visibility, and a sibling
crate cannot name the `sealed::Sealed` marker. The question this record settles,
which ADR-0007 left open ("whether `CapabilityAdapter` is the same as or contains
the `Capability` trait"), is: what boundary lets attack force live out of crate while
"no action escapes its scope" stays a compile error?

Something depends on this answer while the record is still `proposed`: #89 is blocked
on it, and on the force/recipe carve-out below.

## Decision Drivers

* The escape-scope guarantee (#9, ADR-0006) must stay compiler-held, not degrade to a
  documented promise. A false PASS is CLAUDE.md row 6; an action reaching outside its
  scope is off CLAUDE.md's scale entirely, and is refused rather than ranked.
* The sibling crate runs *inside* the vantage container, which can reach any lab host.
  So fixing "which external host" is not enough: the boundary must fix the destination
  down to the one scope-resolved target, or a technique could direct force at a lab
  host the scope gate never cleared (a scope escape, even without a lab escape).
* The dependency must be one-way: core must not depend on the technique crate, so a
  later milestone can add techniques without recompiling or re-reasoning about core.
* ADR-0007 already names the active-execution tier `CapabilityAdapter` and intends it
  to carry external tools (sqlmap, nmap) later. A first-party out-of-crate technique
  and a tool adapter are the same kind of thing (force that executes as a scenario
  step through the gates), so one boundary should serve both.

## Considered Options

* Option 1: keep the techniques in core, split only into an in-crate `attacks/`
  module tree (no sibling crate).
* Option 2: un-seal `Capability` so a sibling crate implements it directly.
* Option 3: a new public `CapabilityAdapter` trait that receives a core-constructed,
  destination-fixed channel; all force and the gate stay sealed in core; three-layer
  dependency (core, attacks, a top layer that registers).

## Decision Outcome

Chosen: Option 3. `Capability` stays sealed and keeps its role: host in-process,
`Safe`-only measurement primitives (`TcpConnect`), which run with a route to
everything and so must stay in core. The cross-crate boundary is a new, *public*
(unsealed) `CapabilityAdapter` trait. A `CapabilityAdapter` never holds a
`ScopedTarget`, never mints a gate, and never opens a socket; core does all three,
then hands the adapter a `VantageChannel` whose destination is already fixed to the
one scope-resolved target. The adapter chooses only the payload it sends and
interprets the response into a normalized `Observation` + `EvidenceDraft`. The
escape-scope guarantee therefore relocates from "`Capability` is sealed" to "the
channel's destination, and the constructors of `ScopedTarget`, the gate proof and
the channel, are all core-private": a sibling crate that tries to name any of them
does not compile.

The dependency is three-layer: `redstep` (core: the `CapabilityAdapter` trait, the
gate, the channel, the orchestrator holding `dyn CapabilityAdapter`, and the sealed
`Capability` primitives); `redstep-attacks` (concrete techniques implementing
`CapabilityAdapter`, depending on core); and a top layer (the binary or a scenario
crate) that depends on both and registers the techniques into core's runner. Core
names its own trait, never the technique crate, so the dependency stays one-way, and
the same trait is what ADR-0007's tool adapters (sqlmap, nmap) implement later.

This answers ADR-0007's open question: `CapabilityAdapter` is **separate from**
`Capability`, not the same and not containing it. They are two tiers, split by where
they run and what force they carry: `Capability` is the sealed in-process host
primitive, `CapabilityAdapter` is the public, gated, destination-fixed boundary for
everything that executes out of crate.

Load-bearing prerequisite: today's techniques are not pure recipes. They drive the
vantage container themselves (the shared seam: `wget_cmd`, `run_probe_capturing`,
`poll_logs_for_token`, `classify_witness_shared`). The `VantageChannel` can only fix
the destination if core, not the technique, builds the request to the scoped address
and the technique supplies the payload (path, params, body). That split is the
probe-inputs carve-out noted at `orchestrator.rs:1514` and deferred to v0.4.0 (#133);
it is a safety prerequisite of this boundary, not a later
nicety, because a channel that exposed raw vantage `exec` would let a technique pick
the destination. A companion, not the same work, is #123 (bind the vantage gate's
intensity by type): when `CapabilityAdapter` gains its gate, binding that gate's
intensity by type is exactly what #123 describes for the vantage path. The sequence is
therefore this ADR, then the carve-out (#133), then the crate split (#89).

### Confirmation

Nothing in the tree yet: the crate split is #89, blocked on this ADR and the
probe-inputs carve-out above (#133). The guarantee was measured on a throwaway three-crate prototype
(`core` / `attacks` / `app`) built during this record's design and since removed. In
it, the sibling `attacks` crate's attempts to escape scope were all compile errors:

| Mutation in the sibling crate | Error |
|---|---|
| `ScopedTarget::new("evil.example.com:443".into())` | `E0624` (private associated function) |
| `Cleared::issue()` (forge a gate proof) | `E0624` |
| `VantageChannel::new(&t, &c)` (open a channel to a chosen destination) | `E0624` |
| read `chan.target` (the fixed destination, to redirect) | `E0616` (private field) |

The happy path compiled and ran: `attacks` depended on `core` one-way, the top crate
registered a technique into core's `dyn CapabilityAdapter` runner, and the technique
chose the payload while core fixed the destination. When #89 is built, these become
`compile_fail` doctests or `trybuild` cases on the real boundary. The mutation that
makes any of them pass, and so would reverse the guarantee, is making the relevant
constructor or the destination field `pub`.

### Consequences

* Good: the escape-scope guarantee stays compiler-held across a crate boundary, so
  attack force can live out of crate (first-party now, tool adapters later) without
  relaxing #9. The same trait serves ADR-0007's `CapabilityAdapter` tier.
* Good: the one-way dependency lets a later milestone add techniques without touching
  or recompiling core.
* Bad: it requires the probe-inputs force/recipe carve-out (#133) as a
  prerequisite, and it requires `CapabilityAdapter` to be object-safe (`dyn`) with
  `async`, which `Capability` deliberately avoids today (manual future boxing or
  `async-trait` at the registry).
* What would reverse this: a single sealed in-crate trait proving enough because no
  out-of-crate authoring (first-party or tool) is ever wanted, which would make
  Option 1 correct and this boundary unused surface.

## Pros and Cons of the Options

### Option 1 (in-crate module split only)

* Good: the seal stays intact with no new surface; simplest; delivers the catalog
  mirroring and the registry now.
* Bad: no out-of-crate authoring ever, so it does not deliver the plugin boundary
  ADR-0007 wants, and the eventual crate split still faces this same question.

### Option 2 (un-seal `Capability`)

* Good: the crate split becomes a plain move of `Capability` impls.
* Bad: removes the compiler-held escape-scope guard (#9). An out-of-crate impl could
  hold a `ScopedTarget` or mint a gate; the guarantee drops to a documented promise,
  which is CLAUDE.md's trust-defect case and, for scope, off its scale. Refused.

### Option 3 (public `CapabilityAdapter` + destination-fixed channel)

* Good: escape-scope stays a compile error (relocated to core-private constructors),
  the boundary is one-way, and it unifies first-party techniques with tool adapters.
* Bad: needs the probe-inputs carve-out (#133) first and `dyn`/`async` on the trait.

## More Information

Settles the "`CapabilityAdapter` same as or contains `Capability`" question left open
in [ADR-0007](./0007-integrate-tools-as-a-plugin-with-three-role-contracts.md);
specializes the `Capability` abstraction of
[ADR-0002](./0002-unify-capabilities-behind-one-trait-gated-by-intensity.md); rests on
the escape-scope guarantee of
[ADR-0006](./0006-guarantee-safety-in-independent-layers.md) and the sealing rationale
in `crates/redstep/src/capability/mod.rs`. Depends for implementation on the
probe-inputs force/recipe carve-out (#133; noted at `orchestrator.rs:1514`, v0.4.0),
with #123 (bind the vantage gate's intensity by type) as its companion, and is the
precondition of the crate split (#89, under #110). The
reachability-is-not-a-host-capability constraint is RK-008 in
`.claude/review/knowledge.md`.
