---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Own the network boundary in the framework and drive Docker with bollard

## Context and Problem Statement

The thing being tested is the network boundary itself, so the framework must own the boundary rather than delegate it. How is the isolated environment (attacker, targets, boundaries) defined, created, and destroyed, and how is Docker driven?

## Decision Drivers

* The boundary is the object under test, so it cannot be left to a user's compose file.
* Redefining the targets' contents too would double-manage existing app assets and raise the barrier to adoption.
* Segment and boundary control plus an ephemeral lifecycle need to be driven precisely from code.

## Considered Options

* Definition model: (1) boundary in compose; (2) framework owns both boundary and target contents; (3) hybrid, framework owns segments/boundaries/attacker/lifecycle, user references existing images or compose services for target contents.
* Orchestration: (i) bollard (Rust Docker API client); (ii) shelling out to the docker CLI; (iii) testcontainers-rs.

## Decision Outcome

Chosen: definition Option 3 and orchestration (i) bollard. The framework owns the segments, the boundaries, the attacker placement, and the ephemeral create/destroy; the user supplies target contents by reference. bollard drives network creation, container placement, boundary control, and teardown type-safely, avoiding the CLI's brittle output parsing and testcontainers-rs's weak segmentation control. MVP starts at two segments (`internet`/`internal`) with `web`/`api`/`db`; DMZ, VPN, multiple segments, and routing are added later.

MVP shape (first built here): an `environment` module holds `Segment`, `Workload { name, image, segment, kind }`, `Boundary { from, to, allow }`, and `Environment`, built through `Environment::builder()` (valid by construction). A workload's `kind` is a `Standin` (kept alive by `sleep`, running no service, the boundary demo's placeholders) or a real `Service` running the image's own command or an explicit one (#46), so the lab can stand up a real listening app, not only inert placeholders. `build` validates references (every boundary and workload segment, and the vantage, is declared; names unique) returning `Error::InvalidEnvironment`. The model refuses a non-empty `allow` fail-closed, because the membership-only MVP (ADR-0011) cannot enforce a port-level permission and an unenforceable opening must be inexpressible, not left for a downstream unit to refuse. The YAML/DSL definition format and the `compose(...)` source are deferred (M2); the MVP builds the environment in code.

### Confirmation

Reference and name validation and the non-empty-`allow` refusal are guarded in `crates/redstep/src/environment.rs` (`a_boundary_with_a_nonempty_allow_is_refused`, the name-validation tests, `vantage_segment_must_be_set_and_declared`). Bring-up and teardown are guarded by `brings_up_and_tears_down_the_mvp_lab` in `crates/redstep/tests/environment.rs`, whose structural `internal == Some(true)` assertion fails if `bring_up` drops the egress-less flag (Docker, confirmed on the CI Linux leg).

### Consequences

* Good, the boundary is first-class and precisely controlled; target contents reuse existing assets.
* Bad, bollard ties the orchestrator to the Docker API; a provider abstraction for mock/real backends is deferred (ADR-0013, M4).
* What would reverse this: a compose-owned boundary proving sufficient (it is not, the boundary is the object under test).

## Pros and Cons of the Options

### Definition Option 1 (compose owns the boundary)

* Good, familiar. Bad, the object under test is delegated, the fundamental weakness.

### Definition Option 2 (framework owns everything)

* Good, full control. Bad, doubles app-asset management, raising the adoption barrier.

### Definition Option 3 (hybrid)

* Good, framework owns the boundary, user references existing assets. Bad, an integration layer to adopt a compose service while ignoring its network definition.

### Orchestration bollard vs CLI vs testcontainers

* bollard: type-safe, precise. CLI: brittle output parsing. testcontainers-rs: too weak for complex segmentation.

## More Information

Was "Decision C" in the retired `design-decisions.md`; the lab model settled in #17, bring-up/teardown in #18/#19. Code: `crates/redstep/src/environment.rs`, `crates/redstep/src/orchestrator.rs`. Open: the definition format, the compose-adopt logic, how the firewall gateway is built on Docker networks, VPN boundaries.
