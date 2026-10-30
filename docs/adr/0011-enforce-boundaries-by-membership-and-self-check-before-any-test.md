---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Enforce boundaries by membership, add a firewall only where needed, and self-check before any test

## Context and Problem Statement

The boundary the oracle judges (ADR-0010) has to be built on Docker and its egress-less isolation guaranteed (ADR-0003, ADR-0006). Raw Docker separates by network and blocks egress with `internal: true`, but cannot do L4 port-level allow/deny (connectivity is all-or-nothing). How is a boundary built, and how is a dropped `internal: true` kept from passing silently?

## Decision Drivers

* The First-Prototype boundary holds with membership alone, so the MVP can be light; a real corporate network needs port-level rules.
* Without a self-check, a broken test-bed boundary makes every test a false PASS and voids the whole verification (the ADR-0010 trust concern).
* Both membership and a firewall gateway are buildable from bollard (ADR-0003).

## Considered Options

* Option 1: membership networks only (no port-level boundary ever).
* Option 2: a firewall gateway for every boundary.
* Option 3: layered, membership as the base, a firewall gateway only where a port-level or asymmetric rule is declared, plus a mandatory boundary self-check.

## Decision Outcome

Chosen: Option 3. Segment separation is separate networks, egress is blocked with `internal: true`, and an all-or-nothing boundary needs only that; a port-level or asymmetric boundary gets a firewall-gateway container (nftables/iptables), the framework choosing the minimal mechanism from the declaration. Before any test runs, the framework itself verifies each declared-forbidden path is actually blocked (the self-check), the concrete form of the ADR-0006 isolation proof against a forgotten `internal: true`. MVP is membership-only (two segments) plus a minimal self-check; the firewall gateway, DMZ, and multi-step boundaries are Phase 4.

MVP shape (first built here): `orchestrator::bring_up` creates one `internal: true` network per segment and attaches each workload to its segment's network only, so an unconnected pair is blocked by construction. `orchestrator::boundary_self_check` verifies each forbidden path behaviourally before a run: for *every* workload in the `to` segment, a probe in the `from` segment must fail to reach it by container name over ICMP, while a positive control in the `to` segment reaches it, so a broken probe cannot read as isolation. A reachable forbidden path is `Error::BoundaryViolated`; a failed control or undeterminable probe is `Error::LabUnavailable`, fail-closed. The lab-wired run (`run_in_lab` / `run_in_running_lab`, #28) gates on the self-check before any test and tears down on every path.

### Confirmation

Guarded in `crates/redstep/src/orchestrator.rs`: `check_refuses_when_a_non_first_workload_is_reachable` (mutation: probe only the first `to` workload, so a non-first break is missed), `check_fails_closed_when_the_positive_control_cannot_reach`, `check_fails_closed_when_a_probe_errors`. The run-gate is guarded by `a_connected_lab_is_refused_before_any_test_runs` in `tests/environment.rs` (mutation: remove the gate, so a connected lab returns Ok). The egress-less flag is held structurally by `brings_up_and_tears_down_the_mvp_lab`. The Docker tests are confirmed on the CI Linux leg; `check_boundaries`'s decision logic is guarded offline with an injected prober. The firewall gateway and its port-level probe are Phase 4, confirmed by nothing yet.

### Consequences

* Good, the MVP is light yet its boundary is self-verified before any test, so a forgotten `internal: true` is caught rather than passing as a false "isolated"; the firewall adds port-level rules only where declared.
* Bad, the self-check is membership-only (ICMP by name); a routed or port-level boundary needs the Phase 4 TCP-to-port probe.
* What would reverse this: membership proving enough for every topology (it is not; corporate networks need port rules) or a firewall for every boundary proving simpler (it is heavier for all-or-nothing paths).

## Pros and Cons of the Options

### Option 1 (membership only)

* Good, lightest. Bad, cannot express a port-level corporate boundary.

### Option 2 (firewall everywhere)

* Good, uniform. Bad, a privileged gateway for every all-or-nothing path is heavy.

### Option 3 (layered + self-check)

* Good, minimal mechanism per boundary, and a self-check that stops a false isolated. Bad, two mechanisms plus a self-check to maintain.

## More Information

Was "Decision N" in the retired `design-decisions.md`; the membership layer and self-check settled in #18/#19, the gating in #28. The gateway container landed in #113 and its port-level enforcement and self-check in #114; the "nftables/iptables" mechanism named above is **refined to a TCP proxy by [ADR-0024](0024-realize-the-inter-segment-gateway-as-a-tcp-proxy.md)** (this ADR's membership base and mandatory self-check are unchanged). Code: `crates/redstep/src/orchestrator.rs`, `crates/redstep/src/runner.rs`. Open: VPN boundaries. See ADR-0003 (the environment), ADR-0006 (the isolation layer this proves), and ADR-0024 (the gateway mechanism).
