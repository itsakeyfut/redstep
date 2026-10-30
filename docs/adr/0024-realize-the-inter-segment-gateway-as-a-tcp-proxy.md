---
status: "accepted"
date: 2026-10-30
decision-makers: the author
---

# Realize the inter-segment gateway as a TCP proxy, not a packet filter

## Context and Problem Statement

[ADR-0011](0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md) decides a layered boundary: membership networks as the base, a firewall-gateway container where a port-level or asymmetric path is declared, and a mandatory self-check before any test. It named the gateway's mechanism as "nftables/iptables". Implementing the enforcement (#114) on top of the gateway container (#113) forced the mechanism to be concrete, against how redstep actually observes reachability: the vantage probe (`tcp_reachable_from`) connects to a scope-resolved `workload:port` *by name* from a container on the attacker's segment. How is a port-level east-west boundary enforced so that this name-based probe sees exactly the allowed paths, and no more?

## Decision Drivers

* The reachability probe connects by workload name on its own segment's network; a cross-segment target neither resolves (Docker's embedded DNS is per-network) nor routes (the segments are separate `internal` networks).
* The dangerous failure is a boundary that reads enforced but is not: a false "contained", off CLAUDE.md's scale.
* The gateway runs only on egress-less lab networks (ADR-0006 layer 1), so its blast radius is bounded whichever mechanism is chosen.
* The mechanism must be verifiable by the self-check with a positive control and per-element coverage (ADR-0011, RK-008/RK-009).

## Considered Options

* Option 1: nftables packet filter on the gateway — `ip_forward`, client-route injection into the probe containers (or DNAT with the target aliased to the gateway), NET_ADMIN, conntrack. Faithful to ADR-0011's wording.
* Option 2: a TCP proxy on the gateway — aliased with each allowed workload name on the `from` network, one `socat` listener per allowed `workload:port` forwarding to the target's inspected IP on the `to` network. Default-deny stays membership (no route `from -> to`); the proxy is the only opening.

## Decision Outcome

Chosen: Option 2, the TCP proxy. It refines ADR-0011's mechanism clause (nftables/iptables -> TCP proxy); ADR-0011's other two decisions — membership as the base, and the mandatory self-check — are unchanged and still hold, so ADR-0011 stays `accepted` and this ADR records only the mechanism.

The proxy fits redstep's name-based probe with no L3 machinery: a probe on `from` connecting to `api:8080` resolves `api` to the gateway (the alias) and hits the `socat` listener, which forwards to the real `api` on `to`; `api:5432` (not allowed) has no listener and is refused; `db` (not in any allow) is not aliased and does not resolve. No NET_ADMIN, no `ip_forward`, no route injection, no cross-segment DNS forwarder. This was prototyped against a live daemon while designing (a throwaway, not kept): a probe on `from` reached an allowed port through the gateway and was refused on a non-allowed one, while the target's address on `to` was unreachable directly (the segments stay isolated; the gateway is the only path). The kept proof is the Confirmation's `gateway_enforces_the_port_boundary`.

The self-check (`orchestrator::check_boundaries`) gains a gateway branch: for every allowed `workload:port` a `from` probe must connect (the intended path, which doubles as the positive control proving the gateway is reachable, RK-008), and every non-allowed `to`-workload must be unreachable on every allowed port (RK-009). Port-exactness on an allowed workload (its non-allowed ports are not proxied) is held by construction — `gateway_cmd` runs one listener per allowed spec and no other — pinned offline and demonstrated against a served-but-denied port by the Docker self-check test.

### Confirmation

Guarded in `crates/redstep/src/orchestrator.rs`: `gateway_cmd_builds_one_listener_per_spec` (the exact listener set, offline), `gateway_check_passes_when_allowed_reachable_and_others_blocked`, `gateway_check_fails_closed_when_a_non_first_intended_path_is_down` (RK-009 over the allowed specs), `gateway_check_refuses_when_a_non_first_non_allowed_workload_is_reachable` (RK-009 over the non-allowed workloads), and `gateway_check_fails_closed_when_a_tcp_probe_errors` (fail-closed). The end-to-end enforcement is the Docker-gated `gateway_enforces_the_port_boundary` in `tests/environment.rs`, which drives real `bring_up` + `boundary_self_check`, confirms a served-but-denied port is closed through the gateway (RK-008 non-vacuous), and breaks a non-first allowed member (RK-009). The Docker leg is confirmed on CI / a live daemon; the offline guards carry the decision logic on every gate (RK-013/RK-014).

### Consequences

* Good, the mechanism matches how redstep observes reachability (name-based, in-lab), so enforcement and the self-check and the real vantage capabilities all agree with no L3 plumbing, and the proxy can only ever open a declared `workload:port` to an inspected in-lab IP, never egress or a raw address.
* Bad, a TCP proxy is connection-level, not packet-level: it mediates only the declared TCP paths (default-deny is the absence of a route, not a drop rule), and the target sees the gateway as the client, so a future multi-step pivot that turns on the real source identity (v0.5.0) may need to revisit this.
* Bad, one gateway mediates on a single address, so its proxy keys on port alone. Two allowed `workload:port` specs on the same port in one boundary would collide on one listener and could not be told apart, so `EnvironmentBuilder::build` refuses a repeated port, keeping port -> workload injective; a topology needing two services on one port through one gateway is out of this mechanism's reach. A related name-laxity remains even with distinct ports: every allowed workload name is aliased to the one gateway address, and `socat TCP-LISTEN` binds all of it keyed on port, so with `allow = ["api:8080", "web:80"]` a probe to `web:8080` resolves `web` to the gateway and hits the 8080 listener, reaching `api`. This does **not** weaken containment: the backend reached is always one of the allowed in-scope `(ip, port)` pairs (here `api:8080`, which is allowed), so no forbidden service, non-allowed port, or out-of-lab host becomes reachable; only the *name* used to reach an already-allowed backend is lax. A reachability probe through the gateway is therefore per-port, not per-name. Per-name enforcement would need one gateway address per workload, which a single Docker endpoint does not give.
* Neutral, an allowed workload is aliased to the gateway, so the prober-based self-check cannot test it by name; `boundary_self_check` adds a structural check that every `to`-workload is on its own segment network and not on `from`, which restores for a gateway boundary the defense-in-depth layer (ADR-0006) the ICMP membership check gives a plain one and catches a workload wrongly dual-homed onto `from`.
* Neutral, `socat` accepts the inbound connection before dialing upstream, so the positive control proves the gateway opened the port, not that the target app is healthy (that is `await_readiness`'s job); the dangerous direction (a forbidden path open) does not rest on this, since it is "no listener -> refused".
* What would reverse this: a boundary redstep must observe that a proxy cannot express (a non-TCP path, or packet-level filtering of traffic that is not a connection to a declared port), or a pivot model that needs the real source address end to end.

## More Information

Refines [ADR-0011](0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md) (the layered boundary and its self-check) and rests on [ADR-0006](0006-guarantee-safety-in-independent-layers.md) (the egress-less base that bounds the gateway's blast radius). Built in #114 on the gateway container of #113. Code: `crates/redstep/src/orchestrator.rs` (`GATEWAY_IMAGE`, `gateway_cmd`, the `provision` gateway loop, `check_boundaries`'s gateway branch), `crates/redstep/src/environment.rs` (`gateway_boundary`, `parse_allow_spec`). Open: the DMZ reference topology (#115) that exercises this across the three-segment internet/dmz/internal shape.
