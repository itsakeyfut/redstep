---
name: Network Service Discovery
slug: network-service-discovery
attack: [T1046, T1595]
owasp: []
cwe: []
targets: [network]
capability: network_service_discovery_vantage
---

# Network Service Discovery

## Summary

Network service discovery is finding which hosts are reachable and which ports and
services they expose, the map an attacker builds before choosing a target. It spans
external reconnaissance before any access (ATT&CK Active Scanning, T1595) and internal
discovery once on the network (ATT&CK Network Service Discovery, T1046); in practice both
are the same port-and-service scanning, so they share one file here.

## Mechanism

The attacker probes a range of addresses and ports, a TCP connect or SYN scan to see
what answers, and fingerprints the services and versions behind the open ports (the work
`nmap` does). The result is an inventory: live hosts, open ports, service versions, from
which known-vulnerable services are chosen. It is recon rather than exploitation, so its
witness is the inventory itself, the services it reveals.

## How redstep exercises it

The native capability `network_service_discovery_vantage`
(`TestContext::discover_services_from_vantage`) enumerates which of a declared set of
services the attacker's vantage can reach, from an assume-breach foothold inside the lab
(#96). It probes each target with the same reachability primitive as the single-target
`connect_from_vantage`, and records one evidence draft per target attributed to the vantage
(not the host). This is reachability enumeration, not port fingerprinting: it answers
"which declared services can this foothold reach", the blast-radius measurement expressed
as a catalogued technique. The fuller version that scans for open ports and fingerprints
service versions is the `nmap` tool adapter, which the roadmap defers to v0.4.0
([ADR-0007](../adr/0007-integrate-tools-as-a-plugin-with-three-role-contracts.md)).

## What a verdict means

Discovery does not itself decide an exploit verdict: it produces an inventory (which
services were reachable) that later techniques and the blast-radius report act on. Each
target is its own observation with its own confidence: a completed connect is reachable at
`High`, an explicit refusal is not-reachable at `High`, and a timeout or a probe-side error
is `Low`, never a confident "not reachable"
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).
It becomes a Pass/Fail only when paired with a check that a service should not have been
reachable from the vantage, which is a scope/boundary question.

## Confinement

A `targets: [network]` technique scanning only within the lab. The segment is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) so no scan traffic
leaves the lab, and scope resolves what may be scanned by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)):
a scan cannot be aimed at a host outside the declared scope.

## References

- ATT&CK: [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) (internal) and [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/) (external reconnaissance)
- OWASP: not an application-layer category (ADR-0016 allows unmapped).
