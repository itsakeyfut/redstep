---
name: Network Service Discovery
slug: network-service-discovery
attack: [T1046, T1595]
owasp: []
cwe: []
targets: [network]
capability: none
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

Not yet implemented (`capability: none`). This is the natural home of a real tool adapter
(`nmap`), which the roadmap defers to M3; when built it would scan the lab segment from
the attacker vantage and the witness is the discovered open ports and service versions,
checked against what the lab is expected to expose. The boundary self-check already
proves reachability within a segment, so discovery extends that from one positive control
to an enumeration.

## What a verdict means

Discovery does not itself decide an exploit verdict: it produces an inventory that later
techniques act on. Reported as an observation (the services found), not a Pass/Fail,
unless paired with a check that a service should not have been reachable from the
vantage, which is a scope/boundary question
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [network]` technique scanning only within the lab. The segment is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) so no scan traffic
leaves the lab, and scope resolves what may be scanned by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)):
a scan cannot be aimed at a host outside the declared scope.

## References

- ATT&CK: [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) (internal) and [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/) (external reconnaissance)
- OWASP: not an application-layer category (ADR-0016 allows unmapped).
