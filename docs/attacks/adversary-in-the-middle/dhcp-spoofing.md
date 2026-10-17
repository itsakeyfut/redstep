---
name: DHCP Spoofing
slug: dhcp-spoofing
attack: [T1557.003]
owasp: []
cwe: [CWE-300]
targets: [network]
capability: none
---

# DHCP Spoofing

A sub-technique of [Adversary-in-the-Middle](README.md); see the umbrella for the
general technique.

## Summary

Hosts joining a network ask a DHCP server for their IP address, gateway, and DNS
servers. A rogue DHCP server that answers first can hand the victim a configuration that
routes traffic through the attacker, or points DNS at an attacker-controlled resolver,
putting the attacker on-path from the moment the victim connects.

## Mechanism

The attacker runs a DHCP server on the segment and races the legitimate one to answer
`DHCPDISCOVER` broadcasts. Its offer names the attacker as gateway or DNS server, so the
victim's default route or name resolution now flows through the attacker. It is
distinguished from normal DHCP by the victim accepting an attacker-supplied
configuration, so the witness is the victim routing through the attacker.

## How redstep exercises it

Not yet implemented (`capability: none`). On a shared lab segment the witness is the
victim adopting the rogue configuration and its traffic reaching the attacker vantage. It
needs DHCP in the lab topology and would land with the network-boundary work (roadmap
M3).

## What a verdict means

When implemented, a `Fail` (High) would mean the victim accepted the rogue lease and
routed through the attacker. A confident "not exploitable" would mean the rogue offer
was not accepted (DHCP snooping, a pinned configuration)
([ADR-0010](../../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [network]` technique acting within one lab segment; it reaches nothing
beyond it. The segment is egress-less
([ADR-0006](../../adr/0006-guarantee-safety-in-independent-layers.md)), and scope is by
membership
([ADR-0011](../../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- ATT&CK: [T1557.003 DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003/)
- CWE: [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)
- See the [Adversary-in-the-Middle](README.md) umbrella.
