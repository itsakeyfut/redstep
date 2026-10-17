---
name: ARP Cache Poisoning
slug: arp-cache-poisoning
attack: [T1557.002]
owasp: []
cwe: [CWE-300]
targets: [network]
capability: none
---

# ARP Cache Poisoning

A sub-technique of [Adversary-in-the-Middle](README.md); see the umbrella for the
general technique.

## Summary

On a local network, hosts map IP addresses to MAC addresses with ARP, which has no
authentication. ARP cache poisoning sends forged ARP replies so a victim associates
another host's IP (often the gateway's) with the attacker's MAC, and sends that host's
traffic to the attacker instead.

## Mechanism

The attacker broadcasts or unicasts ARP replies claiming `gateway-IP is at
attacker-MAC`, and the victim's ARP cache accepts the unsolicited mapping. Traffic the
victim meant for the gateway now goes to the attacker, who forwards it on to stay
transparent. It is distinguished from normal ARP by the mapping being attacker-asserted
and wrong, so the witness is the victim's traffic arriving at the attacker.

## How redstep exercises it

Not yet implemented (`capability: none`). It would run on a shared lab segment where an
attacker workload and victim workloads share a layer-2 network; the witness is the
redirected traffic reaching the attacker vantage (a sentinel flow captured there). It
depends on the lab's network giving containers a shared L2 broadcast domain, which the
network-boundary work (roadmap M3) is where this would land.

## What a verdict means

When implemented, a `Fail` (High) would mean a sentinel flow from the victim was
captured at the attacker after poisoning, so the segment permits on-path interception. A
confident "not exploitable" would mean the poisoning did not redirect the flow (static
ARP, or L2 protections)
([ADR-0010](../../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [network]` technique acting at layer 2 within a single lab segment; it
reaches nothing beyond it. The segment network is egress-less
([ADR-0006](../../adr/0006-guarantee-safety-in-independent-layers.md)) so intercepted
traffic cannot leave the lab, and scope is by membership
([ADR-0011](../../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- ATT&CK: [T1557.002 ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/)
- CWE: [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)
- See the [Adversary-in-the-Middle](README.md) umbrella.
