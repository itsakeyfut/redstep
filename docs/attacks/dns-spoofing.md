---
name: DNS Spoofing and Cache Poisoning
slug: dns-spoofing
attack: [unmapped]
owasp: []
cwe: [CWE-345]
targets: [network]
capability: none
---

# DNS Spoofing and Cache Poisoning

## Summary

DNS spoofing feeds a resolver or a client a forged answer for a name, so a victim
resolving a trusted hostname is sent to an attacker-controlled address. Cache poisoning
makes that forged answer stick in a resolver's cache, so every client of that resolver is
redirected until the entry expires, scaling one forged response into many victims.

## Mechanism

DNS over UDP is easy to forge: an attacker who can answer faster than the real server, or
who is on-path, returns a response mapping the name to their address. Against a recursive
resolver, guessing or racing the transaction id and source port lands a poisoned record in
its cache, which it then serves to all its clients. It is distinguished from a legitimate
answer by the mapping being attacker-chosen, so the witness is a victim resolving the name
to the attacker's address.

## How redstep exercises it

Not yet implemented (`capability: none`). On a lab segment with a resolver and clients, the
witness is a victim resolving a sentinel name to an in-lab attacker address, or an
attacker address appearing in the resolver's cache. It is on-path adjacent to
[Adversary-in-the-Middle](adversary-in-the-middle/README.md) and would land with the
network-boundary work (roadmap v0.3.0).

## What a verdict means

When implemented, a `Fail` (High) would mean a victim accepted the forged resolution. A
confident "not exploitable" would mean the forged answer was rejected (DNSSEC validation,
source-port and transaction-id entropy, a trusted path)
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [network]` technique whose forged answers point at in-lab addresses; nothing
leaves the egress-less lab
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), and scope is by
membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- CWE: [CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- ATT&CK: on-path DNS manipulation is a facet of [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/); the specific cache-poisoning technique is not a distinct enterprise id, so the frontmatter is unmapped (ADR-0016).
