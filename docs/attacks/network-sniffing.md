---
name: Network Sniffing
slug: network-sniffing
attack: [T1040]
owasp: []
cwe: [CWE-319]
targets: [network]
capability: none
---

# Network Sniffing

## Summary

Network sniffing is capturing traffic as it crosses a network the attacker can observe,
to read credentials, tokens, or data sent without encryption, and to learn the topology
and the protocols in use. It is often paired with an on-path position
([Adversary-in-the-Middle](adversary-in-the-middle/README.md)) that brings traffic within
reach.

## Mechanism

The attacker puts an interface into promiscuous mode, or sits on-path, and records
frames. Anything sent in cleartext, a password on plain HTTP, a token, an internal API
call, is readable; even encrypted traffic leaks metadata (who talks to whom, when, how
much). It is distinguished from a normal host by capturing traffic not addressed to it,
so the witness is sensitive content recovered from captured frames.

## How redstep exercises it

Not yet implemented (`capability: none`). On a shared lab segment the witness is a
sentinel value (a planted credential or token) sent by one workload and recovered from
the attacker vantage's capture. It depends on the lab segment being observable from the
vantage and would land with the network-boundary work (roadmap v0.3.0).

## What a verdict means

When implemented, a `Fail` (High) would mean a sentinel sent by another workload was
recovered from captured traffic, so the segment exposes cleartext to an on-path observer.
A confident "not exploitable" would mean the sentinel was not recoverable (encrypted
transport, a switched path)
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [network]` technique capturing within one lab segment; it reaches nothing
beyond it. The segment is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) so captured traffic
cannot leave the lab, scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and any sniffed credential is a fixture.

## References

- ATT&CK: [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- CWE: [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- OWASP: no distinct Top 10 category (ADR-0016 allows unmapped for OWASP).
