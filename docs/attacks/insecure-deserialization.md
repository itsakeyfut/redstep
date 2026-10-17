---
name: Insecure Deserialization
slug: insecure-deserialization
attack: [T1190]
owasp: [A08:2021-Software and Data Integrity Failures]
cwe: [CWE-502]
targets: [web, api]
capability: none
---

# Insecure Deserialization

## Summary

An application that deserialises attacker-controlled data with a format that can
reconstruct arbitrary objects lets the attacker craft a serialized payload that, when
rebuilt, runs code or changes application state. In the worst case it is remote code
execution reachable from any field that carries a serialized blob: a cookie, a hidden
form value, an API body.

## Mechanism

The application takes serialized data from the request and rebuilds objects from it
with a language or library mechanism (Java serialization, Python pickle, PHP
`unserialize`, .NET formatters). The attacker supplies a crafted object graph, often a
known "gadget chain" of classes whose construction or finalisation has side effects,
so deserialisation itself executes code or tampers with state. A true instance is
distinguished from benign data by those side effects occurring, so the witness is the
effect: a value only code execution could produce, or an out-of-band callback the
gadget chain makes.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is usually out-of-band, since a
gadget chain that runs code often has no in-response output: the crafted object calls
back to the in-lab canary
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)), the same
pattern as a blind command injection. Where a chain returns a value, the in-band seam
could read a sentinel. The payload is language- and library-specific.

## What a verdict means

When implemented, a `Fail` (High) would mean deserialising the crafted payload produced
its effect (the canary callback, or a returned sentinel). A confident "not exploitable"
would prove only that this gadget chain did not fire, not that no chain exists for the
libraries on the classpath
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique that can reach code execution, so confinement is
load-bearing. Deserialisation runs inside the scoped target's container; the lab is
egress-less ([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) so a
gadget chain cannot reach real infrastructure, and scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- OWASP: [A08:2021 Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- CWE: [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- PortSwigger Web Security Academy: [Insecure deserialization](https://portswigger.net/web-security/deserialization)
- ATT&CK: maps coarsely to [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/); OWASP above is the sharper application-layer mapping (ADR-0016).
