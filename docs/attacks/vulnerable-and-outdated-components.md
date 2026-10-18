---
name: Vulnerable and Outdated Components
slug: vulnerable-and-outdated-components
attack: [T1195.001, T1190]
owasp: [A06:2021-Vulnerable and Outdated Components]
cwe: [CWE-1104]
targets: [web, api]
capability: none
---

# Vulnerable and Outdated Components

## Summary

An application inherits the vulnerabilities of the libraries, frameworks, and runtimes it
ships. Running a component with a known, published vulnerability, or one from an untrusted
or tampered source, hands an attacker a working exploit they did not have to discover: the
CVE is public, and the only question is whether the component is present and reachable.

## Mechanism

The application depends on a component that is outdated and unpatched against a known CVE,
or pulled from a compromised source (the supply-chain case, ATT&CK T1195.001). The
attacker fingerprints the component and version, from banners, error messages, exposed
lockfiles or paths, and runs the public exploit for it. It is distinguished from a patched
stack by a known-vulnerable component being present and reachable, so the witness is the
component's version matched to a known vulnerability, or that vulnerability exploited.

## How redstep exercises it

Not yet implemented (`capability: none`). It has two halves. The detection half,
identifying components and versions and matching them against a known-vulnerability
database, is a software-composition concern rather than an exploit-replay loop. The
exploitation half reduces to whatever specific technique the CVE is (an injection, an RCE,
a deserialization) run through the relevant app check or
[exploitation of remote services](exploitation-of-remote-services.md). A capability here
would most likely be version identification plus known-CVE matching, feeding the specific
exploit checks.

## What a verdict means

More an inventory-and-matching property than a single exploit verdict: whether a reachable
component matches a known vulnerability. Where it is actually exploited, the verdict
belongs to the specific technique the CVE is, under the usual confidence model
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` concern evaluated against the scoped target inside the lab. Scope
is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), so fetching a known
exploit or a component from a real external source is itself prevented.

## References

- OWASP: [A06:2021 Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- CWE: [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)
- ATT&CK: [T1195.001 Supply Chain Compromise: Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/); the exploitation step is [T1190](https://attack.mitre.org/techniques/T1190/).
