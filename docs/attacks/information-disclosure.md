---
name: Information Disclosure
slug: information-disclosure
attack: [unmapped]
owasp: []
cwe: [CWE-200]
targets: [web, api]
capability: none
---

# Information Disclosure

## Summary

Information disclosure is the application revealing something useful to an attacker that
it should keep to itself: stack traces, source or configuration files, internal paths,
version banners, verbose error messages, debug endpoints, secrets echoed into a
response. It is often a stepping stone, handing the attacker the detail that makes a
sharper attack possible.

## Mechanism

Verbose errors or a debug mode are left enabled, backup or source files are served,
comments or headers leak component versions, or a predictable debug or admin endpoint is
reachable. A true disclosure is distinguished from an ordinary response by sensitive
internal data appearing where it should not, so the witness is that data returning: a
stack trace, a known-secret marker, a version string, a path.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is in-band: the probe requests a
likely source (an error path, a backup URL, a debug endpoint) and reads a sentinel
standing for leaked data, an error signature or a planted secret, from the response
through the body-marker seam.

## What a verdict means

When implemented, a `Fail` (High) would mean sensitive internal information was
disclosed. A confident "not exploitable" would prove only that the sources probed did
not leak, not that none does
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique that reads the scoped target's own responses; it
reaches nothing beyond it. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), and any secret used
as a witness is a planted fixture, not real.

## References

- CWE: [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- PortSwigger Web Security Academy: [Information disclosure](https://portswigger.net/web-security/information-disclosure)
- OWASP: no single distinct Top 10 category; ATT&CK unmapped (ADR-0016).
