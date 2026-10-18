---
name: HTTP Parameter Pollution
slug: http-parameter-pollution
attack: [unmapped]
owasp: []
cwe: [CWE-235]
targets: [web, api]
capability: none
---

# HTTP Parameter Pollution

## Summary

When a request carries the same parameter more than once, different components, the web
server, the framework, a back-end, a WAF, may disagree about which occurrence counts.
HTTP parameter pollution exploits that disagreement to bypass a check, change a value past
validation, or reach behaviour a single parameter could not.

## Mechanism

The attacker supplies a parameter twice (or more), for example `?role=user&role=admin`.
One layer validates the first occurrence while another acts on the last, so a value that
passed the check is not the one used; or a WAF inspects one and the app the other. It is
distinguished from a normal request by the duplicated parameter changing the outcome, so
the witness is behaviour that only the second (unvalidated) occurrence could produce.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is in-band: the probe sends a
duplicated parameter whose second occurrence should be rejected and observes the
privileged value taking effect (a marker, or a state change), through the body-marker
seam. It is often a building block for another bypass rather than an end in itself.

## What a verdict means

When implemented, a `Fail` (High) would mean a duplicated parameter's unvalidated
occurrence reached behaviour the validated one forbade. A confident "not exploitable"
would prove only that the parsers agreed for the parameter tried
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique acting within the scoped target; it reaches nothing
beyond it. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- CWE: [CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
- OWASP: WSTG tests HTTP parameter pollution under input validation (4.7.4); no distinct Top 10 category (ADR-0016 allows unmapped).
