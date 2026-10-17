---
name: Mass Assignment
slug: mass-assignment
attack: [unmapped]
owasp: [API3:2023-Broken Object Property Level Authorization]
cwe: [CWE-915]
targets: [web, api]
capability: none
---

# Mass Assignment

## Summary

An endpoint that binds request fields straight onto an object's properties lets the
attacker set properties they were never meant to control, by adding them to the request:
`role=admin`, `isVerified=true`, `balance=1000000`. The mirror image, returning
properties the caller should not see, is the read side of the same object-property
authorization gap.

## Mechanism

A framework auto-binds JSON or form keys to model fields without an allowlist, so extra
keys the client sent are written to the object. The attacker adds a sensitive field the
form never showed. A true mass assignment is distinguished from a normal update by a
property the caller should not control being changed (or disclosed), so the witness is
that privileged property taking effect, or coming back in the response.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is stateful or in-band: after the
probe sends a request carrying an extra sensitive property, a follow-up read shows the
property took effect, or the response discloses a property that should be hidden (read
through the body-marker seam).

## What a verdict means

When implemented, a `Fail` (High) would mean an unauthorised property was set or
disclosed. A confident "not exploitable" would prove only that the property tried was
not bound, not that no sensitive property is bindable
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique acting within the scoped target; it reaches nothing
beyond it. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- CWE: [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- PortSwigger Web Security Academy: [Mass assignment](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerabilities)
- ATT&CK: no enterprise technique maps cleanly; OWASP above is the mapping (ADR-0016).
