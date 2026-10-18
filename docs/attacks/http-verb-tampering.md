---
name: HTTP Verb Tampering
slug: http-verb-tampering
attack: [unmapped]
owasp: [A01:2021-Broken Access Control]
cwe: [CWE-650]
targets: [web, api]
capability: none
---

# HTTP Verb Tampering

## Summary

When access control or input handling is applied to some HTTP methods but not others, an
attacker reaches a protected action by switching the verb. A rule that guards `POST` but
not `PUT`, or a framework that treats an unknown method as `GET`, lets a request slip past
the control it should have met.

## Mechanism

The server enforces a restriction per method rather than per action: a security
constraint lists `GET` and `POST` but the endpoint also answers `PUT`, `HEAD`, or an
arbitrary method, and that path is unguarded. The attacker sends the protected request
with a verb the rule does not cover. It is distinguished from a correctly guarded endpoint
by the action succeeding under an alternate method, so the witness is the protected effect
reached by the tampered verb.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is the protected action succeeding
under an alternate method: the probe repeats a request that is denied under its normal
verb with a different one and observes it succeed (a marker, or the state change), through
the body-marker seam. It is an access-control check varied over the method, close to
[privilege escalation](privilege-escalation.md).

## What a verdict means

When implemented, a `Fail` (High) would mean a protected action succeeded under a verb the
control did not cover. A confident "not exploitable" would prove only that the verbs tried
were all guarded
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique acting within the scoped target; it reaches nothing
beyond it. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/); WSTG tests HTTP verb tampering under input validation (4.7.3).
- CWE: [CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)
- Related: [Privilege Escalation](privilege-escalation.md).
