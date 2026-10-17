---
name: Business Logic Vulnerabilities
slug: business-logic-vulnerabilities
attack: [unmapped]
owasp: [A04:2021-Insecure Design]
cwe: [CWE-840]
targets: [web, api]
capability: none
---

# Business Logic Vulnerabilities

## Summary

Business logic flaws are wrong assumptions in a workflow rather than a bad input: steps
taken out of order, a value outside its intended range, a one-time action reused, a
payment skipped. Every individual request is well-formed and the code runs as written;
it is the design that permits a state it should forbid.

## Mechanism

The application assumes the client follows the intended sequence and value bounds and
does not re-check them on the server, so an attacker who breaks the assumption gets an
outcome the design did not intend: a negative quantity that credits the account, a
coupon redeemed twice, a verification step bypassed by calling the next endpoint
directly. A true flaw is distinguished from normal use by the workflow reaching a
forbidden state, so the witness is that state or the unearned benefit.

## How redstep exercises it

Not yet implemented (`capability: none`). Witnesses are application-specific: a
follow-up read showing the forbidden state, or a benefit granted. A capability here is
less a single generic check than a harness for expressing per-target assertions about a
workflow, so the catalog entry mainly guides how such tests would be written and
witnessed.

## What a verdict means

When implemented, a `Fail` (High) would mean the workflow reached a state the design
forbids. A confident "not exploitable" is especially narrow here: it covers only the
assumptions the test encoded, never the application's logic in general
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique acting within the scoped target; it reaches nothing
beyond it. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [A04:2021 Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/); for APIs, [API6:2023 Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
- CWE: [CWE-840 Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)
- PortSwigger Web Security Academy: [Business logic vulnerabilities](https://portswigger.net/web-security/logic-flaws)
- ATT&CK: no enterprise technique maps cleanly; OWASP above is the mapping (ADR-0016).
