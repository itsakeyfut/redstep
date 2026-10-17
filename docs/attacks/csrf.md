---
name: Cross-Site Request Forgery
slug: csrf
attack: [unmapped]
owasp: [A01:2021-Broken Access Control]
cwe: [CWE-352]
targets: [web]
capability: none
---

# Cross-Site Request Forgery

## Summary

Cross-site request forgery (CSRF) makes a logged-in victim's browser send a
state-changing request to a site they are authenticated to, without their intent.
Because the browser attaches the victim's cookies automatically, a request forged by
another site is accepted as the victim's own: a password change, a funds transfer, a
setting flipped.

## Mechanism

The state-changing endpoint relies only on the ambient session cookie and does not
require an unpredictable token tied to the request. An attacker page the victim visits
issues the request (an auto-submitting form, an image, a fetch), and the browser sends
the victim's cookies with it. A true CSRF is distinguished from a blocked one by the
state change actually taking effect from a cross-site context, so the witness is the
effect occurring for a request that carried no valid anti-CSRF token.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is not a body marker: it is a
state change caused by a request that omitted or forged the anti-CSRF token, which
needs the probe to issue the request as a cross-site context would and then observe the
effect (a follow-up read showing the change, or the absence of token validation). When
built it would most likely drive a request without the token and confirm the change,
closer to the stateful IDOR check than to the body-marker seam.

## What a verdict means

When implemented, a `Fail` (High) would mean a state-changing request with no valid
token was accepted and took effect. A confident "not exploitable" would prove only that
this endpoint rejected the tokenless request, not that every state-changing endpoint
does
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md));
and it must not be read as proof a token was validated rather than the request simply
failing for another reason.

## Confinement

A `targets: [web]` technique whose effect is a state change on the scoped target; it
does not reach beyond it. Scope resolves the target by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), so any attacker
page used to stage the forged request is itself an in-lab workload.

## References

- OWASP: [A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) (CSRF is folded into this category)
- CWE: [CWE-352 Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- PortSwigger Web Security Academy: [CSRF](https://portswigger.net/web-security/csrf)
- ATT&CK: no enterprise technique maps cleanly to CSRF; OWASP above is the mapping (ADR-0016 uses OWASP for the application layer).
