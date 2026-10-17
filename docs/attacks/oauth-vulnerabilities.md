---
name: OAuth Vulnerabilities
slug: oauth-vulnerabilities
attack: [unmapped]
owasp: [A07:2021-Identification and Authentication Failures]
cwe: [CWE-287]
targets: [web, api, identity]
capability: none
---

# OAuth Vulnerabilities

## Summary

OAuth 2.0 delegates access by passing authorization codes and tokens between the user,
the application, and the identity provider. Flaws in how an application runs that flow
let an attacker capture a victim's code or token, or bind the victim's login to the
attacker's account, leading to account takeover without ever knowing a password.

## Mechanism

The common flaws are in the application's half of the flow: a `redirect_uri` that is
not strictly validated, so the code is delivered to an attacker-controlled URL; a
missing or unchecked `state` parameter, so the flow has no CSRF protection and a login
can be forced; codes or tokens leaking through an open redirect or the `Referer`
header; or the implicit flow exposing the token in the URL fragment. A true flaw is
distinguished from a sound flow by the attacker obtaining the victim's code or token, or
the victim's session binding to the attacker's identity, so the witness is that capture
or binding.

## How redstep exercises it

Not yet implemented (`capability: none`). The witnesses vary by flaw and overlap other
techniques: a `redirect_uri` or leak flaw delivers the code to the in-lab canary
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)), reusing
the SSRF/[open redirect](open-redirect.md) witness; a missing-`state` flaw is a
[CSRF](csrf.md)-shaped state change. A capability here would compose those witnesses
rather than invent a new one.

## What a verdict means

When implemented, a `Fail` (High) would mean the attacker captured a code or token, or
forced an account binding, through the flaw tried. A confident "not exploitable" would
prove only that this flaw was absent in the flow tested, not that every OAuth
misconfiguration is
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api, identity]` technique whose captures land at an in-lab canary and
whose redirects cannot leave the egress-less lab
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)); scope resolves every
party by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
so the identity provider and the application are both in-lab workloads.

## References

- OWASP: [A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- CWE: [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- PortSwigger Web Security Academy: [OAuth authentication](https://portswigger.net/web-security/oauth)
- ATT&CK: no enterprise technique maps cleanly; OWASP above is the mapping (ADR-0016).
