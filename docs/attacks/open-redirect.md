---
name: Open Redirect
slug: open-redirect
attack: [unmapped]
owasp: [A01:2021-Broken Access Control]
cwe: [CWE-601]
targets: [web]
capability: none
---

# Open Redirect

## Summary

An endpoint that redirects to a URL taken from request input, without restricting it
to the site's own pages, lets an attacker send a link that looks like the trusted
site but lands the victim on a site the attacker controls. It is most damaging as a
building block: phishing that borrows the trusted domain, or stealing an OAuth token
or code by redirecting the authorization response off-site.

## Mechanism

The endpoint reads a destination from input, for example `?next=/account` or
`?returnUrl=...`, and issues a redirect to it without confirming it points within the
site. The attacker supplies an external URL (`https://evil.example`), or an obfuscated
one that bypasses a weak check (`//evil.example`, `https:evil.example`, a whitelisted
prefix followed by `@`). A true open redirect is distinguished from an in-site redirect
by the response steering the browser to an attacker-controlled host, so the witness is
the redirect's `Location` naming that host.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is in the response: a probe sets
the redirect parameter to an in-lab sentinel host and checks whether the 3xx `Location`
(or a meta/JavaScript redirect) points there. A future capability would read the
redirect target from the response headers rather than the body, a header-witness
variant of the seam; `response_was_redirected` already recognises a 3xx in the probe
plumbing.

## What a verdict means

When implemented, a `Fail` (High) would mean the endpoint redirected to the
attacker-named host. A confident "not exploitable" would prove only that this payload
was not followed off-site, not that an encoding or prefix trick would also be rejected
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique whose witness is a redirect naming an in-lab sentinel
host; nothing leaves the lab. The lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) so even a redirect
to a real host could not be followed out of the lab, and scope resolves the target by
membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- OWASP: [A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) (unvalidated redirects are folded into this category)
- CWE: [CWE-601 URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- PortSwigger Web Security Academy: [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection)
- ATT&CK: no enterprise technique maps cleanly; often a step toward [T1566 Phishing](https://attack.mitre.org/techniques/T1566/). OWASP above is the mapping (ADR-0016).
