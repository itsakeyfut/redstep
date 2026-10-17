---
name: CORS Misconfiguration
slug: cors-misconfiguration
attack: [unmapped]
owasp: [A05:2021-Security Misconfiguration]
cwe: [CWE-942]
targets: [web, api]
capability: none
---

# CORS Misconfiguration

## Summary

A cross-origin resource sharing policy that trusts the wrong origins lets a site the
attacker controls read responses from the vulnerable site using the victim's
credentials. Where the server reflects any origin and allows credentials, an
attacker page can call the API as the victim and read back private data the
same-origin policy was supposed to protect.

## Mechanism

The server sets `Access-Control-Allow-Origin` from the request's `Origin` header
without validating it (reflecting any origin), and sets
`Access-Control-Allow-Credentials: true`. A browser on an attacker page then makes a
credentialed cross-origin request and is allowed to read the response. Weaker
variants trust `null`, a regex that matches attacker subdomains, or any subdomain. A
true misconfiguration is distinguished from a safe policy by the response granting a
reflected or attacker-controlled origin credentialed access, so the witness is in the
response's CORS headers.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness here is a response header, not a
body marker: a probe sends an attacker `Origin` and checks whether the response echoes
it in `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials:
true`. A future capability would read the response headers rather than the body, so it
is a header-witness variant of the seam rather than `classify_http_witness` as it
stands.

## What a verdict means

When implemented, a `Fail` (High) would mean the server granted the attacker origin
credentialed cross-origin access in its headers. A confident "not exploitable" would
prove only that this origin was not trusted, not that no origin-validation bypass
exists (a trusted subdomain, a `null` origin)
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique observed in the scoped target's own response headers;
it reaches nothing beyond the target. Scope resolves the target by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- CWE: [CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- PortSwigger Web Security Academy: [CORS](https://portswigger.net/web-security/cors)
- ATT&CK: no enterprise technique maps cleanly; OWASP above is the mapping (ADR-0016).
