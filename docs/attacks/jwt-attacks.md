---
name: JWT Attacks
slug: jwt-attacks
attack: [unmapped]
owasp: [A07:2021-Identification and Authentication Failures]
cwe: [CWE-347]
targets: [web, api, identity]
capability: none
---

# JWT Attacks

## Summary

A JSON Web Token carries claims (who the user is, what they may do) that a server
trusts because it verified the token's signature. JWT attacks make the server accept a
token the attacker forged or tampered with, by exploiting weak or skipped verification,
turning a stateless session into a forgeable one: authenticate as anyone, grant
yourself any claim.

## Mechanism

The server's verification is weak in one of several well-known ways: it accepts
`alg: none` and skips the signature; it does not verify the signature at all; the HMAC
secret is weak and can be brute-forced offline; or algorithm confusion, where a server
expecting RS256 is given an HS256 token signed with the RSA public key as the HMAC
secret. Header fields such as `kid`, `jku`, or `x5u` can also point verification at a
key the attacker controls. A true weakness is distinguished from sound verification by a
token the attacker altered being accepted, so the witness is access granted under the
forged claims.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is the server accepting a forged
or tampered token: the probe presents such a token in the request-headers identity
channel the IDOR check already uses, and reads access being granted, or another user's
data returning, from the response through the body-marker seam. Each verification flaw
is a distinct payload (an `alg: none` token, a resigned token, a confused-algorithm
token).

## What a verdict means

When implemented, a `Fail` (High) would mean a token the attacker forged or altered was
accepted as valid. A confident "not exploitable" would prove only that the specific flaw
tried was not present, not that verification is sound against the others
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api, identity]` technique acting on the scoped target; it reaches
nothing beyond it. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)). A token the probe
forges is recorded in the reproduction and is a fixture, not a real credential.

## References

- OWASP: [A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- CWE: [CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- PortSwigger Web Security Academy: [JWT attacks](https://portswigger.net/web-security/jwt)
- ATT&CK: no enterprise technique maps cleanly; OWASP above is the mapping (ADR-0016).
