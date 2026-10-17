---
name: Use of Alternate Authentication Material
slug: alternate-authentication-material
attack: [T1550]
owasp: []
cwe: [CWE-294]
targets: [identity]
capability: none
---

# Use of Alternate Authentication Material

## Summary

Authentication often accepts a token that stands in for the password, a hash, a Kerberos
ticket, an OAuth access token, a session cookie. If an attacker captures that material,
they can authenticate with it directly and never need the password, which is why stealing
the token is so often the whole attack.

## Mechanism

ATT&CK (T1550) groups the variants by the material reused. Pass the hash (.002)
authenticates with a captured NTLM hash. Pass the ticket (.003) reuses a stolen Kerberos
ticket. Application access token (.001) replays an OAuth or API token. Web session cookie
(.004) replays a stolen session cookie, the web case, covered as its own technique in
[session hijacking](session-hijacking.md). They are distinguished from legitimate login
by authentication succeeding from captured material rather than a credential the actor
knows, so the witness is access granted by replaying the token.

## How redstep exercises it

Not implemented, and mostly out of redstep's lab scope: pass-the-hash and pass-the-ticket
are Windows and Active Directory techniques the Linux-Docker lab does not model. The two
that are in scope are expressed as their own entries where redstep can witness them: an
OAuth or API token reused is [OAuth vulnerabilities](oauth-vulnerabilities.md) and
[JWT attacks](jwt-attacks.md); a stolen web session cookie is
[session hijacking](session-hijacking.md). This entry is the umbrella that names the
family; the AD variants stay `capability: none`.

## What a verdict means

Not applicable directly: the in-scope cases decide their verdicts in the token-specific
entries above, and the AD variants have no lab model
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

No in-lab action of its own; the in-scope token cases are confined by their own entries,
all within the egress-less lab
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) under membership scope
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
with any token used a fixture.

## References

- ATT&CK: [T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) (application access token, pass the hash, pass the ticket, web session cookie)
- CWE: [CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)
- Related: [Session Hijacking](session-hijacking.md), [OAuth Vulnerabilities](oauth-vulnerabilities.md), [JWT Attacks](jwt-attacks.md).
