---
name: Session Hijacking
slug: session-hijacking
attack: [T1539, T1550.004]
owasp: [A07:2021-Identification and Authentication Failures]
cwe: [CWE-384]
targets: [web, identity]
capability: none
---

# Session Hijacking

## Summary

After login, a web application tracks the user with a session token, usually a cookie.
Session hijacking is obtaining a valid user's token and replaying it to act as that user
without their password. The token is a bearer credential: whoever holds it is the user,
so stealing it is as good as logging in.

## Mechanism

The token is captured, by [cross-site scripting](xss.md) reading a non-`HttpOnly`
cookie, by [network sniffing](network-sniffing.md) of cleartext traffic, by a predictable
or non-rotated identifier, or by session fixation (planting a known token before the
victim logs in). The attacker then sends the token and is served the victim's session. It
is distinguished from a normal session by the token being used from a context that did
not authenticate, so the witness is the victim's session reached by replaying the token.

## How redstep exercises it

Not yet implemented (`capability: none`), and in scope for the web layer. The witness is
in-band: the probe presents a captured or planted session token and reads the victim's
session content (a marker only that session should return) through the body-marker seam,
the same identity-carrying channel the [IDOR](idor.md) check uses. The capture step
itself overlaps XSS and network sniffing; this entry is the replay.

## What a verdict means

When implemented, a `Fail` (High) would mean a token used from a non-authenticating
context was accepted as the victim's session. A confident "not exploitable" would prove
only that this token was not accepted (bound to the client, rotated on privilege change),
not that session management is sound in general
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, identity]` technique acting within the scoped target; it reaches
nothing beyond it. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), and any token used is
a fixture recorded in the reproduction and treated as sensitive (security.md).

## References

- ATT&CK: [T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) and [T1550.004 Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/)
- OWASP: [A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- CWE: [CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- PortSwigger Web Security Academy: [Session management](https://portswigger.net/web-security/authentication)
