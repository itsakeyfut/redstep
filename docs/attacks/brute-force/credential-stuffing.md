---
name: Credential Stuffing
slug: credential-stuffing
attack: [T1110.004]
owasp: [A07:2021-Identification and Authentication Failures]
cwe: [CWE-307]
targets: [web, api, identity]
capability: none
---

# Credential Stuffing

A sub-technique of [Brute Force](README.md); see the umbrella for the general
technique.

## Summary

Replaying username-and-password pairs leaked from one service against another, betting
that people reuse passwords. It is not guessing: each pair is a known-valid credential
somewhere, so the hit rate against a site with reused passwords is high and the traffic
looks like ordinary logins.

## Mechanism

The attacker takes a list of real `username:password` pairs from a prior breach and
submits each to the target's login. Because each guess is a real pair rather than a
generated one, few attempts per account are needed and the requests resemble legitimate
logins, which is what makes rate-limiting and anomaly detection harder. It is
distinguished from guessing and spraying by using breach-sourced valid pairs rather than
generated candidates.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is an authentication success when
a supplied known-pair is replayed, read from the login response through the body-marker
seam. A check would use a fixture credential list (never real breach data) and record
whether reuse succeeded and whether any limit slowed the replay.

## What a verdict means

When implemented, a `Fail` (High) would mean a replayed pair authenticated, so a reused
credential was accepted without a second factor or a reuse check. A confident "not
exploitable" would prove only that the pairs tried did not match, not that reused
credentials in general are defended (MFA, breached-password screening)
([ADR-0010](../../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api, identity]` technique acting on the scoped target's login; it
reaches nothing beyond it. Scope is by membership
([ADR-0011](../../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
the lab network is egress-less
([ADR-0006](../../adr/0006-guarantee-safety-in-independent-layers.md)), and the
credential list is a fixture, never real breach data.

## References

- ATT&CK: [T1110.004 Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)
- OWASP: [Credential Stuffing Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- See the [Brute Force](README.md) umbrella for the category CWE.
