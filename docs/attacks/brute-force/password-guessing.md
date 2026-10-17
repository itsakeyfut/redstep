---
name: Password Guessing
slug: password-guessing
attack: [T1110.001]
owasp: [A07:2021-Identification and Authentication Failures]
cwe: [CWE-307]
targets: [web, api, identity]
capability: none
---

# Password Guessing

A sub-technique of [Brute Force](README.md); see the umbrella for the general
technique.

## Summary

Guessing the password of a specific, known account by trying many candidates (common
passwords, a wordlist, patterns derived from the target) against the login until one
works.

## Mechanism

The attacker fixes a username and submits many passwords to the same account. It
succeeds where the login applies no per-account rate limit or lockout, so the thousandth
attempt is as welcome as the first. It is distinguished from password spraying by
concentrating on one account rather than spreading one password across many, which is
also what makes it trip a per-account lockout if one exists.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is an authentication success for
the targeted account after a series of failures: the probe submits candidates and reads
a session or token being granted (or the login's success response) from the response,
through the body-marker seam. The signal that matters is success reached by volume, so
the check also records that the attempts were not throttled.

## What a verdict means

When implemented, a `Fail` (High) would mean the account's password was found and no
effective limit stopped the attempts. A confident "not exploitable" would prove only
that the candidate set tried did not include the password, not that the login is
rate-limited
([ADR-0010](../../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api, identity]` technique acting on the scoped target's login; it
reaches nothing beyond it. Scope is by membership
([ADR-0011](../../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- ATT&CK: [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- PortSwigger Web Security Academy: [Authentication vulnerabilities](https://portswigger.net/web-security/authentication)
- See the [Brute Force](README.md) umbrella for OWASP and CWE.
