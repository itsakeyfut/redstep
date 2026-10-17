---
name: Brute Force
slug: brute-force
attack: [T1110]
owasp: [A07:2021-Identification and Authentication Failures]
cwe: [CWE-307]
targets: [web, api, identity]
capability: none
---

# Brute Force

This is an umbrella: it teaches the general technique and links its sub-techniques,
each of which is a file of its own. The sub-techniques carry the redstep detail, their
own ATT&CK sub-technique id, and their own capability.

## Summary

Brute force is defeating an authentication mechanism by submitting many credential
values until one works, when nothing makes the attempts costly. It succeeds not because
any single guess is clever but because the system allows unlimited, unthrottled tries.

## Mechanism

The authentication endpoint applies no effective rate limit, lockout, or increasing
cost (a CAPTCHA, a delay), so an attacker submits guesses at scale. ATT&CK T1110
divides the technique by what is varied and where the work happens: guessing many
passwords for one account, cracking captured hashes offline, trying a few common
passwords across many accounts to stay under lockout thresholds, or replaying
credential pairs leaked from other breaches. A true weakness is distinguished from a
hardened login by the attempts being allowed to continue to success, so the witness is
an authentication success reached through volume.

## Sub-techniques

- [Password Guessing](password-guessing.md) (T1110.001)
- [Password Cracking](password-cracking.md) (T1110.002)
- [Password Spraying](password-spraying.md) (T1110.003)
- [Credential Stuffing](credential-stuffing.md) (T1110.004)

## References

- ATT&CK: [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- OWASP: [A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- CWE: [CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- PortSwigger Web Security Academy: [Authentication vulnerabilities](https://portswigger.net/web-security/authentication)
