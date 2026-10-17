---
name: Password Spraying
slug: password-spraying
attack: [T1110.003]
owasp: [A07:2021-Identification and Authentication Failures]
cwe: [CWE-307]
targets: [web, api, identity]
capability: none
---

# Password Spraying

A sub-technique of [Brute Force](README.md); see the umbrella for the general
technique.

## Summary

Trying one, or a few, common passwords across many accounts, rather than many passwords
against one account. Spreading the attempts this way keeps each account below a
per-account lockout threshold while still, across a large user base, finding the
accounts that use a weak password.

## Mechanism

The attacker picks a likely password (a season-and-year, a default, a breach favourite)
and submits it once against each of many usernames, then moves to the next password. It
defeats a lockout that counts failures per account, because no single account sees many
failures. It is distinguished from password guessing by the axis varied: many accounts,
few passwords, so a defence that only locks individual accounts does not see it.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is an authentication success for
any account in a supplied set when a common password is tried, read from the login's
success response through the body-marker seam. The check would need a set of accounts to
spray and would record that per-account limits did not catch the spread.

## What a verdict means

When implemented, a `Fail` (High) would mean a common password authenticated at least
one account and the per-account defence did not stop the spread. A confident "not
exploitable" would prove only that the passwords tried matched none of the accounts
tried, not that a broader-scope limit (per source, per window) is in place
([ADR-0010](../../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api, identity]` technique acting on the scoped target's login; it
reaches nothing beyond it. Scope is by membership
([ADR-0011](../../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- ATT&CK: [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- PortSwigger Web Security Academy: [Authentication vulnerabilities](https://portswigger.net/web-security/authentication)
- See the [Brute Force](README.md) umbrella for OWASP and CWE.
