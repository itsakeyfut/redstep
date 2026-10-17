---
name: Password Cracking
slug: password-cracking
attack: [T1110.002]
owasp: [A07:2021-Identification and Authentication Failures]
cwe: [CWE-916]
targets: [identity]
capability: none
---

# Password Cracking

A sub-technique of [Brute Force](README.md); see the umbrella for the general
technique.

## Summary

Recovering a plaintext password from a captured hash by computing candidate hashes
offline until one matches. Unlike the online sub-techniques, the work happens away from
the target, against material already stolen, so rate limits on the login do not apply.

## Mechanism

Having obtained password hashes (from a database breach, a dump, a captured
authentication exchange), the attacker runs a wordlist or exhaustive search through the
same hash function and compares, optionally with precomputed tables. Its feasibility
turns on the hashing choice: a fast, unsalted hash cracks quickly, while a slow,
salted, memory-hard function (bcrypt, scrypt, Argon2) resists it. It is distinguished
from the online sub-techniques by being offline: there is no interaction with the
target while cracking.

## How redstep exercises it

Not yet implemented, and likely to stay `capability: none` within redstep's model: the
cracking is offline and presupposes hashes already captured, so there is no live target
to drive and no lab witness. redstep's contribution here is upstream (surfacing where
hashes could be captured, or assessing the hashing choice), not an exploit-replay loop.
It is catalogued so the sub-technique is visible and its scope is explicit.

## What a verdict means

Not applicable as a live check. If assessed at all it would be a property of the stored
hashing scheme (algorithm, salt, cost), not a Pass/Fail against a running target under
[ADR-0010](../../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md).

## Confinement

Offline and target-free, so the lab isolation does not come into play; there is no
action against a target to confine. Any captured material used would be a fixture, not
real credentials.

## References

- ATT&CK: [T1110.002 Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
- CWE: [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- See the [Brute Force](README.md) umbrella for OWASP.
