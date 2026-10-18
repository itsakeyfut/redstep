---
name: Valid Accounts
slug: valid-accounts
attack: [T1078]
owasp: [A07:2021-Identification and Authentication Failures]
cwe: []
targets: [web, api, identity]
capability: none
---

# Valid Accounts

## Summary

The most common way into a breach is not an exploit but a login: authenticating with
legitimate credentials the attacker obtained, phished, leaked, cracked, reused, or stolen
from a token store. Because the session is genuine, the activity blends with normal use.
In the Verizon DBIR this credential abuse is consistently the top initial-access vector,
which is why it earns its own entry even though there is no flaw to exploit in the login
itself.

## Mechanism

The attacker first obtains a working credential, by [brute force](brute-force/README.md),
[credential stuffing](brute-force/credential-stuffing.md), [phishing](phishing.md), a
leak, or [cloud metadata](cloud-instance-metadata-abuse.md), then authenticates as that
principal and inherits its access, often more than it should have. It is distinguished
from legitimate access only by the actor, not the mechanism, so there is no software
vulnerability to witness, only the use of the credential and whether a secondary control
stops it.

## How redstep exercises it

Not implemented, and largely `capability: none` by nature: the use of a valid credential is
legitimate authentication, so there is no flaw for an exploit-replay loop. redstep's
contribution is upstream, the techniques that obtain the credential (brute force,
credential stuffing, phishing, metadata abuse, information disclosure), and, where a target
can be driven, confirming that a secondary control (MFA, anomaly detection, a reuse check)
does not stop a credential presented from a new context, which is the [MFA
bypass](mfa-bypass.md) and [session hijacking](session-hijacking.md) territory. The cloud
case is [valid cloud accounts](valid-cloud-accounts.md).

## What a verdict means

Not a single exploit verdict: whether obtained credentials grant access, and whether a
secondary control catches their misuse. Where redstep can test it, it is the secondary
control that is under test, not the login, under the usual confidence model
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api, identity]` technique acting on the scoped target's authentication
inside the lab; any credential used is a fixture, not real, recorded in the reproduction
and treated as sensitive (security.md). Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- ATT&CK: [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- OWASP: [A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- Empirical: the Verizon DBIR reports credential abuse as the leading initial-access vector.
- Related: [Brute Force](brute-force/README.md), [Phishing](phishing.md), [Valid Cloud Accounts](valid-cloud-accounts.md), [Use of Alternate Authentication Material](alternate-authentication-material.md).
