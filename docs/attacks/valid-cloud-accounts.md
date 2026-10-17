---
name: Valid Cloud Accounts
slug: valid-cloud-accounts
attack: [T1078.004]
owasp: []
cwe: []
targets: [cloud, identity]
capability: none
---

# Valid Cloud Accounts

## Summary

Using legitimate cloud credentials, rather than exploiting a vulnerability, to access and
act within a cloud environment. Credentials leaked in code, captured from metadata, or
phished give an attacker a valid identity, and because the activity is authenticated it
blends in with normal use, which is what makes it both common and hard to spot.

## Mechanism

The attacker obtains a working credential, an access key committed to a repository, a
token from [instance metadata](cloud-instance-metadata-abuse.md), a password reused from
a breach, and authenticates to the cloud provider as that principal. From there they
have exactly the permissions the principal holds, which is often more than intended. It
is distinguished from legitimate access only by the actor, not the mechanism, so there is
no software flaw to witness, only the use of the credential.

## How redstep exercises it

Not implemented, and out of redstep's lab scope: it presupposes a real cloud account and
valid credentials for it, which the software-defined lab does not have, and there is no
vulnerability for an exploit-replay loop to confirm. It stays `capability: none`,
catalogued so the technique is visible; redstep's contribution is upstream, the
techniques that leak a credential in the first place ([instance metadata
abuse](cloud-instance-metadata-abuse.md), SSRF, information disclosure), not the use of a
valid one.

## What a verdict means

Not applicable as a lab check: there is no flaw to decide a verdict on, only an actor
using a valid identity. Any assessment would be of how credentials could be obtained or
of least-privilege on the account, not a Pass/Fail against a target
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

No lab action to confine: outside the software-defined lab, and the egress-less network
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) means redstep cannot
authenticate to a real provider at all.

## References

- ATT&CK: [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- Related: [Cloud Instance Metadata Abuse](cloud-instance-metadata-abuse.md), a common source of the credentials.
- OWASP: no application-layer category (ADR-0016 allows unmapped).
