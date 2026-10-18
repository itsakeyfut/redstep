---
name: Phishing
slug: phishing
attack: [T1566]
owasp: []
cwe: []
targets: [identity]
capability: none
---

# Phishing

## Summary

Phishing deceives a person into handing over credentials or running attacker content, with
a message or site that impersonates something they trust. It is the archetypal
social-engineering attack and, in the Verizon DBIR, one of the top initial-access vectors
year after year, because it targets the person rather than the software and no patch closes
it.

## Mechanism

The attacker sends a crafted email or message, or stands up a lookalike site, and induces
an action: entering a password into a credential-harvesting page, opening a malicious
attachment, or clicking a link that delivers a payload or relays an authentication. ATT&CK
divides it by delivery, a malicious attachment (T1566.001), a link (T1566.002), or a
message through a service (T1566.003). It is distinguished from legitimate correspondence
by the deception succeeding, so the "witness" is a human acting on it, which is exactly
what makes it a people problem rather than a software one.

## How redstep exercises it

Not implemented, and out of redstep's scope: it targets a human, and the lab is a
non-interactive set of software workloads with no person and no real mail or messaging to
deceive. It stays `capability: none`, catalogued because it is empirically a top real-world
entry point and its absence must be explicit rather than silent. redstep's adjacent
contribution is downstream: a harvested credential becomes [valid accounts](valid-accounts.md),
and a clicked link lands on whatever web vulnerability the target has.

## What a verdict means

Not applicable as a lab check: there is no human in the lab to deceive and no software flaw
to decide a verdict on. Any assessment of phishing exposure is a people-and-process matter
outside redstep's model
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

No lab action to confine: the technique is outside the software-defined lab, which has no
human target and, being egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), no path to a real
person in any case.

## References

- ATT&CK: [T1566 Phishing](https://attack.mitre.org/techniques/T1566/) (attachment, link, via service)
- Empirical: the Verizon DBIR consistently ranks phishing among the top initial-access vectors.
- Related: [Valid Accounts](valid-accounts.md) (the harvested-credential consequence).
