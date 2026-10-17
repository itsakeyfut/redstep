---
name: Cloud IAM Privilege Escalation
slug: cloud-iam-privilege-escalation
attack: [T1098]
owasp: []
cwe: [CWE-269]
targets: [cloud, identity]
capability: none
---

# Cloud IAM Privilege Escalation

## Summary

Cloud identity and access management grants permissions through policies attached to
users, roles, and resources. When a low-privilege principal holds a permission that lets
it change those grants, it can escalate to higher privilege, and often to full account
control, without exploiting any software bug: the IAM policy itself is the flaw.

## Mechanism

Certain permissions are escalation primitives: creating a new access key for a more
privileged user, attaching an administrator policy to oneself, passing a privileged role
to a service one can invoke (`iam:PassRole` with `lambda:CreateFunction`), or editing a
policy version. The attacker chains the permissions it has into one it should not. It is
distinguished from legitimate administration by a principal granting itself authority it
was not given, so the witness is the principal performing an action its original policy
forbade.

## How redstep exercises it

Not implemented, and out of redstep's lab scope: it requires a real cloud provider's IAM
to evaluate policies and grant the escalation, which the software-defined lab does not
have. It stays `capability: none`, catalogued so the technique and its scope are explicit;
assessing it belongs to a cloud-posture tool that reads live IAM policies, not to the
lab's exploit-replay model. ATT&CK expresses the mechanisms as Account Manipulation
sub-techniques (Additional Cloud Credentials, Additional Cloud Roles).

## What a verdict means

Not applicable as a lab check in the current model: it would be a property of a live IAM
policy graph (which permissions reach an escalation), assessed against a real account, not
a Pass/Fail reached against an in-lab target
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

No lab action to confine: the technique is outside the software-defined lab, and the
egress-less network ([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md))
means redstep cannot reach a real provider's IAM to act on it in the first place.

## References

- ATT&CK: [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) (cloud sub-techniques: Additional Cloud Credentials, Additional Cloud Roles)
- CWE: [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- OWASP: no application-layer category (ADR-0016 allows unmapped).
