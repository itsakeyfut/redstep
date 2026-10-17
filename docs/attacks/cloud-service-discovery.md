---
name: Cloud Service and Infrastructure Discovery
slug: cloud-service-discovery
attack: [T1526, T1580]
owasp: []
cwe: []
targets: [cloud]
capability: none
---

# Cloud Service and Infrastructure Discovery

## Summary

Once an attacker holds a cloud credential, they enumerate what the account contains and
what services it uses, the instances, storage, databases, functions, networks, and the
permissions on them. It is the cloud equivalent of network service discovery: the map
that tells the attacker what is worth taking and where to escalate.

## Mechanism

The attacker calls the provider's own management APIs (list buckets, describe instances,
enumerate roles and policies) with the credential they hold. Because these are
read-only, intended APIs, the activity is quiet. It is reconnaissance rather than
exploitation, so its witness is the inventory produced, not a changed state.

## How redstep exercises it

Not implemented, and out of redstep's lab scope: it requires a real provider's management
APIs and a valid credential, which the software-defined lab does not have. It stays
`capability: none`, catalogued so the technique is visible; it is the cloud counterpart of
the in-lab [network service discovery](network-service-discovery.md), and like that one
it produces an inventory rather than a verdict.

## What a verdict means

Not applicable as a lab check: discovery yields an inventory, not a Pass/Fail, and against
a real account it is outside the lab entirely
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

No lab action to confine: outside the software-defined lab, and the egress-less network
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) means redstep cannot
reach a real provider's APIs.

## References

- ATT&CK: [T1526 Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/) and [T1580 Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)
- Related: [Network Service Discovery](network-service-discovery.md), the in-lab, network-layer counterpart.
- OWASP: no application-layer category (ADR-0016 allows unmapped).
