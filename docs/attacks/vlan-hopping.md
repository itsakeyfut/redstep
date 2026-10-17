---
name: VLAN Hopping
slug: vlan-hopping
attack: [unmapped]
owasp: []
cwe: [CWE-300]
targets: [network]
capability: none
---

# VLAN Hopping

## Summary

VLANs segment a switched network so hosts on one VLAN cannot reach another at layer 2.
VLAN hopping defeats that segmentation, letting an attacker on one VLAN send traffic into
another they should not reach, crossing a boundary the network design relied on.

## Mechanism

Two classic routes. In switch spoofing, the attacker's port negotiates a trunk (via DTP),
so the switch delivers it traffic for all VLANs. In double tagging, the attacker prepends
two 802.1Q tags; the first switch strips the outer tag and forwards the frame on, and a
second switch acts on the inner tag, delivering it into the target VLAN. It is
distinguished from normal switching by a frame crossing a VLAN boundary it should not, so
the witness is traffic arriving on a VLAN the attacker was not a member of.

## How redstep exercises it

Not implemented, and out of redstep's lab scope: it turns on physical-switch behaviour
(DTP trunk negotiation, 802.1Q tag handling) that the lab's software-defined Docker
networks do not model. It stays `capability: none`, catalogued so the technique is visible
and its scope is explicit rather than silently absent; redstep's segmentation is enforced
by separate Docker networks, whose boundary the membership self-check already verifies.

## What a verdict means

Not applicable as a lab check in the current model. Where redstep does enforce a segment
boundary, it is the membership and boundary self-check
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md))
that proves a forbidden path is unreachable, which is the property VLAN hopping would
attack
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

No lab action to confine in the current model: the technique is outside the
software-defined lab. Were it ever modelled, the egress-less network
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) would keep any crossed
boundary inside the lab.

## References

- CWE: [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)
- ATT&CK: no distinct enterprise technique; related to network boundary bridging. Unmapped (ADR-0016).
