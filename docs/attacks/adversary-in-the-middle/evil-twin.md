---
name: Evil Twin
slug: evil-twin
attack: [T1557.004]
owasp: []
cwe: [CWE-300]
targets: [network]
capability: none
---

# Evil Twin

A sub-technique of [Adversary-in-the-Middle](README.md); see the umbrella for the
general technique.

## Summary

An evil twin is a rogue Wi-Fi access point that copies a legitimate network's name
(SSID), so devices and users connect to it believing it is the real one. Once connected,
all of the victim's traffic passes through the attacker, who is on-path from the first
packet.

## Mechanism

The attacker broadcasts a stronger or identically-named SSID, optionally deauthenticating
victims from the real access point so they reconnect to the twin. Because many devices
auto-join known SSIDs, the victim associates without noticing. It is distinguished from
the real network by the access point being attacker-operated, so the witness is the
victim associating and routing through it.

## How redstep exercises it

Not implemented, and out of redstep's lab scope: this is a wireless, radio-layer attack,
and the lab is a set of software-defined Docker networks with no Wi-Fi. It stays
`capability: none`, catalogued for completeness of the Adversary-in-the-Middle family and
so its scope is explicit rather than silently absent.

## What a verdict means

Not applicable as a lab check. The on-path consequences, once associated, are the same as
the other AiTM sub-techniques, which is where redstep's interception witnesses apply; the
wireless association itself is what the lab cannot reproduce
([ADR-0010](../../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

No lab action to confine: the technique is outside the software-defined lab, so there is
nothing for the isolation layers to contain here.

## References

- ATT&CK: [T1557.004 Evil Twin](https://attack.mitre.org/techniques/T1557/004/)
- CWE: [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)
- See the [Adversary-in-the-Middle](README.md) umbrella.
