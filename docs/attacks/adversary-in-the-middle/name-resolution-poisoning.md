---
name: Name Resolution Poisoning and SMB Relay
slug: name-resolution-poisoning
attack: [T1557.001]
owasp: []
cwe: [CWE-300]
targets: [network, identity]
capability: none
---

# Name Resolution Poisoning and SMB Relay

A sub-technique of [Adversary-in-the-Middle](README.md); see the umbrella for the
general technique.

## Summary

When a host fails to resolve a name through DNS, Windows falls back to broadcast
protocols (LLMNR, NBT-NS, mDNS) that any machine on the segment can answer. An attacker
answers these queries, the victim connects to the attacker believing it is the intended
host, and authenticates, handing over credential material that can be cracked or relayed
onward (SMB relay) to authenticate as the victim elsewhere.

## Mechanism

The attacker listens for LLMNR (UDP 5355), NBT-NS (UDP 137), or mDNS (UDP 5353) queries
and replies authoritatively for the requested name. The victim then opens a connection,
often SMB, and sends an NTLM authentication the attacker captures. Rather than crack it,
the attacker can relay that authentication to a third host that accepts it, gaining
access as the victim without ever knowing the password. It is distinguished from normal
resolution by the attacker answering for a name it does not own.

## How redstep exercises it

Not yet implemented (`capability: none`). On a shared lab segment the witness is the
captured authentication or a successful relay: the attacker vantage answers a victim's
broadcast query and records the credential material or the relayed session. It needs the
broadcast name-resolution protocols active between lab workloads and would land with the
network-boundary work (roadmap v0.3.0).

## What a verdict means

When implemented, a `Fail` (High) would mean the victim's authentication was captured or
relayed after the poisoned response. A confident "not exploitable" would mean the
broadcast fallback was not answerable or the authentication not usable (signing enforced)
([ADR-0010](../../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [network, identity]` technique acting within one lab segment; it reaches
nothing beyond it. The segment is egress-less
([ADR-0006](../../adr/0006-guarantee-safety-in-independent-layers.md)), scope is by
membership
([ADR-0011](../../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and any captured credential is a lab fixture, not real.

## References

- ATT&CK: [T1557.001 Name Resolution Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
- CWE: [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)
- See the [Adversary-in-the-Middle](README.md) umbrella.
