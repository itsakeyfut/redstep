---
name: Adversary-in-the-Middle
slug: adversary-in-the-middle
attack: [T1557]
owasp: []
cwe: [CWE-300]
targets: [network, identity]
capability: none
---

# Adversary-in-the-Middle

This is an umbrella: it teaches the general technique and links its sub-techniques,
each of which is a file of its own carrying the redstep detail, its own ATT&CK
sub-technique id, and its own capability.

## Summary

Adversary-in-the-middle (AiTM) is taking a position on a network so that traffic
between two parties flows through the attacker, who can then read it, alter it, or
relay it to impersonate one side. Where an application attack abuses one endpoint, AiTM
abuses the network between endpoints, so it undermines confidentiality and integrity for
every protocol that trusts the path.

## Mechanism

The attacker subverts whatever the network uses to decide where to send a frame or
packet: the layer-2 address mapping (ARP), name resolution (LLMNR, NBT-NS, mDNS),
address assignment (DHCP), or wireless association (a rogue access point). Once victims
send their traffic to the attacker instead of the real destination, the attacker is
on-path. ATT&CK T1557 divides the technique by which mechanism is subverted, which is
why it is a directory here.

## Sub-techniques

- [ARP Cache Poisoning](arp-cache-poisoning.md) (T1557.002)
- [Name Resolution Poisoning and SMB Relay](name-resolution-poisoning.md) (T1557.001)
- [DHCP Spoofing](dhcp-spoofing.md) (T1557.003)
- [Evil Twin](evil-twin.md) (T1557.004)

## References

- ATT&CK: [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- CWE: [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)
