---
name: OS Credential Dumping
slug: os-credential-dumping
attack: [T1003]
owasp: []
cwe: [CWE-522]
targets: [identity]
capability: none
---

# OS Credential Dumping

## Summary

Credential dumping is extracting account secrets, password hashes, Kerberos tickets,
cleartext passwords, from where the operating system keeps them, so the attacker can
authenticate as those accounts or crack the hashes offline. It is the usual pivot from a
single compromised host to the rest of a network.

## Mechanism

ATT&CK (T1003) divides it by the store read: LSASS process memory on Windows (.001), the
SAM hive (.002), the Active Directory database NTDS.dit (.003), LSA secrets (.004),
cached domain credentials (.005), DCSync by impersonating a domain controller (.006), the
`/proc` filesystem (.007), and `/etc/passwd` and `/etc/shadow` on Linux (.008). The
attacker needs sufficient privilege on the host, then reads and parses the store. It is
distinguished from normal operation by secret material being read out of its store, so
the witness is a recovered credential or hash.

## How redstep exercises it

Not implemented, and largely out of redstep's lab scope: most sub-techniques are Windows
or Active Directory host internals (LSASS, SAM, NTDS, DCSync) that the Linux-Docker lab
does not model, and all require host-level access redstep's app-, network-, and
container-layer checks do not take. The one lab-adjacent case is reading `/etc/shadow`
from a container that has escalated, which is really a consequence of
[container escape](container-escape-to-host.md) or a misconfigured mount. It stays
`capability: none`, catalogued so the technique and its scope are explicit.

## What a verdict means

Not applicable as a lab check in the current model: there is no host-agent step to drive
and no running-target flaw for an exploit-replay loop. Where it touches redstep at all,
it is downstream of a container escape, whose verdict belongs to that technique
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

No in-lab action in the current model. Were the `/etc/shadow` case ever modelled, it
would run inside the egress-less lab
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) against a fixture
credential, under membership scope
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- ATT&CK: [T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003/) (sub-techniques folded here as reference-only, out-of-lab-scope)
- CWE: [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- OWASP: no application-layer category (ADR-0016 allows unmapped).
