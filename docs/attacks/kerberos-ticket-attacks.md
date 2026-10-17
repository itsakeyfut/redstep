---
name: Kerberos Ticket Attacks
slug: kerberos-ticket-attacks
attack: [T1558]
owasp: []
cwe: [CWE-522]
targets: [identity]
capability: none
---

# Kerberos Ticket Attacks

## Summary

Kerberos authenticates users in Active Directory by issuing signed tickets. Its ticket
attacks abuse how those tickets are requested, signed, and validated to crack service
account passwords offline or to forge tickets that grant arbitrary access, up to full
domain compromise.

## Mechanism

ATT&CK (T1558) groups the variants. Kerberoasting (.003) requests service tickets for
accounts with a service principal name and cracks the returned, account-password-encrypted
ticket offline. AS-REP roasting (.004) targets accounts that do not require
pre-authentication, obtaining crackable material without credentials. A silver ticket
(.002) forges a service ticket using a captured service account key; a golden ticket
(.001) forges ticket-granting tickets using the domain's KRBTGT key, minting access to
anything. They are distinguished from legitimate Kerberos use by tickets being cracked
offline or forged, so the witness is a cracked service password or a forged ticket being
accepted.

## How redstep exercises it

Not implemented, and out of redstep's lab scope: these are Active Directory and Kerberos
attacks, and the Linux-Docker lab runs no domain controller or KDC to issue, sign, or
validate tickets. They stay `capability: none`, catalogued so the Kerberos family is
visible and its scope is explicit; assessing them needs an AD environment redstep does
not model.

## What a verdict means

Not applicable as a lab check in the current model: there is no KDC and no running-target
flaw for an exploit-replay loop
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

No in-lab action: the technique is outside the software-defined lab, which runs no Active
Directory, and the egress-less network
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) means redstep could
not reach a real domain's KDC in any case.

## References

- ATT&CK: [T1558 Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) (Kerberoasting, AS-REP roasting, silver and golden tickets, folded here as reference-only, out-of-lab-scope)
- CWE: [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- OWASP: no application-layer category (ADR-0016 allows unmapped).
