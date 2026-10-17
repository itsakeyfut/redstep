---
name: Multi-Factor Authentication Bypass
slug: mfa-bypass
attack: [T1111, T1621]
owasp: [A07:2021-Identification and Authentication Failures]
cwe: [CWE-287]
targets: [identity]
capability: none
---

# Multi-Factor Authentication Bypass

## Summary

Multi-factor authentication is meant to stop an attacker who has the password. MFA bypass
defeats the second factor anyway, by intercepting it, by wearing the victim down with
requests until they approve one, or by exploiting a flaw in how the factor is enrolled or
validated, so a stolen password becomes a full login.

## Mechanism

Several routes. Interception (T1111) captures a one-time code in transit (SMS, a phishing
proxy that relays it). Request generation, or MFA fatigue (T1621), repeatedly triggers
push approvals until the victim accepts one to stop the noise. Flaws in the flow are
their own route: a code with no rate limit (brute-forceable), a recovery path that skips
the factor, or an enrollment an attacker can hijack. It is distinguished from a blocked
login by the second factor being satisfied without the legitimate user's intent, so the
witness is a session granted past MFA.

## How redstep exercises it

Not yet implemented (`capability: none`). The flow-flaw cases are the ones redstep could
reach against a web target: a one-time code with no rate limit is a
[brute-force](brute-force/README.md)-shaped check against the MFA step, and a recovery or
enrollment path that skips the factor is a logic flaw. The human-in-the-loop cases
(fatigue, real-time phishing) are outside a non-interactive lab. The witness for the
in-scope cases is a session granted after the factor was not properly required.

## What a verdict means

When implemented for a flow flaw, a `Fail` (High) would mean a session was granted past
MFA without satisfying the factor legitimately. A confident "not exploitable" would prove
only that the flaw tried was absent, not that the factor is sound against the others
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [identity]` technique acting on the scoped target's auth; the in-scope flow
checks run within the egress-less lab
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) under membership scope
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- ATT&CK: [T1111 Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111/) and [T1621 Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/)
- OWASP: [A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- CWE: [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
