---
name: Privilege Escalation
slug: privilege-escalation
attack: [unmapped]
owasp: [A01:2021-Broken Access Control]
cwe: [CWE-862]
targets: [web, api]
capability: none
---

# Privilege Escalation

## Summary

Privilege escalation is a user reaching functionality or data above their
authorization level: a normal user invoking an admin-only function, or reading an
object a role boundary should have denied. Where [IDOR](idor.md) is access across
object ownership at the same level, this is access across privilege levels, and it is
the broken-function-level-authorization half of broken access control.

## Mechanism

The server enforces authorization in the UI (hiding the admin link) or on the wrong
layer, but not on the privileged endpoint itself, so a lower-privilege identity that
calls the endpoint directly, for example `POST /admin/users/1/delete`, is served. A
true escalation is distinguished from a denied request by the privileged action
succeeding, or privileged data returning, for an unprivileged identity, so the witness
is that effect under a low-privilege credential.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness parallels the IDOR check but
across privilege rather than ownership: as a low-privilege identity (carried in the
request-headers identity channel the IDOR check already uses) the probe calls a
privileged endpoint and reads a marker only a privileged response would contain, or
observes the privileged action's effect, through the body-marker seam.

## What a verdict means

When implemented, a `Fail` (High) would mean a privileged function or datum was reached
by an unprivileged identity. A confident "not exploitable" would prove only that this
endpoint denied this identity, and, as with IDOR, must not be read as proof the
low-privilege identity actually took effect rather than the request failing for another
reason
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique acting within the scoped target; it reaches nothing
beyond it. Scope resolves the target by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/); for APIs, [API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- CWE: [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html); the authentication counterpart, [CWE-306 Missing Authentication for a Critical Function](https://cwe.mitre.org/data/definitions/306.html) (a sensitive action that requires no authentication at all), is folded here as the same broken-access-control failure seen from the authentication side.
- PortSwigger Web Security Academy: [Access control vulnerabilities](https://portswigger.net/web-security/access-control)
- ATT&CK: no enterprise technique maps cleanly to web function-level authorization; OWASP above is the mapping (ADR-0016).
