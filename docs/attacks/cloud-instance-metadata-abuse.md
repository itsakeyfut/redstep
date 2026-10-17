---
name: Cloud Instance Metadata Abuse
slug: cloud-instance-metadata-abuse
attack: [T1552.005]
owasp: []
cwe: [CWE-522]
targets: [cloud]
capability: none
---

# Cloud Instance Metadata Abuse

## Summary

Cloud virtual machines expose a metadata service at a link-local address
(`169.254.169.254`) that returns instance configuration and, crucially, temporary
credentials for the instance's role. An attacker who can make a request to that endpoint
from the instance, directly or through [SSRF](ssrf.md), reads those credentials and then
acts with the instance's cloud permissions.

## Mechanism

The metadata endpoint answers any request from the instance with no authentication, so
whoever can originate a request from the host reaches it. The classic path is SSRF: a
server that fetches a caller-supplied URL is pointed at the metadata endpoint, and its
response hands back the role's access keys. With those keys the attacker calls the cloud
provider's APIs as the instance. It is distinguished from legitimate use by the
credentials being read by an attacker-controlled request, so the witness is the metadata
response, or a subsequent API call made with the stolen keys.

## How redstep exercises it

Not yet implemented (`capability: none`), but the most lab-modelable of the cloud
techniques: a mock metadata service on the lab network stands in for `169.254.169.254`,
and the witness is a sentinel credential reaching the attacker, the same out-of-band
shape as the SSRF canary ([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)).
It is the cloud consequence of SSRF; the [SSRF](ssrf.md) entry is the web vulnerability
that most often reaches it.

## What a verdict means

When implemented, a `Fail` (High) would mean the instance's metadata credentials were
read through an attacker-originated request. A confident "not exploitable" would mean the
metadata endpoint was not reachable that way (IMDSv2 session requirement, egress
controls, no SSRF path)
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [cloud]` technique modelled only against an in-lab mock: the egress-less lab
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) means redstep cannot
reach a real provider's metadata service in the first place, which is itself the
guarantee that a test cannot touch real cloud credentials. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and any credential used is a fixture.

## References

- ATT&CK: [T1552.005 Unsecured Credentials: Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/)
- CWE: [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- Related: [SSRF](ssrf.md), the web vulnerability that most often reaches the metadata endpoint.
