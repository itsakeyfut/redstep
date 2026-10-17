---
name: Public Cloud Storage Exposure
slug: public-cloud-storage-exposure
attack: [T1530, T1619]
owasp: []
cwe: [CWE-732]
targets: [cloud]
capability: none
---

# Public Cloud Storage Exposure

## Summary

Cloud object storage (S3 buckets, Azure blobs, GCS buckets) is private by default but
easily made world-readable or world-listable by a misconfiguration. When it is, anyone
who knows or guesses the bucket name reads the data: backups, customer records, secrets,
source. It is one of the most common causes of large data exposures.

## Mechanism

An over-permissive bucket policy or ACL grants read, or list, to everyone. The attacker
enumerates likely bucket names (often derived from the company or product), lists the
objects if listing is open, and downloads them. It is distinguished from intended public
hosting by sensitive data being reachable without authorization, so the witness is a
private object retrieved anonymously.

## How redstep exercises it

Not yet implemented (`capability: none`). Partly lab-modelable against a mock object
store on the lab network: the witness is a sentinel object retrieved without credentials.
Against a real provider it is out of the lab's reach, which is the point of the
egress-less design, so a live check would be limited to an in-lab stand-in.

## What a verdict means

When implemented, a `Fail` (High) would mean a sentinel object was read, or the bucket
listed, without authorization. A confident "not exploitable" would mean anonymous access
was denied
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [cloud]` technique modelled only against an in-lab mock store; the egress-less
lab ([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) prevents reaching a
real provider's storage, and scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).
Any object used is a fixture, not real data.

## References

- ATT&CK: [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) and [T1619 Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619/)
- CWE: [CWE-732 Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- OWASP: no application-layer category (ADR-0016 allows unmapped).
