---
name: XML External Entity Injection
slug: xxe
attack: [T1190]
owasp: [A05:2021-Security Misconfiguration]
cwe: [CWE-611]
targets: [web]
capability: none
---

# XML External Entity Injection

## Summary

An XML parser configured to resolve external entities lets an attacker who controls
the XML define an entity that points at a local file or an internal URL, and have its
contents substituted into the parsed document. The result is server-side file read,
SSRF, or in some parsers denial of service, from any endpoint that accepts XML.

## Mechanism

The endpoint parses attacker-supplied XML with a parser that has external-entity
resolution enabled (the unsafe default in many libraries). The attacker declares a
`DOCTYPE` with an external entity, for example `<!ENTITY x SYSTEM "file:///etc/passwd">`,
then references `&x;` where the parsed value is echoed back or acted on. A true XXE is
distinguished from an ordinary parse by the external resource's contents actually being
pulled in, so the witness is the file content returned, or an out-of-band fetch arriving
at a canary when the entity names a URL.

## How redstep exercises it

Not yet implemented (`capability: none`). Two witness shapes fit, mirroring the native
checks: an in-band one where the entity reads a sentinel file and the content comes back
in the response (the body-marker seam), and a blind, out-of-band one where the entity
names an in-lab canary URL and the parse makes the server fetch it
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)). The
out-of-band shape overlaps with SSRF, since XXE is one way to reach it.

## What a verdict means

When implemented, a `Fail` (High) would mean the external entity resolved: a sentinel
file's content returned, or the canary recorded the entity's fetch. A confident "not
exploitable" would prove only that this payload did not resolve an entity, not that the
parser is safe against every entity or DTD trick
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique that reads local files or makes the server fetch a URL,
both of which stay inside the lab: the network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) so an entity naming
real infrastructure cannot reach it, and the files read are inside the scoped target's
container, resolved by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- OWASP: [A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) (XXE was merged into this category in 2021)
- CWE: [CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- PortSwigger Web Security Academy: [XML external entity (XXE) injection](https://portswigger.net/web-security/xxe)
- ATT&CK: maps coarsely to [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/); OWASP above is the sharper application-layer mapping (ADR-0016).
