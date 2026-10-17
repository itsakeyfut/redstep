---
name: Credentials in Container Images
slug: credentials-in-container-images
attack: [T1552.001]
owasp: []
cwe: [CWE-798]
targets: [container, identity]
capability: none
---

# Credentials in Container Images

## Summary

A container image is a stack of layers anyone who can pull it can inspect. Secrets baked
into an image, an API key in an environment variable, a private key copied in during
build, a `.env` committed into a layer, are readable by anyone with the image, and they
persist in the layer history even if a later layer deletes the file.

## Mechanism

Secrets reach an image through a `COPY` of a file that contained one, an `ENV` or build
argument set to a key, or a credential written during build and removed in a later layer
(but still present in the earlier one). The attacker who obtains the image, from a public
or weakly-protected registry, extracts the layers and reads the secret. It is
distinguished from a clean image by a usable credential being recoverable from the image,
so the witness is that credential extracted from a layer or the image config.

## How redstep exercises it

Not yet implemented (`capability: none`), and lab-modelable: the check would inspect a
built image's layers and config for a sentinel secret and witness it being recoverable
even if a later layer removed the file. It is static inspection of an artifact rather than
a probe against a running target, so it sits a little aside from the exploit-replay
checks, but the lab already builds the playground images it would examine.

## What a verdict means

When implemented, a `Fail` (High) would mean a usable credential was recovered from the
image. A confident "not exploitable" would mean the layers and config carried no secret
that the inspection recognised
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [container, identity]` technique that inspects an artifact rather than acting
on a live target, so there is little to confine; it runs against images the lab builds or
holds, and any secret used as a witness is a fixture, not a real credential. The evidence
that records a found secret is treated as sensitive regardless (security.md).

## References

- ATT&CK: [T1552.001 Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- CWE: [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- OWASP: no application-layer category (ADR-0016 allows unmapped).
