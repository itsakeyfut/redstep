---
name: HTTP Host Header Attacks
slug: http-host-header-attacks
attack: [unmapped]
owasp: []
cwe: [CWE-20]
targets: [web]
capability: none
---

# HTTP Host Header Attacks

## Summary

Many applications trust the `Host` header, which is client-controlled, to decide what
site they are, which links to build, or which back-end to route to. An attacker who
supplies a crafted `Host` can poison absolute URLs the server generates (a password
reset link pointing at the attacker), reach internal vhosts, or feed a cache a response
keyed to the wrong host.

## Mechanism

The server reads `Host` (or related headers like `X-Forwarded-Host`) and uses it
without validation: it builds `https://<Host>/reset?token=...` into an email, or routes
by it, or caches by it. The attacker sets `Host` to a domain they control. A true
vulnerability is distinguished from a safe one by the attacker-controlled host actually
being used in a sensitive place, so the witness is the poisoned output: the attacker
host in a generated link, or a redirect or cached response that honours it.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is often in-band (the attacker
`Host` reflected into a generated URL in the response body, read by the body-marker
seam) and sometimes out-of-band (a poisoned reset link that, when followed, reaches the
in-lab canary,
[ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)). The
probe would set a sentinel host and look for it in the response or at the canary.

## What a verdict means

When implemented, a `Fail` (High) would mean the server used the attacker-supplied host
in a sensitive output. A confident "not exploitable" would prove only that this header
and sink were not honoured, not that another header (`X-Forwarded-Host`) or sink is safe
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique whose sentinel host is in-lab; nothing leaves the
egress-less lab
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), and scope resolves
the target by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- CWE: [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- PortSwigger Web Security Academy: [HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- OWASP: no distinct Top 10 category; ATT&CK unmapped (ADR-0016).
