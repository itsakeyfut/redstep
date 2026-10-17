---
name: Web Cache Poisoning
slug: web-cache-poisoning
attack: [unmapped]
owasp: []
cwe: [CWE-349]
targets: [web]
capability: none
---

# Web Cache Poisoning

## Summary

A cache stores a response under a key built from part of the request (method, path,
some headers) and serves it to everyone whose request has the same key. If the response
depends on an input that is not part of the key, an attacker can make the server
generate a harmful response and have the cache serve it to other users: stored XSS,
a redirect, or a denial of the real page, at the cache's scale.

## Mechanism

The attacker finds an unkeyed input the response reflects or acts on (a header such as
`X-Forwarded-Host`, a cookie, a query parameter the cache strips from the key), sends a
request that both poisons the response and matches the key other users will use, and the
cache stores the poisoned response. A true poisoning is distinguished from a one-off
reflected issue by the harmful response being cached and then served to a request that
did not carry the attacker's input, so the witness is a clean follow-up request
receiving the poisoned response.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness needs a cache in the lab and two
requests: the probe sends a poisoning request with a sentinel in an unkeyed input, then
a clean request, and checks whether the clean response carries the sentinel. It is a
stateful, two-request check rather than the single-probe body-marker seam.

## What a verdict means

When implemented, a `Fail` (High) would mean a clean request received a response
poisoned by the earlier one, so an unkeyed input reached the cache. A confident "not
exploitable" would prove only that the input tried was keyed or not reflected, not that
no unkeyed input exists
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique whose effect is confined to an in-lab cache serving in-lab
clients; nothing leaves the egress-less lab
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), and scope resolves
the target by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- CWE: [CWE-349 Acceptance of Extraneous Untrusted Data With Trusted Data](https://cwe.mitre.org/data/definitions/349.html)
- PortSwigger Web Security Academy: [Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- OWASP: no distinct Top 10 category; ATT&CK unmapped (ADR-0016).
