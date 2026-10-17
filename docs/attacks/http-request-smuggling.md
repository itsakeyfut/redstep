---
name: HTTP Request Smuggling
slug: http-request-smuggling
attack: [unmapped]
owasp: []
cwe: [CWE-444]
targets: [web]
capability: none
---

# HTTP Request Smuggling

## Summary

When a front-end server and the back-end it forwards to disagree about where one HTTP
request ends and the next begins, an attacker can smuggle part of a request across that
boundary. The smuggled bytes are then prepended to another user's request, letting the
attacker capture that user's request, poison the response they receive, or bypass
front-end access controls.

## Mechanism

The desync comes from conflicting interpretations of message length, classically
`Content-Length` versus `Transfer-Encoding: chunked` (CL.TE, TE.CL, TE.TE), where one
server honours one header and the other the other. The attacker crafts a request whose
trailing bytes one server treats as the start of the next request. A true smuggle is
distinguished from a malformed request by those bytes actually affecting a subsequent
request on the connection, so the witness is a later request or response showing the
injected prefix.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is a desync effect, which needs a
front-end and a back-end in the lab (the disagreement is between two hops): the probe
sends a crafted request and observes a following request being altered, or a response
arriving with the smuggled prefix. It does not fit the single-hop body-marker seam.

## What a verdict means

When implemented, a `Fail` (High) would mean the two hops disagreed and the smuggled
bytes crossed the boundary. A confident "not exploitable" would prove only that the
variant tried (CL.TE, TE.CL, ...) did not desync this pair, not that no variant does
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique whose effect is between two in-lab hops; it reaches nothing
beyond the lab. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- CWE: [CWE-444 Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)](https://cwe.mitre.org/data/definitions/444.html)
- PortSwigger Web Security Academy: [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- OWASP: no distinct Top 10 category; ATT&CK unmapped (ADR-0016 allows both).
