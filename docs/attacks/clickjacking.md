---
name: Clickjacking
slug: clickjacking
attack: [unmapped]
owasp: []
cwe: [CWE-1021]
targets: [web]
capability: none
---

# Clickjacking

## Summary

Clickjacking (UI redressing) frames a vulnerable site inside an attacker page, made
invisible or disguised, so the victim's clicks land on the real site's controls while
they believe they are interacting with the attacker's page. It turns a victim's
genuine clicks into actions on a site they are logged in to.

## Mechanism

The vulnerable site can be loaded in an `iframe` because it does not forbid framing
(no `X-Frame-Options: DENY` and no `Content-Security-Policy: frame-ancestors`). The
attacker overlays the transparent frame beneath decoy UI and positions a sensitive
control (a "delete account" button, an OAuth consent) under something the victim will
click. A true exposure is distinguished from a safe page by the page being framable at
all, so the witness is the absence of a framing restriction, confirmed by the framed
page remaining interactive.

## How redstep exercises it

Not yet implemented (`capability: none`). The first-order witness is a response-header
check: whether `X-Frame-Options` or a CSP `frame-ancestors` directive forbids framing.
Confirming exploitability (that a sensitive control can actually be reached through the
frame) needs a browser to render the overlay, so a full check would use an in-lab
headless browser, while a header check alone gives the weaker signal.

## What a verdict means

When implemented, a header-only `Fail` would mean the page permits framing, a
necessary condition; confirming a clickjack would need a browser to show a sensitive
control is reachable, so a header-only result is better reported as a weaker-confidence
observation than a `High` exploit
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).
A confident "not exploitable" would mean framing is forbidden.

## Confinement

A `targets: [web]` technique whose effect is in a browser the lab drives; it reaches
nothing beyond the lab. Scope resolves the target by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), so any attacker
framing page is itself an in-lab workload.

## References

- OWASP: not a distinct Top 10 category; see the [Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- CWE: [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
- PortSwigger Web Security Academy: [Clickjacking](https://portswigger.net/web-security/clickjacking)
- ATT&CK: no enterprise technique maps cleanly; the mapping is the CWE above (ADR-0016 allows unmapped).
