---
name: Race Conditions
slug: race-conditions
attack: [unmapped]
owasp: []
cwe: [CWE-362]
targets: [web, api]
capability: none
---

# Race Conditions

## Summary

When the result of an operation depends on the timing of concurrent requests, an
attacker who sends overlapping requests can slip between a check and the action it
guards. The effect is a limit that should hold once holding several times: a one-time
coupon redeemed twice, a balance overspent, a withdrawal counted once but paid twice.

## Mechanism

The server checks a condition and acts on it in steps that are not atomic (a
time-of-check to time-of-use gap), so several concurrent requests each pass the check
before any completes the action. The attacker fires requests simultaneously to land in
that window. A true race is distinguished from normal use by concurrency producing an
outcome a single request could not, so the witness is the duplicated or over-limit
effect.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is stateful and timing-driven:
the probe sends several overlapping requests and a follow-up read shows an effect that
should have been singular (a limit exceeded, a benefit granted twice). It needs
concurrency, so it is a multi-request check rather than the single-probe body-marker
seam.

## What a verdict means

When implemented, a `Fail` (High) would mean concurrency produced a forbidden state. A
"not exploitable" result is weaker here than elsewhere, because a clean run may simply
have missed the timing window, so it should carry lower confidence rather than a
confident negative
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique acting within the scoped target; it reaches nothing
beyond it. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- CWE: [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)](https://cwe.mitre.org/data/definitions/362.html)
- PortSwigger Web Security Academy: [Race conditions](https://portswigger.net/web-security/race-conditions)
- OWASP: no distinct Top 10 category; ATT&CK unmapped (ADR-0016).
