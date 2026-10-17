---
name: Unrestricted Resource Consumption
slug: unrestricted-resource-consumption
attack: [unmapped]
owasp: [API4:2023-Unrestricted Resource Consumption]
cwe: [CWE-770]
targets: [api]
capability: none
---

# Unrestricted Resource Consumption

## Summary

An API that puts no limit on what a single request may demand lets a caller exhaust CPU,
memory, bandwidth, or paid third-party quota: unbounded page sizes, expensive
operations, no rate limit. The result is degraded or denied service for everyone, and
sometimes a large bill.

## Mechanism

The service accepts requests without a ceiling on rate, page size, payload size, or the
cost of an operation it triggers (an email send, an upstream API call). A caller asks
for more than the service can sustain, or repeats a costly call. It is distinguished
from normal load by the absence of a limit, not by any single request being malformed.

## How redstep exercises it

Not yet implemented, and likely to stay `capability: none`: redstep does not perform
denial-of-service, so it will not drive a target to exhaustion. The useful,
non-destructive signal is detecting *missing* limits (no rate-limit response headers, an
unbounded page size accepted, a payload far over any sane cap returning normally) rather
than causing the harm. It is catalogued so the risk is visible and the deliberate scope
(no DoS, per the project's safety posture) is explicit.

## What a verdict means

Not a load test. If assessed, it would be a property of whether limits are declared and
enforced on the endpoints examined, reported as an observation rather than a Pass/Fail
reached by overwhelming the target
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

redstep does not generate exhausting load, so there is no destructive action to confine;
any probe stays within safe, bounded limits. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- CWE: [CWE-770 Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- ATT&CK: resource-exhaustion maps to [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/), which redstep does not perform; OWASP above is the mapping (ADR-0016).
