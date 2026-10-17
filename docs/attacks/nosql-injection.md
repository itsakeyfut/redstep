---
name: NoSQL Injection
slug: nosql-injection
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-943]
targets: [web, api]
capability: none
---

# NoSQL Injection

## Summary

A query to a NoSQL datastore that is built from unneutralised request input lets the
attacker change the query's structure, as SQL injection does for relational databases.
Depending on the store and driver this bypasses authentication, returns records the
query never meant to, or in some engines runs server-side JavaScript.

## Mechanism

The application places input into a query object or expression without treating it as
data, for example a MongoDB filter where a login becomes `{ user: input, pass: input }`
and the attacker sends an operator object such as `{ "$ne": null }` to match any value,
or injects into a `$where` JavaScript expression. A true injection is distinguished
from a normal query by the attacker-controlled operator or expression changing the
result set, so the witness is records returned that the intended query would have
excluded, keyed by a value present only in them.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is in-band and parallels the SQL
injection check: inject an always-true operator or expression and read a sentinel from
a record the intended query would not have returned, through the body-marker seam
(`classify_http_witness`). The payload shape is store-specific (operator injection for
document stores, expression injection where server-side JavaScript is allowed).

## What a verdict means

When implemented, a `Fail` (High) would mean the injected operator or expression
altered the query and returned the sentinel. A confident "not exploitable" would prove
only that this payload did not alter the query, not that another store's syntax would
not
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique that reads the target's own datastore; it does not
reach beyond the scoped target, so confinement rests on scope rather than egress. Scope
resolves the target by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- CWE: [CWE-943 Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
- PortSwigger Web Security Academy: [NoSQL injection](https://portswigger.net/web-security/nosql-injection)
- ATT&CK: maps coarsely to [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/); OWASP above is the sharper application-layer mapping (ADR-0016).
