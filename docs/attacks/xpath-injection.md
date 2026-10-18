---
name: XPath Injection
slug: xpath-injection
attack: [unmapped]
owasp: [A03:2021-Injection]
cwe: [CWE-643]
targets: [web, api]
capability: none
---

# XPath Injection

## Summary

An application that builds an XPath query over an XML document from unsanitised input lets
an attacker change the query, as SQL injection does for a database. The common payoff is
authentication bypass or reading nodes the query was never meant to return, wherever XML
is used as a data store.

## Mechanism

Input is concatenated into an XPath expression, for example a login that checks
`//user[name='INPUT' and pass='INPUT']`; a payload such as `' or '1'='1` makes the
predicate always true. Blind XPath injection infers the document one node or character at
a time from true/false responses. It is distinguished from a normal query by the
attacker's expression changing the node set, so the witness is nodes returned that the
intended query would have excluded.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is in-band and parallels the SQL
injection check: inject an always-true predicate and read a sentinel from a node the
intended query would not have returned, through the body-marker seam.

## What a verdict means

When implemented, a `Fail` (High) would mean the injected expression altered the query and
returned the sentinel. A confident "not exploitable" would prove only that this payload
did not alter the query
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique reading the target's own XML data; it reaches nothing
beyond the scoped target. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/); WSTG tests XPath injection under input validation (4.7.9).
- CWE: [CWE-643 Improper Neutralization of Data within XPath Expressions](https://cwe.mitre.org/data/definitions/643.html)
- Related: [SQL Injection](sql-injection.md), [NoSQL Injection](nosql-injection.md).
