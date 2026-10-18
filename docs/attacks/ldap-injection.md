---
name: LDAP Injection
slug: ldap-injection
attack: [unmapped]
owasp: [A03:2021-Injection]
cwe: [CWE-90]
targets: [web, api]
capability: none
---

# LDAP Injection

## Summary

An application that builds an LDAP query from unsanitised input lets an attacker alter the
filter, commonly to bypass authentication or to read directory entries the query did not
intend. It is the directory-service cousin of SQL injection, and it turns up wherever an
app authenticates or looks users up against an LDAP directory.

## Mechanism

Input is placed into an LDAP search filter without escaping the filter metacharacters
(`*`, `(`, `)`, `&`, `|`). A login filter like `(&(uid=INPUT)(password=INPUT))` can be
subverted with `*` or injected clauses to match any entry, or to widen the result set. It
is distinguished from a normal lookup by the attacker's metacharacters changing which
entries match, so the witness is entries returned, or a login succeeding, that the
intended filter would not have produced.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is in-band and parallels the SQL
injection check: inject filter metacharacters and read a sentinel from an entry the
intended filter would exclude, or observe an authentication succeeding, through the
body-marker seam.

## What a verdict means

When implemented, a `Fail` (High) would mean the injected filter altered the lookup and
returned the sentinel or authenticated. A confident "not exploitable" would prove only
that this payload did not alter the filter
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web, api]` technique querying the target's own directory service, inside the
lab. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/); WSTG tests LDAP injection under input validation (4.7.6).
- CWE: [CWE-90 Improper Neutralization of Special Elements used in an LDAP Query](https://cwe.mitre.org/data/definitions/90.html)
- Related: [SQL Injection](sql-injection.md).
