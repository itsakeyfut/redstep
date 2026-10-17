---
name: GraphQL API Vulnerabilities
slug: graphql-api-vulnerabilities
attack: [unmapped]
owasp: []
cwe: [CWE-200]
targets: [api]
capability: none
---

# GraphQL API Vulnerabilities

## Summary

GraphQL lets a client ask for exactly the fields it wants across a typed schema, and
that flexibility is its own attack surface: introspection can hand over the whole
schema, aliased or batched queries multiply work and bypass limits, and authorization
is easy to apply inconsistently across resolvers, so a field one query guards leaks
through another.

## Mechanism

Common issues: introspection left enabled, so a single query returns every type and
field; object- and field-level authorization applied per resolver inconsistently, so a
guarded datum is reachable by an unguarded path (IDOR and privilege escalation expressed
over GraphQL fields); aliasing and batching to multiply an operation or evade a
per-request limit; and injection through resolver arguments. A true issue is
distinguished by the schema or guarded data being reached through a GraphQL-specific
path, so the witness is introspection returning the schema, or a guarded field returning
via an unguarded query.

## How redstep exercises it

Not yet implemented (`capability: none`). The introspection case has an in-band witness
(the schema returned, read by the body-marker seam); the access-control cases reduce to
[IDOR](idor.md) and [privilege escalation](privilege-escalation.md) over GraphQL fields
and would reuse those witnesses; the resource-multiplication cases overlap
[unrestricted resource consumption](unrestricted-resource-consumption.md) and are out of
the no-DoS scope.

## What a verdict means

When implemented, a `Fail` (High) would mean a GraphQL-specific exposure was confirmed:
the schema via introspection, or a field reached past its authorization. A confident
"not exploitable" would prove only the specific query tried, not that every resolver's
authorization is consistent
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [api]` technique acting within the scoped target; it reaches nothing beyond
it. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- CWE: [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- PortSwigger Web Security Academy: [GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql)
- OWASP: [API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) covers the authorization and consumption facets; no single distinct category. ATT&CK unmapped (ADR-0016).
