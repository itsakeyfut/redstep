---
name: Prototype Pollution
slug: prototype-pollution
attack: [unmapped]
owasp: []
cwe: [CWE-1321]
targets: [web]
capability: none
---

# Prototype Pollution

## Summary

In JavaScript every object inherits from a shared prototype. Prototype pollution is an
attacker setting properties on that shared prototype through crafted keys, so a property
they chose appears on every object. Downstream code that reads the property as trusted
then behaves as the attacker intended: a privilege flag flipped, a check subverted, or,
chained with a gadget, cross-site scripting or, on Node, remote code execution.

## Mechanism

A recursive merge, clone, or query-string parse copies attacker-controlled keys into
object properties without blocking `__proto__` or `constructor.prototype`, so those keys
reach `Object.prototype`. Later code that looks up a property and finds the polluted
value acts on it. A true pollution is distinguished from a contained assignment by a
property appearing on objects that never set it, so the witness is that downstream
effect, not the assignment itself.

## How redstep exercises it

Not yet implemented (`capability: none`). Client-side pollution needs a browser to
witness the gadget's effect, so it would use an in-lab headless browser like
[XSS](xss.md); server-side (Node) pollution can show an in-band effect, a flag the
polluted property enables appearing in a response. The witness is the effect of the
pollution, reached through whichever side the vulnerable code runs on.

## What a verdict means

When implemented, a `Fail` (High) would mean a property the attacker injected onto the
prototype changed behaviour. A confident "not exploitable" would prove only that this
payload did not pollute through the sink tried, not that no merge or parse is vulnerable
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique whose effect is in a browser or a Node process the lab
runs; it reaches nothing beyond the lab. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- CWE: [CWE-1321 Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)](https://cwe.mitre.org/data/definitions/1321.html)
- PortSwigger Web Security Academy: [Prototype pollution](https://portswigger.net/web-security/prototype-pollution)
- OWASP: no distinct Top 10 category; ATT&CK unmapped (ADR-0016).
