---
name: Server-Side Template Injection
slug: ssti
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-1336]
targets: [web]
capability: none
---

# Server-Side Template Injection

## Summary

An application that builds a server-side template out of user input, rather than
passing the input as data to a fixed template, lets the attacker inject template
syntax the engine then evaluates. Because template engines expose language
constructs, this usually escalates to reading server data and often to remote code
execution.

## Mechanism

The code concatenates input into the template source, for example
`render("Hello " + name)` instead of `render("Hello {{ name }}", name=name)`. The
attacker submits engine syntax such as `{{7*7}}` and sees `49`, confirming evaluation,
then reaches the engine's object model to run code. A true SSTI is distinguished from
reflected text by the template expression being evaluated, so the witness is the
result of an expression that input could not otherwise produce (a computed value, or a
marker only code execution could return).

## How redstep exercises it

Not yet implemented (`capability: none`). The natural witness is in-band: inject an
expression that evaluates to a value the request did not contain (an arithmetic result,
or a sentinel printed by a called function) and read it from the response through the
body-marker seam (`classify_http_witness`). A blind SSTI that reaches code execution
could additionally call back to the in-lab canary
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)).

## What a verdict means

When implemented, a `Fail` (High) would mean the injected expression was evaluated by
the engine, not merely reflected. A confident "not exploitable" would prove only that
this payload's syntax did not evaluate, not that another engine's syntax would not
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)):
the correct payload depends on which template engine is in use.

## Confinement

A `targets: [web]` technique that can reach code execution, so confinement is
load-bearing exactly as for command injection. Evaluation happens inside the scoped
target's container; the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) and scope is by
membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
so code that tries to reach outside the lab cannot.

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- CWE: [CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
- PortSwigger Web Security Academy: [Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- ATT&CK: maps coarsely to [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/); OWASP above is the sharper application-layer mapping (ADR-0016).
