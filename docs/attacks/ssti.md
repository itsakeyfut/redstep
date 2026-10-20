---
name: Server-Side Template Injection
slug: ssti
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-1336]
targets: [web]
capability: http_ssti_vantage
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

The `http_ssti_vantage` capability (`TestContext::exploit_ssti_from_vantage`) runs a
probe from the attacker vantage against the playground api's `/render?tpl=` endpoint,
whose vulnerable build renders the caller's input as the template source. The injected
`{{ flag }}` evaluates against a secret seeded into the engine's template context, and
the witness is that secret appearing in the response, read in-band through the
body-marker seam (`classify_http_witness`). The secret is never in the request, so a
server that merely reflected the input could not forge it (`validate_http_request`
refuses a marker that appears in the request path). A blind SSTI that reaches code
execution could additionally call back to the in-lab canary
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)); redstep
does not yet exercise that out-of-band variant.

## What a verdict means

A `Fail` (High) means the injected expression was evaluated by the engine, not merely
reflected: the seeded secret only reaches the response when the template was evaluated.
A confident "not exploitable" proves only that this payload's syntax did not evaluate,
not that another engine's syntax would not
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)):
the correct payload depends on which template engine is in use. An abnormal probe (one
that could not reach the endpoint) is `Low`, so it lands Inconclusive rather than a
confident "secure" (RK-002).

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
