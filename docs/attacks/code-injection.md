---
name: Code Injection
slug: code-injection
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-94]
targets: [web]
capability: none
---

# Code Injection

## Summary

Code injection is getting the application to execute source code the attacker supplies in
the application's own language, typically by reaching a dynamic-evaluation construct
(`eval`, `exec`, `Function`, deserialization into code) with unsanitised input. Unlike OS
command injection, which reaches a shell, this runs in the interpreter itself, and the
result is usually full application-level code execution.

## Mechanism

The code passes request input to a language evaluator: `eval(user_input)`, a template or
expression engine, a `pickle`/`unserialize` that reconstructs callables, or a format
feature that evaluates. The attacker supplies a snippet that the interpreter runs. It is
distinguished from reflected text by the snippet being evaluated, so the witness is an
effect only execution could produce (a computed value, a marker printed, an out-of-band
callback). It overlaps [SSTI](ssti.md) (code injection through a template engine) and
[insecure deserialization](insecure-deserialization.md) (code reached through a gadget).

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is in-band where the evaluated code
returns a value (a sentinel only execution yields, read by the body-marker seam) and
out-of-band where it does not (a callback to the in-lab canary,
[ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)), the same
two shapes as command injection.

## What a verdict means

When implemented, a `Fail` (High) would mean the injected code was evaluated by the
interpreter. A confident "not exploitable" would prove only that this payload did not
evaluate, not that no evaluation sink is reachable
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique that reaches code execution, so confinement is load-bearing,
as for command injection. The code runs inside the scoped target's container; the lab is
egress-less ([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) and scope
is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- CWE: [CWE-94 Improper Control of Generation of Code (Code Injection)](https://cwe.mitre.org/data/definitions/94.html)
- Related: [OS Command Injection](command-injection.md), [Server-Side Template Injection](ssti.md), [Insecure Deserialization](insecure-deserialization.md).
