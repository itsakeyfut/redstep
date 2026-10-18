---
name: Improper LLM Output Handling
slug: improper-output-handling
attack: [unmapped]
owasp: [LLM05:2025-Improper Output Handling]
cwe: [CWE-94]
targets: [ai, web]
capability: none
---

# Improper LLM Output Handling

## Summary

An application that treats a language model's output as trusted, passing it to a shell, a
database, a browser, or an eval, inherits whatever the model was steered to produce.
Because the model's output can be influenced by [prompt injection](prompt-injection.md),
unvalidated output is a path from the AI layer straight into the classic injection
vulnerabilities: XSS, SQL injection, command or code execution.

## Mechanism

The application sends the model's response to a downstream sink without validating or
encoding it for that sink: model output rendered into a page becomes XSS, output
interpolated into SQL becomes SQL injection, output passed to `exec`/`eval` becomes
command or code execution. The attacker uses prompt injection to make the model emit the
payload. It is distinguished from safe handling by the model's output taking effect in the
sink, so the witness is the downstream effect, the same witness the corresponding
injection check uses.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is the downstream injection firing
from model output: steer the model (via prompt injection) to emit a payload for a sink,
then observe that sink's effect with the existing witness, [XSS](xss.md) execution,
[SQL injection](sql-injection.md)'s marker, or a [command](command-injection.md)/[code
injection](code-injection.md) callback. It composes prompt injection with an injection
check rather than inventing a witness.

## What a verdict means

When implemented, a `Fail` (High) would mean model output reached a sink and took effect
there. A confident "not exploitable" would prove only that this output was neutralised at
the sink, not that every sink validates model output
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [ai, web]` technique whose effect lands in the scoped target's own sink inside
the lab; nothing leaves the egress-less lab
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), under membership scope
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- OWASP: [LLM05:2025 Improper Output Handling](https://owasp.org/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM05_ImproperOutputHandling)
- CWE: [CWE-94 Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html) (one of several sinks; XSS is [CWE-79](https://cwe.mitre.org/data/definitions/79.html), SQLi [CWE-89](https://cwe.mitre.org/data/definitions/89.html))
- Related: [Prompt Injection](prompt-injection.md), [XSS](xss.md), [SQL Injection](sql-injection.md), [OS Command Injection](command-injection.md), [Code Injection](code-injection.md).
