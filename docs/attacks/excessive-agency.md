---
name: Excessive Agency
slug: excessive-agency
attack: [unmapped]
owasp: [LLM06:2025-Excessive Agency]
cwe: [CWE-250]
targets: [ai]
capability: none
---

# Excessive Agency

## Summary

An LLM application often gives the model agency: tools, plugins, and APIs it can call to
act, not just answer. Excessive agency is granting more of that than the task needs, too
many tools, too broad permissions, or too much autonomy, so that a model steered by
[prompt injection](prompt-injection.md) can take damaging actions: delete data, send mail,
spend money, move laterally through connected systems.

## Mechanism

The harm is the combination of an influenceable model and over-broad capability. Excessive
functionality (tools beyond what is needed), excessive permissions (a tool that can do
more than the use case requires), or excessive autonomy (actions taken without
confirmation) each widen what an injection can reach. The attacker injects an instruction
that invokes a tool to the limit of its permission. It is distinguished from intended use
by the model performing a consequential action it was steered to, so the witness is that
action taking effect.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is a consequential tool action the
model was steered to take: the probe uses [prompt injection](prompt-injection.md) to make
the model invoke an in-lab tool with an observable effect (a sentinel written, a request
to the in-lab canary, [ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)),
and witnesses that effect. It composes prompt injection with the agency the app granted.

## What a verdict means

When implemented, a `Fail` (High) would mean the model was steered into a consequential
action its agency allowed. A confident "not exploitable" would prove only that this
injection did not reach a damaging action, not that the granted agency is minimal
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [ai]` technique whose tool actions are confined to in-lab tools and sinks;
the egress-less lab ([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md))
keeps any action the model is steered to take inside the lab, under membership scope
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).
This is where the catalog's own warning bites hardest: an agent with real-world tools is
exactly the thing the isolation model must keep inside the lab.

## References

- OWASP: [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- CWE: [CWE-250 Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- Related: [Prompt Injection](prompt-injection.md), [Improper LLM Output Handling](improper-output-handling.md).
