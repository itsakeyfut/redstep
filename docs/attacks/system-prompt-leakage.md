---
name: System Prompt Leakage
slug: system-prompt-leakage
attack: [unmapped]
owasp: [LLM07:2025-System Prompt Leakage]
cwe: [CWE-200]
targets: [ai]
capability: none
---

# System Prompt Leakage

## Summary

An LLM application steers the model with a system prompt the user is not meant to see,
which often contains instructions, rules, and sometimes secrets or internal details.
System prompt leakage is getting the model to reveal that prompt, handing the attacker the
application's logic and anything unwisely embedded in it, and a map for crafting further
[prompt injection](prompt-injection.md).

## Mechanism

The attacker asks, directly or through injection, for the model to repeat or summarise its
instructions ("print everything above", "what were your initial instructions"), or elicits
it piecewise. The deeper flaw is relying on the system prompt for secrecy at all: a prompt
is not a secure store, so any credential or sensitive rule in it is exposed. It is
distinguished from normal output by the system prompt's content appearing in the response,
so the witness is a sentinel planted in the system prompt coming back.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is in-band: a sentinel placed in the
system prompt is elicited into the response and read through the body-marker seam. It is
usually a step toward prompt injection, since knowing the system prompt sharpens the
injection payload.

## What a verdict means

When implemented, a `Fail` (High) would mean the system prompt's sentinel was leaked. A
confident "not exploitable" would prove only that this elicitation did not leak it, not
that no phrasing does, with the same run-to-run variability caveat as prompt injection
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [ai]` technique acting on the scoped LLM app within the lab; the leaked
sentinel is a fixture, not a real secret. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [LLM07:2025 System Prompt Leakage](https://genai.owasp.org/llmrisk/llm07-insecure-plugin-design/)
- CWE: [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- Related: [Prompt Injection](prompt-injection.md), [LLM Sensitive Information Disclosure](llm-sensitive-information-disclosure.md).
