---
name: Prompt Injection
slug: prompt-injection
attack: [unmapped]
owasp: [LLM01:2025-Prompt Injection]
cwe: []
targets: [ai]
capability: none
---

# Prompt Injection

## Summary

An application built on a large language model mixes its own instructions with text from
users and other sources in a single prompt. Prompt injection is supplying text that the
model reads as instructions rather than data, so the attacker overrides the application's
intent: leak the system prompt, ignore safety rules, call tools the user should not reach,
or act on content the attacker planted. It is the defining LLM vulnerability, the
injection class of the AI layer.

## Mechanism

Because the model has no reliable boundary between trusted instructions and untrusted
input, text that looks like a command ("ignore previous instructions and ...") can steer
it. Direct injection comes from the user's own input; indirect injection comes from
content the model ingests, a web page, a document, a retrieved record, carrying hidden
instructions the model obeys when it processes them. It is distinguished from normal use
by the model following attacker text as instruction, so the witness is the model doing
what the injected text said rather than the application's task.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is the model performing an injected
instruction: the probe sends input (direct) or plants it in a source the app ingests
(indirect) that directs the model to emit a sentinel or take an observable action, and
reads the sentinel from the response (in-band) or the action at an in-lab sink or canary
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)). It is the
AI-layer analogue of the injection checks.

## What a verdict means

When implemented, a `Fail` (High) would mean the model followed the injected instruction.
A confident "not exploitable" would prove only that this payload did not steer the model,
not that no phrasing or indirect source does, which is weaker than for deterministic
injection because model behaviour varies between runs
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [ai]` technique acting on the scoped LLM-integrated app within the lab. Scope
is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), so any tool the model
is steered to call, or source it ingests, is itself in-lab.

## References

- OWASP: [LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) (OWASP Top 10 for LLM Applications)
- Related: [Improper LLM Output Handling](improper-output-handling.md), [System Prompt Leakage](system-prompt-leakage.md), [Excessive Agency](excessive-agency.md).
- ATT&CK: not in the enterprise matrix; see MITRE ATLAS for adversarial-ML tactics (ADR-0016 allows unmapped).
