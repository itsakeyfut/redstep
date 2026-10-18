---
name: LLM Sensitive Information Disclosure
slug: llm-sensitive-information-disclosure
attack: [unmapped]
owasp: [LLM02:2025-Sensitive Information Disclosure]
cwe: [CWE-200]
targets: [ai]
capability: none
---

# LLM Sensitive Information Disclosure

## Summary

A language model can reveal sensitive information it was exposed to: data from its
training, from documents retrieved to answer a query, from another user's context, or from
the tools and systems it is connected to. The attacker coaxes the model into disclosing
what it should not, turning a helpful assistant into a leak.

## Mechanism

The model has access, through training data, a retrieval corpus, conversation history, or
connected tools, to data it should not surface to this user, and no effective filter stops
it. The attacker asks in a way that elicits it: a direct request, a role-play, or an
indirect [prompt injection](prompt-injection.md) that redirects what the model returns. It
is distinguished from normal answers by sensitive data crossing a boundary it should not,
so the witness is a sentinel planted in a restricted source coming back in the response.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is in-band: a sentinel seeded in a
source the model should not disclose to this user (another user's record in the retrieval
corpus, a restricted document) is elicited and read through the body-marker seam. It is
the AI-layer counterpart of [information disclosure](information-disclosure.md) and, for
the retrieval case, of [IDOR](idor.md) over what the model may return.

## What a verdict means

When implemented, a `Fail` (High) would mean the model disclosed the restricted sentinel.
A confident "not exploitable" would prove only that this prompt did not elicit it, not
that no prompt does, with the model-variability caveat
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [ai]` technique acting on the scoped LLM app within the lab; every restricted
source and sentinel is an in-lab fixture. Scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)).

## References

- OWASP: [LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)
- CWE: [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- Related: [Information Disclosure](information-disclosure.md), [Prompt Injection](prompt-injection.md), [IDOR](idor.md).
