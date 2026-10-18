---
name: Server-Side Includes Injection
slug: ssi-injection
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-97]
targets: [web]
capability: none
---

# Server-Side Includes Injection

## Summary

Server-Side Includes (SSI) are directives a web server evaluates in a page before serving
it. Where a server has SSI enabled and reflects unsanitised input into a served page, an
attacker injects an SSI directive the server then executes, which can disclose files or
run commands on the host.

## Mechanism

The attacker submits input containing an SSI directive, such as `<!--#include virtual="..."-->`
or `<!--#exec cmd="..."-->`, that is stored or reflected into a page the server parses for
SSI. If SSI is on and the input is not escaped, the server evaluates the directive. It is
distinguished from reflected text by the directive being executed, so the witness is the
directive's effect: an included file's content, or a command's output, in the response.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is in-band: inject a directive that
yields a sentinel (an included marker file, or a command printing a marker) and read it
from the response through the body-marker seam. The `#exec` case reaches command
execution, like [OS command injection](command-injection.md).

## What a verdict means

When implemented, a `Fail` (High) would mean the injected SSI directive was evaluated. A
confident "not exploitable" would prove only that this directive was not evaluated (SSI
disabled, input escaped)
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique that can reach command execution via `#exec`, so confinement
is load-bearing. It runs inside the scoped target's container; the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) and scope is by
membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/); WSTG tests SSI injection under input validation (4.7.8).
- CWE: [CWE-97 Improper Neutralization of Server-Side Includes](https://cwe.mitre.org/data/definitions/97.html)
- Related: [OS Command Injection](command-injection.md), [Server-Side Template Injection](ssti.md).
