---
name: OS Command Injection
slug: command-injection
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-78]
targets: [web]
capability: http_cmdi_vantage
---

# OS Command Injection

## Summary

An endpoint that passes request input into an operating-system shell command lets
the attacker inject shell metacharacters and run arbitrary commands on the host. It
is among the most severe web vulnerabilities, because it turns a single input into
full control of the server.

## Mechanism

The endpoint builds a shell command by concatenating caller input, for example
`ping <input>` or `convert <input> out.png`, and runs it through a shell. Input such
as `; id`, `| id`, or `$(id)` ends the intended command and runs the attacker's. A
blind variant returns no command output in the response and is confirmed instead by
a deliberate time delay or an out-of-band callback the injected command triggers. A
true injection is distinguished from a reflected string by an attacker-chosen command
actually executing, so the witness is that command's output, a measurable delay, or a
callback, never the payload appearing in the body.

## How redstep exercises it

Implemented in-band as `http_cmdi_vantage` (`exploit_command_injection_from_vantage`),
a caller over the shared HTTP witness seam, like the SQL injection check. The target is
a dedicated playground fixture, `redstep/cmdi`, because the other fixtures' runtime is
distroless and cannot run a shell; its `GET /exec?cmd=` builds a shell command from the
input on the mvp build and runs it with an argument vector (no shell) on the fixed one.
The probe injects `;cat` of a sentinel file the image bakes in, and the witness is that
file's body appearing in the response (read by `classify_http_witness`), which is the
injected command's OUTPUT, never the injected bytes: the seam refuses a marker that
appears in the request path, so a reflected path cannot forge it. The blind,
out-of-band variant (the injected command calls back to the in-lab canary,
[ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)) is a
follow-up, not yet built.

## What a verdict means

A `Fail` (High) means an injected command executed: the baked sentinel, which only a
successful `cat` could return, came back in the response. A `Pass` (not-exploitable,
High) means this payload did not execute. A followed redirect or an abnormal probe is
`Inconclusive`. A confident "not exploitable" proves only that this payload and quoting
did not break out of the command, not that every shell context is safe, and it does not
cover the blind case, which has no in-response output and awaits the out-of-band variant
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique that runs commands, which is exactly the capability that
would be catastrophic outside a lab, so confinement is load-bearing. The injected
command runs only inside the scoped target's own container; the lab network is
egress-less ([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), so a
command that tries to reach real infrastructure cannot, and scope resolves the target
by membership, never a raw address
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).
This is a row-off-scale concern (arbitrary execution) that the layered isolation
exists to contain.

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- CWE: [CWE-78 Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- PortSwigger Web Security Academy: [OS command injection](https://portswigger.net/web-security/os-command-injection)
- ATT&CK: the vulnerability maps coarsely to [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/); the commands it runs are Execution ([T1059](https://attack.mitre.org/techniques/T1059/)). OWASP above is the sharper application-layer mapping (ADR-0016).
