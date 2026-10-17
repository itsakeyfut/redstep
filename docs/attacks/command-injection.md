---
name: OS Command Injection
slug: command-injection
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-78]
targets: [web]
capability: none
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

Not yet implemented (`capability: none`). Two witness shapes fit: for a non-blind
injection, a unique marker printed by the injected command returns in the response
and the existing body-marker seam (`classify_http_witness`) reads it; for a blind
injection, the out-of-band canary pattern
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)) has
the injected command call back to the in-lab canary. When built it would likely
carry both, like a combined in-band and out-of-band check.

## What a verdict means

When implemented, a `Fail` (High) would mean an injected command executed: a marker
it printed came back, or the canary recorded its callback. A `Pass` (not-exploitable)
would mean this payload did not execute. A confident "not exploitable" would prove
only that this payload and quoting did not break out, not that every shell context is
safe ([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

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
