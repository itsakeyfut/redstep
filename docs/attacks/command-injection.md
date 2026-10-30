---
name: OS Command Injection
slug: command-injection
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-78]
targets: [web]
capability: [http_cmdi_vantage, http_blind_cmdi_vantage]
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

redstep exercises command injection over two witness channels against one dedicated
playground fixture, `redstep/cmdi` (a separate target because the other fixtures'
runtime is distroless and cannot run a shell). Its `GET /exec?cmd=` builds a shell
command from the input on the mvp build and runs it with an argument vector (no shell)
on the fixed one, so the same payload is exploitable against mvp and inert against
fixed.

The **in-band** channel, `http_cmdi_vantage` (`exploit_command_injection_from_vantage`),
is a caller over the shared HTTP witness seam, like the SQL injection check. The probe
injects `;cat` of a sentinel file the image bakes in, and the witness is that file's body
appearing in the response (read by `classify_http_witness`), which is the injected
command's OUTPUT, never the injected bytes: the seam refuses a marker that appears in the
request path, so a reflected path cannot forge it.

The **blind, out-of-band** channel, `http_blind_cmdi_vantage`
(`exploit_blind_command_injection_from_vantage`), handles the case where the endpoint runs
the command but returns no output. The probe injects a `curl` that makes the target call
back to an in-lab canary at `http://<canary>:<port>/<token>`, and the per-probe token appearing in
the canary's container logs is the witness, observed OUT-OF-BAND
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)), never in the
target's own response. It reuses the SSRF canary mechanism; the one difference from the SSRF
check is that the coercion is a command injection at `/exec`, not a URL parameter. Time-based
blind detection (a deliberate delay with no callback) is a separate, later technique.

## What a verdict means

A `Fail` (High) means an injected command executed. In-band, that witness is the baked
sentinel, which only a successful `cat` could return, coming back in the response; blind,
it is the per-probe token reaching the in-lab canary, so the target ran a command that made
an outbound request even though its response carried nothing. A `Pass` (not-exploitable,
High) means this payload did not execute: in-band, the sentinel did not come back; blind,
the token did not reach the canary. A followed redirect or an abnormal probe exit is
`Inconclusive` by channel: in-band it downgrades even with the sentinel present (a
redirected body may be another host's). Blind, a NON-redirected abnormal exit with the
token seen stays a confident `Fail` (with no redirect to follow, the canary-log token is
the target's own callback), but a FOLLOWED REDIRECT downgrades to `Inconclusive` even
with the token seen, because the probe may have followed an open redirect to the canary
itself ([#126](https://github.com/itsakeyfut/redstep/issues/126)); a token-absent
redirect/abnormal is `Inconclusive` too. A confident "not exploitable" proves only that this payload and quoting did
not break out of the command, not that every shell context is safe. The blind channel is
weaker still, and in a way the in-band channel is not: its witness is a callback the target
makes with its own tools, so a blind "not exploitable" presupposes both that the endpoint
actually ran a command and that the target has a reachable outbound HTTP client (a `curl`).
A target that is genuinely command-injectable but has no outbound client, or whose injected
command errored before the callback, produces the same "no callback" as a secure one, and
this single-probe check cannot tell them apart. So a blind "not exploitable" must be read as
"this callback did not fire", not "not injectable", and beside a positive control that the
canary records on the lab. Closing that gap in the capability (corroborating that the
coercion fired, and varying the callback tool) is the deferred ADR-0010 follow-up it shares
with SSRF, widened by the external-client dependency
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md),
[ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)).

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
