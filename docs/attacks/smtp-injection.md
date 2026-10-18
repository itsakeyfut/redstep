---
name: IMAP/SMTP Injection
slug: smtp-injection
attack: [unmapped]
owasp: [A03:2021-Injection]
cwe: [CWE-93]
targets: [web]
capability: none
---

# IMAP/SMTP Injection

## Summary

An application that builds IMAP or SMTP commands from request input, a webmail client, a
contact form that sends mail, lets an attacker inject extra mail commands or headers by
smuggling CRLF sequences into the input. The result is sending arbitrary mail, injecting
headers (spoofing, extra recipients), or issuing mail-server commands the app never
intended.

## Mechanism

The input is placed into a mail command or header without stripping carriage-return and
line-feed, so a payload containing `\r\n` ends the intended line and starts an
attacker-controlled one (an extra `RCPT TO`, a forged header, an injected IMAP command).
It is distinguished from normal mail handling by the injected command or header taking
effect, so the witness is the extra command being acted on or the forged header appearing.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness depends on the sink: an injected
header reflected into a sent message is observable, and an extra recipient or command is
out-of-band, observed at an in-lab mail sink or canary
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)). The CRLF
smuggling it relies on is the same injection surface the HTTP request/header validation
already refuses for the probe's own requests (RK-015).

## What a verdict means

When implemented, a `Fail` (High) would mean an injected mail command or header took
effect. A confident "not exploitable" would prove only that this payload's CRLF was
neutralised
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique acting against the target's mail path within the lab; any
injected recipient or command reaches only an in-lab sink, since the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) and no mail can leave
it, under membership scope
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/); WSTG tests IMAP/SMTP injection under input validation (4.7.10).
- CWE: [CWE-93 Improper Neutralization of CRLF Sequences](https://cwe.mitre.org/data/definitions/93.html)
- Related: [HTTP Host Header Attacks](http-host-header-attacks.md) (the other CRLF/header-smuggling surface).
