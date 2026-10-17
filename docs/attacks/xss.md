---
name: Cross-Site Scripting
slug: xss
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-79]
targets: [web]
capability: none
---

# Cross-Site Scripting

## Summary

Cross-site scripting (XSS) lets an attacker run their own JavaScript in another
user's browser, in the trusted context of the vulnerable site. With it they read
the victim's session, act as the victim, exfiltrate what is on the page, or rewrite
what the victim sees. It is the canonical client-side injection and one of the most
common web vulnerabilities.

## Mechanism

The site places attacker-controlled input into a page without encoding it for the
context it lands in, so the input is parsed as markup or script rather than shown as
text. It comes in three shapes: reflected (the payload rides in the request and is
echoed into the immediate response), stored (the payload is saved and later served
to other users), and DOM-based (client-side JavaScript writes attacker input into a
dangerous sink such as `innerHTML`). A true XSS is distinguished from a harmless
reflection by the injected script actually executing in the browser, so the witness
is execution (a unique callback the script fires, or a DOM effect), not the string
appearing in the response body.

## How redstep exercises it

Not yet implemented (`capability: none`). XSS executes in a browser, so its witness
is not a marker in the server's response body, and the body-marker seam
(`classify_http_witness`) cannot express it: confirming XSS needs the payload to
actually run. When built it would most resemble the out-of-band witness pattern
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)), with
an in-lab headless browser or a script-fired canary callback observing execution,
rather than reading the response.

## What a verdict means

When implemented, a `Fail` (High) would mean the injected script executed in a
browser context, not merely that the payload was reflected; a reflected-but-encoded
payload is not exploitable. A confident "not exploitable" would prove only that this
payload did not execute in the context tried, not that every sink and context on the
page is safe ([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique whose effect is in a browser the lab drives; it does not
reach beyond the lab. Scope resolves the target by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), so any browser
used to witness execution is itself an in-lab workload and the exfiltration a real
payload would attempt has nowhere outside the lab to send to.

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- CWE: [CWE-79 Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- PortSwigger Web Security Academy: [Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- ATT&CK: maps coarsely to [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/); OWASP above is the sharper application-layer mapping (ADR-0016).
