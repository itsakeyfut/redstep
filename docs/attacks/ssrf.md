---
name: Server-Side Request Forgery
slug: ssrf
status: implemented
attack: [T1190, T1552.005]
owasp: [A10:2021-SSRF]
cwe: [CWE-918]
targets: [web, cloud]
capability: http_ssrf_vantage
---

# Server-Side Request Forgery

## Summary

A server that fetches a URL chosen by request input can be made to fetch a URL the
attacker names instead. The attacker then reaches resources the server can reach
but they cannot: an internal service, an admin endpoint behind the perimeter, or
the cloud instance metadata endpoint that hands out credentials. The server is the
confused deputy; its network position, not the attacker's, decides what the request
reaches.

## Mechanism

The vulnerable endpoint takes a URL as input and performs the request server-side,
for example an image proxy, a webhook validator, or a link preview. The attack
replaces the expected URL with one pointing at a host the server should never fetch
on a caller's behalf: `http://169.254.169.254/latest/meta-data/` on a cloud host,
`http://localhost:<admin-port>/`, or an internal hostname. A true SSRF is
distinguished from a harmless reflected URL by the request actually leaving the
server toward the attacker's chosen host; the server's own response to the attacker
often says nothing, which is why the witness cannot be read there.

## How redstep exercises it

The `http_ssrf_vantage` capability (`exploit_ssrf_from_vantage`) drives the
playground api's `GET /fetch?url=`, which fetches the caller-supplied URL
server-side. Because the proof is out-of-band, redstep coerces the app to fetch
`http://<canary>/<token>` with a per-probe token and witnesses the token in the
logs of an in-lab canary workload, not in the app's own response
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)); the
canary is the lab equivalent of an OAST/Collaborator listener. The vulnerable mvp
build fetches any URL; the fixed build allowlists the permitted hosts and answers
without fetching, so the canary is never reached. `ssrf_check_flags_the_playground`
proves the exploit end to end and that the body alone would not show it;
`ssrf_fix_and_replay_closes_the_loop` records the coercion and replays it
not-exploitable against the fix ([ADR-0022](../adr/0022-capture-a-success-witness-and-generate-a-pinned-replay.md)),
with a positive control that the canary still records a direct hit.

## What a verdict means

A `Fail` (High) means the per-probe token reached the canary, so the app was
coerced into the request; the `ssrf_diagnostic` names the internal host reached and
prescribes an outbound allowlist that refuses internal or private targets
([ADR-0009](../adr/0009-emit-an-executable-rustc-style-fail-diagnostic-from-the-oracle.md)).
A `Pass` (not-exploitable, High) means this coercion did not reach the canary; a
followed redirect or an abnormal probe is `Inconclusive`
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).
A confident "not exploitable" does NOT prove the app is safe: a coercion that never
fired (the app erred before fetching, or ignored the URL) also reaches the canary
with nothing, so it must be read alongside a positive control that `/fetch` is live
and the canary records. Corroborating that the coercion fired, inside the
capability, is a deferred follow-up.

## Confinement

This is a `targets: [web, cloud]` technique whose whole point is reaching another
host, so confinement is load-bearing. The lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md) layer 1): the
coerced fetch can reach only in-lab workloads, so even a crafted URL cannot leave
the lab toward real infrastructure, and the canary that observes the callback is
itself an in-lab workload. Scope resolves the app by membership, not a raw address
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
so a replay cannot aim the probe outside the declared scope.

## References

- OWASP: [A10:2021 Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- CWE: [CWE-918 Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- PortSwigger Web Security Academy: [SSRF](https://portswigger.net/web-security/ssrf)
- ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) is the coarse umbrella, and the cloud-metadata pivot maps to [T1552.005 Unsecured Credentials: Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/); OWASP above is the sharper application-layer mapping (ADR-0016).
