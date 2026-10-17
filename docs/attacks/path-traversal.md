---
name: Path Traversal
slug: path-traversal
attack: [T1190]
owasp: [A01:2021-Broken Access Control]
cwe: [CWE-22]
targets: [web]
capability: http_path_traversal_vantage
---

# Path Traversal

## Summary

An endpoint that builds a filesystem path from request input, without confining the
result to an intended directory, lets the attacker walk out of that directory with
`../` and read files elsewhere on the host: configuration, credentials, source, or
system files. Also called directory traversal, it turns a file-serving endpoint
into arbitrary file read.

## Mechanism

The vulnerable endpoint joins a caller-supplied name onto a base directory and opens
the result, for example serving `base + "/" + <input>`. Input such as
`../../../../etc/passwd` resolves outside the base. A true traversal is
distinguished from a missing file by the response carrying the contents of a file
that sits outside the intended directory, so the witness is a sentinel known to live
outside the web root.

## How redstep exercises it

The `http_path_traversal_vantage` capability (`exploit_path_traversal_from_vantage`)
drives the playground api's `GET /file?path=`, whose mvp build resolves the caller's
path without confining it. The witness is in-band: the probe traverses to a file
seeded outside the served directory and reads its sentinel from the response body
through the shared seam (`classify_http_witness`, `body.contains(marker)`). The
fixed build canonicalizes the resolved path and refuses one that escapes the
intended directory, so the sentinel never returns.
`path_traversal_check_flags_the_playground` proves the exploit;
`path_traversal_fix_and_replay_closes_the_loop` replays the recorded traversal
not-exploitable against the fix ([ADR-0022](../adr/0022-capture-a-success-witness-and-generate-a-pinned-replay.md)).

## What a verdict means

A `Fail` (High) means a file from outside the intended directory came back, so the
endpoint resolved a caller path without confining it; the
`path_traversal_diagnostic` names the sentinel and prescribes canonicalizing the
path and rejecting one that resolves outside the directory
([ADR-0009](../adr/0009-emit-an-executable-rustc-style-fail-diagnostic-from-the-oracle.md)).
A `Pass` (not-exploitable, High) means the sentinel did not return for this probe; a
redirect or abnormal probe is `Inconclusive`
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).
A confident "not exploitable" does NOT prove the endpoint confines paths: it proves
this one traversal string did not escape. A different encoding (URL-encoded or
double-encoded `../`, absolute paths, or backslashes) is a separate probe; covering
more than the one encoding is a tracked follow-up.

## Confinement

A `targets: [web]` technique that reads files on the scoped target's own host; it
does not reach beyond that host, so confinement rests on scope, not egress. Scope
resolves the target by membership, not a raw address
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), so the traversal
reads only inside the lab container. The file read as the witness is a planted
sentinel, not a real system file.

## References

- OWASP: [A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) (path traversal is folded into this category)
- CWE: [CWE-22 Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- PortSwigger Web Security Academy: [Path traversal](https://portswigger.net/web-security/file-path-traversal)
- ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) is the coarse umbrella; OWASP above is the sharper application-layer mapping (ADR-0016).
