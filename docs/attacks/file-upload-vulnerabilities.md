---
name: File Upload Vulnerabilities
slug: file-upload-vulnerabilities
attack: [T1190]
owasp: []
cwe: [CWE-434]
targets: [web]
capability: none
---

# File Upload Vulnerabilities

## Summary

An upload feature that does not restrict what is uploaded, and where it is stored, lets
an attacker upload a file the server later executes or serves dangerously. The classic
outcome is a web shell: upload a script, request it, and run arbitrary code on the
server.

## Mechanism

The endpoint validates type, extension, or content weakly and stores the file somewhere
web-served and executable. The attacker uploads a script (`shell.php`), or bypasses a
check with a double extension, a spoofed content type, a null byte, or path traversal in
the filename, then requests the stored file. A true vulnerability is distinguished from
a benign upload by the uploaded file being executed or served as the attacker intended,
so the witness is the payload running or returning.

## How redstep exercises it

Not yet implemented (`capability: none`). The witness is the uploaded payload taking
effect: after the upload, requesting the stored file returns a marker the payload prints
(in-band seam) or triggers a canary callback
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md)). It
overlaps [path traversal](path-traversal.md) in the filename and code execution in the
payload.

## What a verdict means

When implemented, a `Fail` (High) would mean the uploaded file was executed or served
dangerously. A confident "not exploitable" would prove only that this payload and
bypass did not land, not that every type and path restriction holds
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique that can reach code execution, so confinement is
load-bearing. The uploaded payload runs inside the scoped target's container; the lab is
egress-less ([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) so it
cannot reach real infrastructure, and scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- CWE: [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- PortSwigger Web Security Academy: [File upload vulnerabilities](https://portswigger.net/web-security/file-upload)
- ATT&CK: maps coarsely to [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) when it yields execution; no distinct OWASP Top 10 category (ADR-0016).
