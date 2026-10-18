---
name: File Inclusion (LFI and RFI)
slug: file-inclusion
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-98]
targets: [web]
capability: none
---

# File Inclusion (LFI and RFI)

## Summary

When an application chooses which file to include or execute from request input, an
attacker steers that choice. Local file inclusion (LFI) includes a file already on the
server, reading sensitive files or, where the included file is executed, running code in
it; remote file inclusion (RFI) includes a file from a URL the attacker controls, which
is straightforward remote code execution.

## Mechanism

The code builds an include/require path from input, for example `include($_GET['page'])`,
without restricting it to an allowlist. LFI points that at a local path (`../../etc/passwd`,
or a log or upload the attacker seeded with code); RFI, where remote URLs are allowed,
points it at `http://attacker/shell`. It is close to [path traversal](path-traversal.md)
but the included file is interpreted, not just read, so the witness is the included
file's code executing or its content returning, not merely a file read.

## How redstep exercises it

Not yet implemented (`capability: none`). LFI of a sentinel file has an in-band witness
(the file's content, or a marker its code prints, in the response); RFI has an out-of-band
one (the server fetches an attacker URL, reaching the in-lab canary,
[ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md), which also
overlaps [SSRF](ssrf.md)). It would read whichever through the body-marker seam or the
canary.

## What a verdict means

When implemented, a `Fail` (High) would mean a file the attacker chose was included,
executed, or fetched. A confident "not exploitable" would prove only that this payload did
not include a file, not that the include is allowlisted against every path
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [web]` technique that can reach code execution, so confinement is load-bearing.
Inclusion runs inside the scoped target's container; the lab is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) so RFI cannot fetch
real infrastructure, and scope is by membership
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/); WSTG tests file inclusion under input validation (4.7.11).
- CWE: [CWE-98 Improper Control of Filename for Include/Require Statement](https://cwe.mitre.org/data/definitions/98.html)
- PortSwigger Web Security Academy: [File path traversal](https://portswigger.net/web-security/file-path-traversal) (the local-read sibling)
- Related: [Path Traversal](path-traversal.md), [SSRF](ssrf.md).
