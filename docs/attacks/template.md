---
name: the technique's common name, e.g. Server-Side Request Forgery
slug: kebab-case, equal to the file name without .md, e.g. ssrf
attack: MITRE ATT&CK technique ids as a list, e.g. [T1190], or [unmapped]
owasp: app-layer OWASP ids, e.g. [A10:2021-SSRF]; empty list if none
cwe: CWE ids, e.g. [CWE-918]; empty list if none
targets: attacker-target genres as a list, e.g. [web, cloud]; from the set in README.md, and more than one is normal
capability: the redstep capability string, e.g. http_ssrf_vantage, or none
---

<!--
One attack technique per file. Copy this to docs/attacks/<slug>.md and fill it in.
Keep the slug and the section headings stable: code comments link here by path and
by heading anchor, and nothing on the code side auto-checks that direction, so a
rename silently breaks every comment that pointed at the old one. Within docs/,
docs-links.sh does check relative links, so keep the ADR links below resolving.
Delete this comment in a filled-in file.
-->

# <Name>

## Summary

One short paragraph: what the attack is, and what an attacker gains by it. Plain
enough that a reader meeting the technique here understands why it matters before
any redstep detail. This is the paragraph a code comment sends a reader to.

## Mechanism

How the vulnerability arises and the step the attacker takes, described from
real-world behaviour rather than from memory (`D-Attack-Semantics`): name a
concrete request, a source, or a real case. Say what distinguishes a true instance
from a lookalike, because that distinction is exactly what the witness below has to
catch, and getting it wrong is how a false verdict is reached.

## How redstep exercises it

The capability that drives it (the `capability` string above), or "planned" with
the roadmap line when none exists yet. How success is witnessed: an in-band marker
in the probe's own response, or an out-of-band witness at an in-lab canary
([ADR-0023](../adr/0023-capture-an-out-of-band-witness-at-an-in-lab-canary.md));
name the marker or the token. The playground vulnerability it is proven against and
the fix that closes it, and the exploit-fix-replay loop
([ADR-0022](../adr/0022-capture-a-success-witness-and-generate-a-pinned-replay.md)).
Keep this honest about what is built versus planned, so a comment that links here
does not promise what the code does not do; a `capability` of `none` says it is not
built yet.

## What a verdict means

What a Fail, a Pass (not-exploitable), and an Inconclusive each assert for this
technique, and at what confidence
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).
State plainly what a confident "not exploitable" does NOT prove: the corroboration a
reader must not assume (for example, that the probe actually reached the vulnerable
code path, rather than erroring before it). The diagnostic emitted on a Fail: its
probable cause and its remediation class
([ADR-0009](../adr/0009-emit-an-executable-rustc-style-fail-diagnostic-from-the-oracle.md)).

## Confinement

Why exercising this cannot escape the lab or its scope: the isolation layer that
holds (an egress-less network, membership-checked scope) and the specific thing that
would go wrong without it
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md),
[ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)).
For a technique whose whole point is reaching another host (SSRF, C2, lateral
movement) this section is load-bearing, not boilerplate. For a purely in-target
technique, say that plainly and briefly rather than inventing a risk.

## References

The standards this maps to (ATT&CK, OWASP, CWE) as links, and the real-world sources
the Mechanism rests on (an authoritative write-up, a notable CVE). These are what
make the file a reference a code comment can send a reader to, instead of a second,
drifting copy of what the code already says.
