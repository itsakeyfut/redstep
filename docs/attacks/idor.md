---
name: Insecure Direct Object Reference
slug: idor
attack: [T1190]
owasp: [A01:2021-Broken Access Control]
cwe: [CWE-639]
targets: [web]
capability: http_idor_vantage
---

# Insecure Direct Object Reference

## Summary

An endpoint that serves an object by an id taken from the request, without checking
that the object belongs to the caller, lets one user read another user's data by
changing the id. It is the common shape of broken access control: the identity is
known, the object reference is honoured, and the authorization step between them is
simply missing.

## Mechanism

The vulnerable endpoint resolves an object directly from a caller-supplied
reference, for example `GET /object?id=2`, and returns it after authenticating the
caller but without confirming ownership. The attacker, authenticated as one user,
increments or guesses the id and receives an object that belongs to another. A true
IDOR is distinguished from a lookalike by another user's data actually coming back,
so the witness is a value that exists only in a different user's object.

## How redstep exercises it

The `http_idor_vantage` capability (`exploit_idor_from_vantage`) drives the
playground api's `GET /object?id=`, carrying the caller's identity in a request
header the seam threads through. The witness is in-band: as one seeded user the
probe requests another user's object and reads `REDSTEP_IDOR_WITNESS_9C2E`, a value
present only in that other user's row, from the response body. The mvp build serves
any id with no ownership check; the fixed build serves the body only when the owner
is the caller and otherwise returns a safe response without another user's data.
When the cross-user read is NOT an exploit, the capability runs a same-run positive
control: the attacker also reads their OWN object, which comes back only if a read
under this identity succeeded, so a confident "not exploitable" is licensed only
when the control succeeds (`corroborate_idor`). The control probe is recorded under
a distinct capability, `http_idor_control_vantage`, so a projection that groups
evidence by capability cannot read the benign self-read as a cross-user finding; it
is corroboration, not a technique, and is not a replayable witness. When the victim
read IS an exploit, the control is skipped (it cannot change the verdict) and only
the victim finding is recorded. `idor_check_flags_the_playground` proves the
exploit; `idor_without_an_effective_identity_reads_inconclusive` proves that a
rejected identity reads Inconclusive rather than a confident PASS;
`idor_fix_and_replay_closes_the_loop` replays the cross-user read not-exploitable
against the fix
([ADR-0022](../adr/0022-capture-a-success-witness-and-generate-a-pinned-replay.md)).

## What a verdict means

A `Fail` (High) means another user's object came back, so the endpoint served by id
without an ownership check; the `idor_diagnostic` states exactly that and prescribes
an authorization check, and deliberately does NOT claim a credential was validated,
because the observation is only that another user's object was returned
([ADR-0009](../adr/0009-emit-an-executable-rustc-style-fail-diagnostic-from-the-oracle.md)).
A `Pass` (not-exploitable, High) means the other user's marker did not come back
AND the same-run own-object control succeeded (the attacker's own object came back);
a redirect or abnormal probe, or a control that did not come back, is `Inconclusive`
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).
So a confident "not exploitable" means this identity did not read that object and a
read under this identity did succeed in the same run: a target that ignores or
rejects the credential and answers a marker-less 200 fails the control and reads
Inconclusive, not a confident PASS (#71).

The control establishes that a read under this identity worked; it does NOT by
itself prove the credential was required (an endpoint that serves the own object to
anyone also passes it), nor that the victim request was not separately blocked (a
WAF or rate-limiter answering the suspicious request with a marker-less 200 would
read not-exploitable while the benign own-object read still succeeds). A stronger
corroboration, a matched negative control that reads the own object WITHOUT the
credential and confirms it is denied, is a deferred follow-up under ADR-0010's
corroboration model. So a `Pass` is scoped to this request: it does not prove access
control is correct for every object or caller.

## Confinement

A `targets: [web]` technique that reads another object within the scoped target; it
does not reach beyond it, so confinement rests on scope, not egress.
Scope resolves the target by membership, not a raw address
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)). The identity the
probe carries rides in the recorded reproduction; the seeded tokens are fixtures,
not real credentials, and the evidence store is treated as sensitive regardless.

## References

- OWASP: [A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- CWE: [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- PortSwigger Web Security Academy: [Insecure direct object references](https://portswigger.net/web-security/access-control/idor)
- ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) is the coarse umbrella; OWASP above is the sharper application-layer mapping (ADR-0016).
