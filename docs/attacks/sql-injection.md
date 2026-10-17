---
name: SQL Injection
slug: sql-injection
attack: [T1190]
owasp: [A03:2021-Injection]
cwe: [CWE-89]
targets: [web]
capability: http_sqli_vantage
---

# SQL Injection

## Summary

An endpoint that builds a SQL query by concatenating request input lets the
attacker change the query rather than only its data. From there they read tables
the endpoint never meant to expose, bypass authentication, or in the worst case
write data and run database functions. It is the oldest item on the injection list
and still among the most damaging, because the database usually holds everything
worth taking.

## Mechanism

The vulnerable endpoint interpolates a parameter straight into SQL, for example
`... WHERE name = '<input>'`. Input such as `' OR '1'='1` or a `UNION SELECT` turns
the single intended row into every row, or into a column the attacker chooses. A
true injection is distinguished from a reflected string by the response carrying a
value that exists only in the database and could not have come from the request, so
the witness is a known database-only sentinel appearing in the body.

## How redstep exercises it

The `http_sqli_vantage` capability (`exploit_sqli_from_vantage`) drives the
playground api's `GET /lookup`, whose mvp build concatenates the query parameter
into its SQL. The witness is in-band: the probe injects a query that exfiltrates
`REDSTEP_SQLI_WITNESS_7F3A`, a flag seeded into the `secrets` table and present
nowhere a benign request could return it, and the shared seam reads it from the
probe's own response body (`classify_http_witness`, `body.contains(marker)`). The
fixed build uses a parameterized query, so the injection becomes literal data and
the marker never returns. `sqli_check_flags_the_playground` proves the exploit;
`sqli_fix_and_replay_closes_the_loop` replays the recorded injection
not-exploitable against the fix ([ADR-0022](../adr/0022-capture-a-success-witness-and-generate-a-pinned-replay.md)).

## What a verdict means

A `Fail` (High) means the database-only marker came back, so request input altered
the SQL; the `sqli_diagnostic` names the marker and prescribes a parameterized
query ([ADR-0009](../adr/0009-emit-an-executable-rustc-style-fail-diagnostic-from-the-oracle.md)).
A `Pass` (not-exploitable, High) means the marker did not return for this probe; a
followed redirect or an abnormal probe is `Inconclusive`
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).
A confident "not exploitable" does NOT prove the endpoint is free of injection: it
proves only that this one payload did not exfiltrate the marker. A different column,
a blind or time-based variant, or another encoding is a separate probe and is out
of scope of this single in-band check.

## Confinement

A `targets: [web]` technique that reads the target's own database; it does not reach
beyond the scoped target, so confinement rests on scope rather than egress.
Scope resolves the target by membership, not a raw address
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and the lab network is egress-less
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)), so the probe and
the database it reaches stay inside the lab. The witness is a planted sentinel, not
live data, so recording it carries no real secret.

## References

- OWASP: [A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- CWE: [CWE-89 Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- PortSwigger Web Security Academy: [SQL injection](https://portswigger.net/web-security/sql-injection)
- ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) is the coarse umbrella (MITRE lists SQL injection as an example); OWASP above is the sharper application-layer mapping (ADR-0016).
