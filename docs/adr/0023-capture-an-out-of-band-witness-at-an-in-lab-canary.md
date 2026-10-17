---
status: "accepted"
date: 2026-10-17
decision-makers: the author
---

# Capture an out-of-band witness at an in-lab canary

## Context and Problem Statement

The native app-security checks so far witness success in the probe's own response: a SQL-injection marker, a traversal sentinel, another user's object, all read from the body the attacker vantage fetched. Some techniques have no such in-band witness. In an SSRF the proof is that the coerced server reached a resource it should not; that request arrives somewhere else, and the server's own response to the attacker may say nothing. Reusing the body-marker seam (`classify_http_witness`, which tests `body.contains(marker)`) for such a technique would read a genuinely vulnerable target as a confident "not exploitable", the row-6 false PASS the seam doc already refuses. These techniques need a different witness channel, and the first one (SSRF, #65) needs it now.

## Decision Drivers

* The witness has to be observed where the effect lands, not in the probe's response.
* It must stay inside the egress-less lab: an attack never reaches real infrastructure (ADR-0006 layer 1), so the out-of-band resource is in-lab.
* The evidence has to attribute the finding to the coerced target, not to the observation point, or a report blames the wrong host.
* It should reuse the existing probe and evidence machinery, not fork a parallel stack.

## Considered Options

* Option 1: force every technique through the in-band body-marker seam.
* Option 2: a dedicated in-lab canary workload that records what reaches it, keyed by a per-probe token, with the witness read from its container logs and attributed to the coerced target.
* Option 3: observe the callback by sniffing the lab network rather than running a canary.

## Decision Outcome

Chosen: Option 2. A dedicated canary workload runs on the lab network and records each request it receives (the playground canary logs the request path). The check coerces the target to reach `http://<canary>/<token>` with a per-probe unique `token`, then reads the canary's container logs (the same `docker.logs` mechanism the probe capture uses) and witnesses the token. The witness is attributed to the coerced target: the evidence `target` is the target, and the canary is recorded only in the `reproduction` params (its alias and port), never as the `target` or `source`. The per-probe token distinguishes this callback from any other, and because the lab is egress-less (ADR-0006) the only way the token reaches the canary's log is the coerced in-lab target, so the witness cannot be forged from outside. This is a separate path from the body-marker seam, reusing the probe plumbing and the ADR-0004 evidence/ADR-0022 witness, not `classify_http_witness`. Future blind or out-of-band techniques (blind SQLi, XXE, blind command injection) reuse this canary-witness pattern.

### Confirmation

Built for SSRF (#65): `ssrf_exploit_from` in `orchestrator.rs` coerces the app, reads the canary logs with `read_container_logs`, and `classify_ssrf` maps a clean probe with the token seen to exploited/High and an abnormal probe to Inconclusive. The offline `ssrf_draft_attributes_the_witness_to_the_target_not_the_canary` pins the attribution (mutation: set the draft `target` to the canary alias and it fails), `classify_ssrf_reads_the_canary_and_fails_closed` pins the classifier, and `parse_ssrf_witness_round_trips_and_rejects_an_incomplete_witness` pins the witness round-trip and its fail-closed parse. The Docker-gated `ssrf_check_flags_the_playground` shows the out-of-band witness end to end, that the target's own response does not carry the token, and (RK-011) that the draft mirrors the observation and is attributed to the app; `ssrf_fix_and_replay_closes_the_loop` replays the recorded witness against the allowlisting fix and is not-exploitable, with a positive control (a direct canary hit, mutation: revert the fix and the loop fails). In-capability corroboration that the coercion actually fired (so a confident "not exploitable" is never vacuous) is deferred under ADR-0010's single-probe model and tracked as a follow-up.

### Consequences

* Good, a technique whose effect is not in the probe's response gets a faithful witness without weakening the body-marker seam into a false PASS.
* Good, the witness stays in the lab (the canary is an in-lab workload), so observing the callback does not add egress (ADR-0006 holds).
* Bad, a canary is another workload the lab stands up, and the witness is read from logs rather than a structured channel; a log-format drift would need the token match updated.
* What would reverse this: a structured out-of-band channel (a canary that exposes an attributable record API) proving cleaner than log-reading, which would refine the mechanism, not the attribute-to-the-target principle.

## Pros and Cons of the Options

### Option 1 (force the in-band seam)

* Good, one path. Bad, it reads a real out-of-band vulnerability as a confident "not exploitable" (row 6), because the witness is not in the body it inspects.

### Option 2 (in-lab canary, token, attributed to the target)

* Good, faithful out-of-band witness, in-lab, attributed to the coerced target, reusing the probe and evidence machinery. Bad, an extra workload and a log-read witness.

### Option 3 (sniff the lab network)

* Good, no canary workload. Bad, a packet capture is heavier and less portable than a workload that logs, and it has no natural per-probe token to attribute the callback.

## More Information

First built for SSRF (#65). Code: `crates/redstep/src/orchestrator.rs` (`ssrf_exploit_from`, `classify_ssrf`, `ssrf_draft`, `parse_ssrf_witness`, `replay_ssrf_probe`, `read_container_logs`), `crates/redstep/src/context.rs` (`exploit_ssrf_from_vantage`, `ssrf_diagnostic`), `playground/canary`. See ADR-0004 (the evidence record it writes), ADR-0022 (the success witness it is a kind of), ADR-0006 (the isolation that keeps the canary and the callback in-lab), ADR-0010 (the confidence model, and the deferred corroboration that the coercion fired).
