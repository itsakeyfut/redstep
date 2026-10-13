# Playground: a bespoke vulnerable 3-tier target

A small, deliberately vulnerable `web -> api -> db` target for the M1
attack-to-defense demo (#47, ADR-0008). It is the real target the SQLi demo runs
against, replacing the inert `sleep` stand-ins.

- **db** — `FROM postgres:16` with a baked dev credential and a seed schema
  (`seed.sql`: a `notes` table the api queries, and a `secrets` table holding a
  witness flag reachable only by injection).
- **api** — a thin Rust service. `GET /lookup?name=` builds its SQL by string
  concatenation, so it is injectable; `GET /health` checks the seeded db.
- **web** — a thin Rust forwarder. It relays `/lookup` to the api verbatim
  (preserving the injectable parameter); `/health` reaches the api.

`web` is healthy only when `api` is, and `api` only when the seeded `db` is, so
the orchestrator's readiness gate (bring_up) waits for the whole chain before a
probe runs.

## These are attack targets, not product code

They are intentionally insecure and are excluded from the cargo workspace so the
framework's own lints never see the raw-concat query. They run only inside the
egress-less lab (every segment network is created `internal: true`). **Never push
them to a registry or deploy them.**

## Building

The orchestrator pulls images by tag and does not build them, so build the local
tags out of band:

```sh
bash playground/build.sh   # builds redstep/{db,api,web}:mvp
```

The orchestrator's `sqli_playground_is_exploitable` test (the exploitability
guard, #47 AC 1) self-skips when these tags are absent, so the gate stays green
on a runner that has not built them.

## Scope of this slice (#47)

This slice is the target plus the proof that the SQLi is exploitable. The
framework-native built-in check that detects it, its remediation diagnostic, the
fix (a parameterized `api`), and the replay loop are the check slice, issue #50.
