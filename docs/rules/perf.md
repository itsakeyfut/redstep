# Performance Rules

## References

- [Rust Performance Book](https://nnethercote.github.io/perf-book/)

---

## Principles

- Measure before optimizing, in release (`cargo build --release`). Most of the
  wall-clock is I/O wait; a faster parse rarely moves it.
- Correctness and safety outrank speed. Never trade a scope check, an isolation
  guarantee, or a verdict's honesty for throughput.

---

## Concurrency, bounded

- The time sink is many actions each waiting on a target. Run them concurrently
  on the async runtime rather than serially, but **bound the concurrency**: a cap
  per target and an overall cap. Unbounded fan-out at a lab target is a denial of
  service against the thing under test, not a faster test (see
  [security.md](./security.md)).
- Keep blocking work off the async runtime. A child tool with a blocking API, or
  a CPU-bound parse of a large output, goes through `spawn_blocking`.

## Timeouts everywhere a target or tool is involved

- Every network action and every child-tool invocation has a timeout. A hostile
  or dead target can hang forever, and a run that hangs is worse than one that is
  wrong (CLAUDE.md row 5). A timeout produces an `Inconclusive` observation, not
  a PASS.

## Stream large output; do not buffer it whole

- A tool can emit a very large result (a full port sweep, a verbose scan). Read
  it incrementally where the adapter can, and bound the total it will accept, so
  a target cannot exhaust memory by returning forever (security.md section 5).

## Build once, reuse

- Build the environment, the HTTP client, and a tool session **once** per run and
  reuse them, rather than reconstructing per action. Tearing the environment up
  and down per capability is both slow and a teardown-correctness hazard.

---

## Benchmarks

Benchmarks are optional and not part of the gate. Add a Criterion bench only for
a path that is actually CPU-bound and on the hot path (a parser over large tool
output, the attack-graph construction over a large run). Do not benchmark code
whose time is spent waiting; profile the waiting instead.

Run benches by hand around a perf-relevant change; they do not run in CI.
