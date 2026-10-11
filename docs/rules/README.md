# Development Rules

The conventions to follow when writing and reviewing code in redstep. These are
referenced during implementation (`/impl`) and review (`/review`); `CLAUDE.md` is
the short charter, and these are the detail behind it.

| File | Contents |
|---|---|
| [security.md](./security.md) | **Read first.** Isolation, scope, intensity, secret handling, untrusted input, tool invocation, verdict honesty, evidence integrity, supply chain |
| [design.md](./design.md) | The role tiers, layering, type placement, the invariants the architecture rests on |
| [rust.md](./rust.md) | Formatting, naming, module layout, concurrency, code quality |
| [error-handling.md](./error-handling.md) | Error-type design, `Result` vs panic, `thiserror`, never leaking secrets |
| [logging.md](./logging.md) | Log levels, message format, redaction of sensitive data |
| [test.md](./test.md) | Behaviour tests, mutation guards, layers, discovery vs replay, fixtures |
| [unsafe.md](./unsafe.md) | When `unsafe` is allowed, isolation, SAFETY comments |
| [perf.md](./perf.md) | Where the cost actually is, bounded concurrency, streaming tool output |

The settled reasoning lives in [`../specs/design-decisions.md`](../specs/design-decisions.md)
(decisions A-V, MVP); the tooling landscape in
[`../research/attack-tooling-survey.md`](../research/attack-tooling-survey.md); the
plan in [`../roadmap/`](../roadmap/). A rule here says *how to keep the code
aligned* with a decision; it does not restate the decision's rationale.

Because redstep is a security tool, **[security.md](./security.md) outranks the
rest**: where a convention here would weaken isolation, scope, or secret handling,
security.md wins and the other rule bends.
