# Roadmap

One file per version under this directory holds that release's goal, scope, release criteria, and attack coverage (named `v-<major>-<minor>-<patch>.md`). This file is the index over them.

How the releases work:

- Each release is a substantial, coherent feature theme; the 0.x series is long by design.
- The versions below are the planned major, theme-introducing milestones, in order. The version numbers are the current plan, indicative rather than fixed: broadening and hardening releases (more catalog coverage, reliability, polish) fill in between and after them and take intermediate numbers, so a later theme may shift to a higher number. When that happens the file is renamed and this table updated.
- `v1.0.0` is a maturity gate, not the successor of the last themed release: it is reached when its criteria are met (a real adoption example, mature governance, a safe supply chain), likely several releases after the last theme listed here.
- Each version's scope is in its own file, linked below. The [attack catalog](../attacks/README.md) is the backlog each release draws a target set from; a technique not yet targeted stays `capability: none` there. What the MVP is, and the criteria for deciding whether to continue the project, are in [mvp.md](./mvp.md).

| Version | Theme | Status |
|---|---|---|
| [v0.1.0](./v-0-1-0.md) | Attack-to-prevention vertical slice | released |
| [v0.2.0](./v-0-2-0.md) | Native Web/API security checks | in progress |
| [v0.3.0](./v-0-3-0.md) | Network boundaries and post-breach reach | planned |
| [v0.4.0](./v-0-4-0.md) | Real offensive tooling | planned |
| [v0.5.0](./v-0-5-0.md) | Multi-step attacks and pivoting | planned |
| [v0.6.0](./v-0-6-0.md) | Reporting and visualization | planned |
| [v0.7.0](./v-0-7-0.md) | Declarative attack scenarios (DSL) | planned |
| [v0.8.0](./v-0-8-0.md) | Platform expansion (cloud, Kubernetes, IaC) | planned |
| [v0.9.0](./v-0-9-0.md) | Windows, Active Directory, and tool interop | planned |
| [v0.10.0](./v-0-10-0.md) | AI-driven testing and adversary emulation | planned |
| [v1.0.0](./v-1-0-0.md) | Production-ready | planned |

Between and after the themed milestones, broadening and hardening releases (v0.11.0 and on) build out the remaining in-scope catalog coverage and the reliability work; they are defined as they are approached, drawing their target set from the attack catalog. Cross-cutting work runs continuously across every release rather than in one of them: the risk-tier distribution governance and legal review (`ADR-0021`), the attack-data packs and attacker-image maintenance (`ADR-0018`, `ADR-0019`), and responsible disclosure.
