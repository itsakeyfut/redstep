---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Integrate existing tools as a plugin with three role contracts

## Context and Problem Statement

How does redstep relate to existing tools (ZAP, Nuclei, InSpec, OpenVAS, nmap, sqlmap, metasploit)? It should integrate and use them rather than replace them, and it must keep a scanner (bulk discovery) separate from a security test (an active attack step the framework controls).

## Decision Drivers

* A scanner and a security test are already declared separate; one adapter contract would erase that distinction at the type level.
* Self-contained tools (ZAP, InSpec) must not run inside the framework's isolation/scope guarantees as if the framework controlled them.
* The ADR-0002 tool adapters are the Capability tier of this scheme.

## Considered Options

* Option 1: one adapter contract for every tool.
* Option 2: no plugin mechanism, each tool wired in ad hoc.
* Option 3: a plugin architecture with three role contracts.

## Decision Outcome

Chosen: Option 3. Three contracts separate the roles by type: a `CapabilityAdapter` actively executes as a scenario step (nmap, hydra, sqlmap, metasploit) through the Intensity and scope gates (ADR-0006); a `ScannerAdapter` bulk-discovers and imports findings (Trivy, Nuclei, OpenVAS) on a separate flow; an `InteropImporter` only ingests a tool's native output (ZAP JSON, InSpec, existing SARIF) with no execution control. Plugins are static (compile-time) Rust to start; dynamic loading (WASM) is deferred. Tool priority: MVP native only; Phase 4 nmap, Trivy, Nuclei; Phase 5+ hydra, sqlmap, metasploit; interop as needed.

### Confirmation

Nothing yet. No adapter contract is implemented; the tiers land in Phase 4 (nmap, the scanner tier) and Phase 5+ (the rest). When the first adapter is built, its ADR (or this one, updated) names the guard that holds the Capability/Scanner/Interop separation at the type level.

### Consequences

* Good, the scanner/test separation is held by distinct types, and self-contained tools stay outside the framework's execution guarantees where they belong.
* Bad, three contracts to maintain rather than one.
* What would reverse this: a single adapter contract proving enough (it collapses the separation the project declared).

## Pros and Cons of the Options

### Option 1 (one contract)

* Good, simplest. Bad, erases the scanner/test separation and would run self-contained tools inside the isolation guarantees unsafely.

### Option 3 (three role contracts)

* Good, the separation is type-level and self-contained tools are import-only. Bad, more surface.

## More Information

Was "Decision G" in the retired `design-decisions.md`. Open: whether `CapabilityAdapter` is the same as or contains the ADR-0002 `Capability` trait, each tier's registry, and tracking tool version/format drift. See ADR-0002 (the capability abstraction these adapters specialize).
