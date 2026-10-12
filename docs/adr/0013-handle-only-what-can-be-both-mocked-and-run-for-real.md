---
status: "accepted"
date: 2026-10-12
decision-makers: the author
---

# Handle only what can be both mocked and run for real, with two backends per workload

## Context and Problem Statement

What platforms does redstep target, and how are real environments and mocks handled? This is the first decision on the project's ultimate reach rather than the MVP scope.

## Decision Drivers

* The project's core principle: handle only what can be both mocked (cheap, safe, CI) and run for real (near-production final check).
* Hardware-dependent targets that cannot be mocked do not fit and are declared non-goals honestly.
* It rides on the ADR-0003 workload abstraction.

## Considered Options

* Option 1: real environments only.
* Option 2: mocks only.
* Option 3: both, a mock and a real backend per workload kind, selected at run time, behind an Environment Provider abstraction.

## Decision Outcome

Chosen: Option 3, with an explicit reach. In scope: Linux containers; Windows/Active Directory (real VMs); cloud (real AWS/Azure/GCP); Kubernetes/infra/IaC. Non-goal, declared: wireless (WiFi/aircrack) and physical attacks, because they are hardware-dependent, un-mockable, and real-hardware-only, which violates the core principle; VPN cracking is kept but reframed as a network-layer IPsec/IKE weakness (weak PSK, leaked key, misconfig), not wireless. Each workload kind has a real backend and a mock backend (cloud real vs LocalStack/moto, Windows/AD real VM vs light simulation, k8s real vs kind/k3d, Linux container vs real VM), selectable at run time. All of this is Phase 4 (M4); the MVP is Linux containers only.

### Confirmation

Nothing yet. The Environment Provider abstraction and the mock/real backends are M4. When built, the ADR names the guard (that the same test passes on both backends). The wireless non-goal is held by its absence, which this record states.

### Consequences

* Good, the mock/real split keeps CI cheap and safe while allowing a near-production check, and the un-mockable is honestly excluded rather than half-supported.
* Bad, the Environment Provider abstraction is undesigned (its shape waits for a second backend to validate it, so building it now would be an interface with no caller).
* What would reverse this: a reason to take on wireless (it breaks the mock-and-real principle) or to drop the mock tier (it is what keeps CI safe).

## Pros and Cons of the Options

### Option 1 (real only)

* Good, faithful. Bad, no cheap safe CI path.

### Option 2 (mock only)

* Good, cheap. Bad, no near-production check.

### Option 3 (both, provider abstraction)

* Good, cheap CI and a real check, and a principle that excludes the un-mockable. Bad, the abstraction is deferred design.

## More Information

Was "Decision M" in the retired `design-decisions.md`. Open: the Environment Provider design, the Windows/AD light simulation, VM orchestration (Hyper-V/QEMU/libvirt), cloud-mock gaps. See ADR-0003 (the workload abstraction) and ADR-0006 (the safety model the mock tier serves).
