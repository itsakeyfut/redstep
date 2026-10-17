---
name: Container Escape to Host
slug: container-escape-to-host
attack: [T1611]
owasp: []
cwe: [CWE-269]
targets: [container]
capability: none
---

# Container Escape to Host

## Summary

A container is meant to confine a process to its own namespaces and a restricted view of
the kernel. Escape to host breaks that confinement: the process in the container gains
code execution or file access on the underlying host, and from there reaches every other
container on it. It is the container world's worst outcome, and the exact event
redstep's own isolation exists to prevent.

## Mechanism

The common routes all come from the container being given more than it needs. A
`--privileged` container keeps dangerous capabilities and device access and can load a
kernel module or mount host devices. A host path bind-mounted in (especially `/` or
`/var/run/docker.sock`) lets the container write host files or drive the daemon. Leftover
capabilities (`CAP_SYS_ADMIN`) enable tricks such as the cgroups `release_agent`. A
kernel vulnerability reachable from the container breaks out directly. It is distinguished
from normal container operation by code or writes landing on the host namespace, so the
witness is an effect observed outside the container, on the host.

## How redstep exercises it

Not yet implemented (`capability: none`), but squarely within the lab's medium, since
redstep drives Docker directly. A check would stand up a deliberately over-privileged
workload and witness an effect on the host side (a sentinel written where only a
successful escape could place it). This is the mirror of redstep's own guarantee: the
same mechanism it must ensure its attacks never use is the one this technique tests a
target for.

## What a verdict means

When implemented, a `Fail` (High) would mean a container reached the host namespace. A
confident "not exploitable" would mean the escape vector tried was closed (no privileged
flag, dropped capabilities, no host mount)
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [container]` technique, and the one the project treats as off its failure
scale when it happens to redstep itself: an action escaping the lab is refused, not
ranked ([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)). Testing a
target for escape runs the target's workload inside the lab, whose network is egress-less
and whose boundary is self-checked
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md));
redstep's own provisioning deliberately adds no privileged flag, host mount, or extra
capability, which the isolation-safety review guards.

## References

- ATT&CK: [T1611 Escape to Host](https://attack.mitre.org/techniques/T1611/)
- CWE: [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- OWASP: no application-layer category (ADR-0016 allows unmapped).
