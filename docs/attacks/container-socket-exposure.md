---
name: Container Runtime Socket Exposure
slug: container-socket-exposure
attack: [T1609, T1610]
owasp: []
cwe: [CWE-668]
targets: [container]
capability: none
---

# Container Runtime Socket Exposure

## Summary

The container runtime's control plane, the Docker daemon socket, the Kubernetes API
server, the kubelet, can create, administer, and run commands in containers. When a
container (or a reachable network position) can talk to that control plane, it can deploy
a privileged container or run commands on any container, which is host takeover by
another name.

## Mechanism

The classic case is `/var/run/docker.sock` bind-mounted into a container: anything in the
container can now ask the daemon to run a new container with the host filesystem mounted
and escape. The same holds for an exposed, unauthenticated Docker API over TCP, a
reachable Kubernetes API server, or an open kubelet. The attacker uses the control plane
as intended, to deploy and administer containers, but from a position that should not
have it. It is distinguished from legitimate orchestration by the control plane being
driven from inside a workload or an untrusted network position, so the witness is a
container deployed or a command run through it.

## How redstep exercises it

Not yet implemented (`capability: none`), and lab-modelable since redstep drives Docker:
a check would expose a runtime socket to a workload and witness it deploying a container
or running a host command through the daemon (a sentinel only that access could produce).
ATT&CK splits the control-plane use into running commands (T1609) and deploying
containers (T1610); both start from the same exposed socket.

## What a verdict means

When implemented, a `Fail` (High) would mean a workload reached the runtime control plane
and used it. A confident "not exploitable" would mean the socket was not mounted or the
API required authentication
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [container]` technique that leads to host takeover, so it is the same
off-scale concern as [escape to host](container-escape-to-host.md) and is confined the
same way: the target workload runs in the egress-less lab
([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) with its boundary
self-checked
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md)),
and redstep never mounts its own host's runtime socket into a workload.

## References

- ATT&CK: [T1609 Container Administration Command](https://attack.mitre.org/techniques/T1609/) and [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610/)
- CWE: [CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)
- Related: [Container Escape to Host](container-escape-to-host.md), the usual goal once the socket is reached.
