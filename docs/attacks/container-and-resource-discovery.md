---
name: Container and Resource Discovery
slug: container-and-resource-discovery
attack: [T1613]
owasp: []
cwe: []
targets: [container]
capability: none
---

# Container and Resource Discovery

## Summary

Once an attacker has a foothold in a container or an orchestrator, they enumerate the
environment: which containers and images exist, which pods and nodes, what secrets and
config are mounted, and which network services are reachable. It is the container-world
map that tells the attacker where to move and what to escalate.

## Mechanism

The attacker fingerprints the environment, reading `/proc`, mounted service-account
tokens, and environment variables, and queries any reachable control plane (the Docker
API, the Kubernetes API, kubelets) to list resources. Tools like `masscan` locate
kubelets; a mounted token enumerates the cluster. It is reconnaissance rather than
exploitation, so its witness is the inventory produced, not a changed state.

## How redstep exercises it

Not yet implemented (`capability: none`), and lab-modelable: from a foothold workload the
check would enumerate the lab's containers, mounts, and reachable services, and the
witness is the inventory, checked against what the lab is expected to expose. It is the
container counterpart of [network service discovery](network-service-discovery.md) and,
like it, produces an inventory rather than a verdict.

## What a verdict means

Discovery does not itself decide an exploit verdict: it yields an inventory that later
techniques act on. Reported as an observation unless paired with a check that something,
a secret mount, a reachable control plane, should not have been visible from that
foothold
([ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md)).

## Confinement

A `targets: [container]` technique enumerating only within the lab; the egress-less
network ([ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md)) and
membership scope
([ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md))
keep discovery inside the declared scope.

## References

- ATT&CK: [T1613 Container and Resource Discovery](https://attack.mitre.org/techniques/T1613/)
- Related: [Network Service Discovery](network-service-discovery.md), the network-layer counterpart.
- OWASP: no application-layer category (ADR-0016 allows unmapped).
