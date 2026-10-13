//! Bring an [`Environment`] up as Docker networks and containers, and tear it
//! down (ADR-0003: bollard; ADR-0006 layer 1 and ADR-0011: egress-less
//! isolation).
//!
//! The environment/network layer (docs/rules/design.md section 2): this is the
//! only module that uses bollard, and it depends on the pure [`Environment`]
//! model. Each segment becomes one Docker network created `internal: true`
//! (every segment, the vantage's included), so nothing in the lab has a route to
//! the internet or to production (docs/rules/security.md section 1). Each
//! workload becomes a container attached to its segment's network *only* (never
//! the default bridge, which would re-add egress), aliased by its workload name
//! so a scope-resolved host like `db` is reachable in the lab by that name.
//!
//! The MVP realises the membership-only model (ADR-0011): a boundary is
//! separate networks with no connection between them, and a non-empty `allow` is
//! refused upstream, so no cross-segment path is wired here; the firewall
//! gateway for port-level boundaries is Phase 4 / M3.
//!
//! This unit stands the lab up, tears it down, and verifies isolation before a
//! run. It makes no test verdict. That the egress-less flag is set is checked
//! structurally (the integration test inspects it); that a declared-forbidden
//! path is blocked at the membership level is [`boundary_self_check`] (Decision
//! N step 4), which probes it behaviourally with a positive control and refuses
//! a run whose forbidden path is reachable.
//!
//! It also *executes* a capability from the attacker's vantage:
//! [`tcp_reachable_from`] runs a TCP-connect probe from a container on a lab
//! network and reuses `tcp_connect`'s classification (#27, a ADR-0002
//! refinement). That is a downward dependency on the capability layer, which the
//! design permits: capability sits below environment, so the orchestrator may
//! call its classification down. A host-run native connect is not usable here,
//! because the host has a route to every segment and so cannot observe an
//! inter-segment boundary; the attack must originate inside the lab.

use std::collections::HashMap;

use bollard::Docker;
use bollard::models::{
    ContainerCreateBody, ContainerState, ContainerStateStatusEnum, EndpointSettings,
    NetworkCreateRequest, NetworkingConfig,
};
use bollard::query_parameters::{CreateContainerOptions, RemoveContainerOptions};

use std::time::Duration;

use crate::capability::tcp_connect::{ConnectOutcome, classify_connect, connect_summary};
use crate::environment::Environment;
use crate::error::{Error, Result};
use crate::evidence::{EvidenceDraft, NodeRef, Reproduction};
use crate::intensity::Intensity;
use crate::observation::Observation;
use crate::scope::{Scope, ScopedTarget};

/// A segment's Docker network, paired with the segment it was built from so the
/// boundary self-check (and later units) can map a segment to its network
/// without reparsing the name.
#[derive(Debug, Clone)]
pub struct LabNetwork {
    segment: String,
    name: String,
}

impl LabNetwork {
    /// The segment this network stands for.
    pub fn segment(&self) -> &str {
        &self.segment
    }

    /// The Docker network name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A workload's Docker container, paired with the workload and segment it was
/// built from so the boundary self-check (and later units) can find a named
/// workload's container and its segment without reparsing the name.
#[derive(Debug, Clone)]
pub struct LabContainer {
    workload: String,
    segment: String,
    name: String,
}

impl LabContainer {
    /// The workload this container stands for.
    pub fn workload(&self) -> &str {
        &self.workload
    }

    /// The segment the workload sits in.
    pub fn segment(&self) -> &str {
        &self.segment
    }

    /// The Docker container name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A running lab: the Docker networks and containers a [`bring_up`] created.
///
/// The normal path is the explicit async [`teardown`](RunningLab::teardown).
/// `Drop` is the backstop for a forgotten teardown or a panic: it removes what
/// it can and warns, never panicking. A leaked network or container is a
/// resource leak, not a scope escape (the networks are egress-less), but
/// teardown is not optional (docs/rules/security.md section 1).
pub struct RunningLab {
    docker: Docker,
    networks: Vec<LabNetwork>,
    containers: Vec<LabContainer>,
    torn_down: bool,
}

/// A short, process-unique tag so repeated runs do not collide and teardown
/// targets exactly this run's objects. Unique within a process via the counter;
/// unlikely to collide across processes via the time and pid mix.
fn run_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "redstep-{:x}-{seq:x}",
        nanos as u64 ^ (std::process::id() as u64)
    )
}

fn lab_unavailable(err: impl std::fmt::Display) -> Error {
    Error::LabUnavailable {
        reason: err.to_string(),
    }
}

/// The network name for a segment in this run.
fn network_name(run_id: &str, segment: &str) -> String {
    format!("{run_id}-net-{segment}")
}

/// The container name for a workload in this run.
fn container_name(run_id: &str, workload: &str) -> String {
    format!("{run_id}-{workload}")
}

/// Bring `env` up: one egress-less network per segment, then each workload as a
/// container attached to its segment's network. `docker` is injected so a test
/// controls the connection. On any failure, what was already created is torn
/// down before returning, so a partial lab never leaks.
pub async fn bring_up(docker: &Docker, env: &Environment) -> Result<RunningLab> {
    let run_id = run_id();
    let mut lab = RunningLab {
        docker: docker.clone(),
        networks: Vec::new(),
        containers: Vec::new(),
        torn_down: false,
    };

    match provision(docker, env, &run_id, &mut lab).await {
        Ok(()) => Ok(lab),
        Err(e) => {
            // Tear down the partial lab before surfacing the error; report a
            // cleanup failure rather than hiding it under the original error.
            if let Err(cleanup) = remove_all(docker, &lab.containers, &lab.networks).await {
                eprintln!("redstep: cleanup after a failed bring-up also failed: {cleanup}");
            }
            lab.torn_down = true;
            Err(e)
        }
    }
}

/// Pull `image` so `create_container` finds it. The Docker API's
/// `create_container` does not pull and returns 404 for an absent image, so the
/// orchestrator pulls first. Idempotent: a present image streams quickly and
/// succeeds. The image reference is split on its last `:` into name and tag
/// (the MVP's `busybox:1.37`, `postgres:16`); a registry-with-port reference is
/// not an MVP shape.
async fn pull_image(docker: &Docker, image: &str) -> Result<()> {
    use futures_util::StreamExt;

    let (from_image, tag) = match image.rsplit_once(':') {
        Some((name, tag)) => (name.to_owned(), tag.to_owned()),
        None => (image.to_owned(), "latest".to_owned()),
    };
    let options = bollard::query_parameters::CreateImageOptionsBuilder::default()
        .from_image(&from_image)
        .tag(&tag)
        .build();
    let mut stream = docker.create_image(Some(options), None, None);
    while let Some(item) = stream.next().await {
        item.map_err(lab_unavailable)?;
    }
    Ok(())
}

async fn provision(
    docker: &Docker,
    env: &Environment,
    run_id: &str,
    lab: &mut RunningLab,
) -> Result<()> {
    // Pull each distinct workload image before any container is created.
    let mut pulled = std::collections::HashSet::new();
    for workload in env.workloads() {
        if pulled.insert(workload.image()) {
            pull_image(docker, workload.image()).await?;
        }
    }

    for segment in env.segments() {
        let name = network_name(run_id, segment.name());
        docker
            .create_network(NetworkCreateRequest {
                name: name.clone(),
                internal: Some(true),
                ..Default::default()
            })
            .await
            .map_err(lab_unavailable)?;
        lab.networks.push(LabNetwork {
            segment: segment.name().to_owned(),
            name,
        });
    }

    for workload in env.workloads() {
        let cname = container_name(run_id, workload.name());
        let net = network_name(run_id, workload.segment());
        // Attach to the segment network ONLY, via networking_config (so the
        // container is not also on the default bridge, which would re-add
        // egress), aliased by the workload name so `db` resolves in the lab.
        let endpoint = EndpointSettings {
            aliases: Some(vec![workload.name().to_owned()]),
            ..Default::default()
        };
        let endpoints = HashMap::from([(net, endpoint)]);
        docker
            .create_container(
                Some(CreateContainerOptions {
                    name: Some(cname.clone()),
                    ..Default::default()
                }),
                ContainerCreateBody {
                    image: Some(workload.image().to_owned()),
                    // Keep a stand-in alive so it is inspectable as attached.
                    cmd: Some(vec!["sleep".to_owned(), "3600".to_owned()]),
                    networking_config: Some(NetworkingConfig {
                        endpoints_config: Some(endpoints),
                    }),
                    ..Default::default()
                },
            )
            .await
            .map_err(lab_unavailable)?;
        lab.containers.push(LabContainer {
            workload: workload.name().to_owned(),
            segment: workload.segment().to_owned(),
            name: cname.clone(),
        });
        docker
            .start_container(
                &cname,
                None::<bollard::query_parameters::StartContainerOptions>,
            )
            .await
            .map_err(lab_unavailable)?;
    }

    Ok(())
}

/// Remove every listed container (forced) then every listed network, best
/// effort: keep going past a failure and return the first error, if any.
async fn remove_all(
    docker: &Docker,
    containers: &[LabContainer],
    networks: &[LabNetwork],
) -> Result<()> {
    let mut first_err: Option<Error> = None;
    for c in containers {
        if let Err(e) = docker
            .remove_container(
                c.name(),
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
        {
            first_err.get_or_insert_with(|| lab_unavailable(e));
        }
    }
    for n in networks {
        if let Err(e) = docker.remove_network(n.name()).await {
            first_err.get_or_insert_with(|| lab_unavailable(e));
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// A tiny pinned image carrying `ping` and `nc`, for the probe containers: the
/// self-check's ICMP probe and the vantage TCP-connect probe (#27). A workload
/// image like `postgres:16` may not carry either.
const PROBE_IMAGE: &str = "busybox:1.37";

/// Something that tests whether a probe placed on `network` can reach `target`
/// (a container name) by ICMP. [`DockerProber`] is the real implementation; the
/// trait is the seam a unit test fills, so the gate's decision logic is verified
/// without a Docker daemon (the behaviour of the probe itself is CI-verified).
trait Prober {
    async fn reaches(&self, network: &str, target: &str) -> Result<bool>;
}

/// Verify every declared-forbidden path is actually blocked, before any test
/// runs (ADR-0011 step 4). For each boundary (an empty `allow` means the path
/// is blocked, and a non-empty one is refused at build) and *every* workload in
/// the `to` segment, a probe in the `from` segment must fail to reach the
/// workload while a positive-control probe in the `to` segment reaches it, so a
/// broken probe cannot read as isolation.
///
/// `Ok(())` only when every declared boundary that has a `to`-workload is
/// verified blocked. A reachable forbidden path is [`Error::BoundaryViolated`];
/// a control that cannot reach, an undeterminable probe, or any probe failure is
/// [`Error::LabUnavailable`], so the run fails closed rather than proceeding on a
/// lab whose isolation is uncertain. The result is distinct from a test verdict.
///
/// This verifies *membership* isolation: reachability is ICMP to the target's
/// container name, which Docker's embedded DNS resolves only for peers on the
/// same network, so it detects a workload wrongly attached to the `from` network
/// (the MVP's all-or-nothing boundary) and needs no listener. It does not verify
/// a routed or port-level boundary: the firewall gateway (ADR-0011, Phase 4 /
/// M3) adds those and will need a TCP-to-port probe, not name-based ICMP.
///
/// The lab-wired runner gates on this before any test ([`run_in_running_lab`](crate::run_in_running_lab),
/// #28): a failure is returned as `RunError::Lab` and no test runs. A caller that
/// invokes it directly must likewise treat both error variants as hard stops,
/// never log-and-continue, and re-run the check after any late change to the lab.
pub async fn boundary_self_check(
    docker: &Docker,
    env: &Environment,
    lab: &RunningLab,
) -> Result<()> {
    pull_image(docker, PROBE_IMAGE).await?;
    check_boundaries(env, lab, &DockerProber { docker }).await
}

/// The gate's decision logic, over an injectable `prober` so it is unit-testable
/// without Docker.
async fn check_boundaries<P: Prober>(
    env: &Environment,
    lab: &RunningLab,
    prober: &P,
) -> Result<()> {
    for boundary in env.boundaries() {
        let from = boundary.from();
        let to = boundary.to();
        let from_net = segment_network(lab, from)?;
        let to_net = segment_network(lab, to)?;

        // Probe every workload in `to`, not a representative: the break this
        // exists to catch is a single workload wrongly attached to `from`, which
        // the self-check must not assume bring-up never produces.
        for target in lab.containers().iter().filter(|c| c.segment() == to) {
            // Positive control first: the target is reachable from its own
            // segment, so a later "unreachable" is a real block, not a broken
            // probe.
            if !prober.reaches(to_net, target.name()).await? {
                return Err(Error::LabUnavailable {
                    reason: format!(
                        "boundary self-check could not reach {to} workload {:?} from its own segment; \
                         the probe is untrustworthy, so isolation cannot be certified",
                        target.workload()
                    ),
                });
            }
            if prober.reaches(from_net, target.name()).await? {
                return Err(Error::BoundaryViolated {
                    from: from.to_owned(),
                    to: to.to_owned(),
                });
            }
        }
    }

    Ok(())
}

/// The Docker network name for a segment in this lab.
fn segment_network<'a>(lab: &'a RunningLab, segment: &str) -> Result<&'a str> {
    lab.networks()
        .iter()
        .find(|n| n.segment() == segment)
        .map(LabNetwork::name)
        .ok_or_else(|| Error::LabUnavailable {
            reason: format!("no network for segment {segment:?} in the running lab"),
        })
}

/// The real prober: a disposable `busybox` container that pings `target` from
/// `network`.
struct DockerProber<'a> {
    docker: &'a Docker,
}

impl Prober for DockerProber<'_> {
    async fn reaches(&self, network: &str, target: &str) -> Result<bool> {
        // Two packets within a 2s deadline: one lost packet should not read a
        // reachable target as blocked (the false-negative, row-6 direction). The
        // dominant correct case fails instantly on name resolution.
        let cmd = vec![
            "ping".to_owned(),
            "-c".to_owned(),
            "2".to_owned(),
            "-w".to_owned(),
            "2".to_owned(),
            target.to_owned(),
        ];
        // `-c 2 -w 2` exits within a few seconds; 10s of polling is ample slack
        // for container create/start/exit latency and fails closed past that.
        let state = run_probe_cmd(self.docker, network, cmd, Duration::from_secs(10)).await?;
        classify_probe(&state)
    }
}

/// Run `cmd` in a disposable busybox container on `network`, wait up to
/// `max_wait` for it to exit, and return its final state. `max_wait` is derived
/// from the probe's own deadline by the caller (the ping's `-w`, the connect's
/// `-w`), so a probe that does not exit fails closed rather than hanging. The
/// container is removed before returning, even on error. Shared by the boundary
/// self-check (ping) and the vantage reachability probe (nc). A probe dropped
/// mid-run by a cancelled future can leak an egress-less container (row 5, not a
/// scope escape); the run paths do not cancel it.
async fn run_probe_cmd(
    docker: &Docker,
    network: &str,
    cmd: Vec<String>,
    max_wait: Duration,
) -> Result<ContainerState> {
    let name = format!("{}-probe", run_id());
    let result = run_probe_to_exit(docker, &name, network, cmd, max_wait).await;
    let _ = docker
        .remove_container(
            &name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    result
}

async fn run_probe_to_exit(
    docker: &Docker,
    name: &str,
    network: &str,
    cmd: Vec<String>,
    max_wait: Duration,
) -> Result<ContainerState> {
    let endpoints = HashMap::from([(network.to_owned(), EndpointSettings::default())]);
    docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some(name.to_owned()),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some(PROBE_IMAGE.to_owned()),
                cmd: Some(cmd),
                networking_config: Some(NetworkingConfig {
                    endpoints_config: Some(endpoints),
                }),
                ..Default::default()
            },
        )
        .await
        .map_err(lab_unavailable)?;
    docker
        .start_container(
            name,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await
        .map_err(lab_unavailable)?;
    // Poll every 500ms up to `max_wait` (derived from the probe's own deadline),
    // so a stuck probe fails closed rather than hanging.
    let polls = (max_wait.as_millis() / 500).max(1) as usize;
    for _ in 0..polls {
        let info = docker
            .inspect_container(
                name,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .map_err(lab_unavailable)?;
        let state = info.state.unwrap_or_default();
        if state.running != Some(true) {
            return Ok(state);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(Error::LabUnavailable {
        reason: format!("probe {name:?} did not exit within the timeout"),
    })
}

/// A finished probe's exit code, or `Err(LabUnavailable)` if it did not cleanly
/// exit: an undeterminable probe must fail closed, never be read as a result.
fn finished_exit_code(state: &ContainerState) -> Result<i64> {
    if state.status == Some(ContainerStateStatusEnum::EXITED)
        && let Some(code) = state.exit_code
    {
        return Ok(code);
    }
    Err(Error::LabUnavailable {
        reason: format!(
            "probe exited abnormally (status {:?}, code {:?})",
            state.status, state.exit_code
        ),
    })
}

/// Read a finished ping probe as reachable (a reply, exit 0) or not (clean
/// no-reply/unresolved, busybox exit 1). Any other code is `Err(LabUnavailable)`:
/// the self-check must refuse rather than read an abnormal probe as "blocked".
fn classify_probe(state: &ContainerState) -> Result<bool> {
    match finished_exit_code(state)? {
        0 => Ok(true),
        1 => Ok(false),
        other => Err(Error::LabUnavailable {
            reason: format!(
                "boundary self-check ping probe exited with {other}; isolation cannot be certified"
            ),
        }),
    }
}

/// The busybox `nc` connect probe as argv (never a shell line): connect to
/// `host:port`, giving up after `secs`, reading nothing. Passing argv directly
/// rather than through `sh -c` means a crafted host or port is one argument to
/// `nc`, not text a shell could interpret, so it cannot inject a command into the
/// probe container. Pure, so the argv shape is unit-tested without Docker.
fn nc_cmd(host: &str, port: u16, secs: u64) -> Vec<String> {
    vec![
        "nc".to_owned(),
        "-w".to_owned(),
        secs.to_string(),
        host.to_owned(),
        port.to_string(),
    ]
}

/// Read a finished busybox `nc` connect probe as a connect outcome: exit 0 is a
/// completed connect; exit 1 is `Indeterminate`, because busybox `nc` dies with 1
/// on a refusal, a timeout, or no route without distinguishing them, so it cannot
/// surface a `Refused`. Any other code, or a probe that did not cleanly exit
/// (crashed, killed, never ran), is `Err(LabUnavailable)`: an abnormal probe must
/// fail closed, never be read as a clean "unreachable" (CLAUDE.md row 6). Taking
/// the state (not a bare code) folds the exited-cleanly check in, so the whole
/// fail-closed mapping is unit-tested without Docker.
fn nc_result(state: &ContainerState) -> Result<ConnectOutcome> {
    match finished_exit_code(state)? {
        0 => Ok(ConnectOutcome::Connected),
        1 => Ok(ConnectOutcome::Indeterminate),
        other => Err(Error::LabUnavailable {
            reason: format!(
                "vantage nc probe exited with {other}; reachability cannot be determined"
            ),
        }),
    }
}

/// Observe whether a scope-resolved `target` is reachable by TCP from the
/// attacker's vantage, running a busybox `nc` connect from a container on the
/// `vantage` network (#27). A host-run native connect is not usable: the host has
/// a route to every segment and so cannot observe an inter-segment boundary, so
/// the attack must originate inside the lab. The types are the gate: a
/// [`LabNetwork`] is only produced by `bring_up` (so the probe runs on a real,
/// egress-less lab network, not an arbitrary one like `bridge`), and a
/// [`ScopedTarget`] is only produced by the scope resolver (so the probe cannot
/// be aimed at a raw address outside scope).
///
/// The observation reuses `tcp_connect`'s classification (a completed connect is
/// reachable at `High`; a failure is unreachable at `Low`, because busybox `nc`
/// cannot prove the port closed), so the native and vantage paths agree on the
/// reachability value a connect means. The confidence still differs by path (a
/// refused port is `High` unreachable natively but `Low` from the vantage) in
/// the one way that
/// matters: a `Low` "unreachable" from a single vantage connect cannot by itself
/// certify that a boundary held (the oracle's default `High` keeps it out of a
/// confident PASS); that certification is [`boundary_self_check`]'s job, with its
/// positive control. The draft is *not* a native `tcp_connect` record: it carries
/// a distinct capability name and records the vantage network, so a reader cannot
/// mistake an in-lab vantage probe for a host-run connect. An abnormal probe is
/// `Error::LabUnavailable`, fail-closed.
///
/// The draft carries a first-class `source` (ADR-0004's `NodeRef::Vantage`) and
/// a reproduction faithful enough to replay: it records the stable vantage
/// *segment*, not the run-scoped network name, so [`replay_vantage_probe`] can
/// re-run it against a fresh lab (ADR-0022, #29). Image-digest and data-pack
/// pinning stay deferred (ADR-0019, ADR-0018), so a replay reproduces against
/// the same `Environment`, not across image drift.
pub(crate) async fn tcp_reachable_from(
    docker: &Docker,
    vantage: &LabNetwork,
    target: &ScopedTarget,
    timeout: Duration,
) -> Result<(Observation<bool>, EvidenceDraft)> {
    // Whole seconds for `nc -w`; record this applied value, not the requested
    // `timeout`, so the reproduction restates what actually ran.
    let secs = timeout.as_secs().max(1);
    let applied = Duration::from_secs(secs);
    let host = target.host();
    let port = target.port();

    let cmd = nc_cmd(host, port, secs);
    // `nc` waits up to `secs`; allow that plus container create/start/exit slack.
    let state = run_probe_cmd(
        docker,
        vantage.name(),
        cmd,
        applied + Duration::from_secs(5),
    )
    .await?;
    let outcome = nc_result(&state)?;
    let observation = classify_connect(outcome);

    let spec = format!("{host}:{port}");
    let draft = vantage_draft(
        vantage.segment(),
        spec,
        &observation,
        connect_summary(outcome),
        applied,
    );
    Ok((observation, draft))
}

/// Compose the evidence draft for a vantage probe. Pure, so the first-class
/// `source` and the witness (the stable segment, not the run-scoped network
/// name) are testable without Docker, which is why it is lifted out of
/// [`tcp_reachable_from`]. The segment appears in both `source` (ADR-0004's
/// `NodeRef`) and the reproduction params: ADR-0004 keeps the reproduction
/// self-contained, the same reason `capability` and `target` sit on both.
fn vantage_draft(
    segment: &str,
    target_spec: String,
    observation: &Observation<bool>,
    summary: &str,
    applied: Duration,
) -> EvidenceDraft {
    EvidenceDraft {
        capability: "tcp_connect_vantage",
        target: target_spec.clone(),
        intensity: Intensity::Safe,
        observed: serde_json::Value::Bool(observation.value),
        confidence: observation.confidence,
        summary: summary.to_owned(),
        source: Some(NodeRef::Vantage {
            segment: segment.to_owned(),
        }),
        reproduction: Reproduction {
            capability: "tcp_connect_vantage".to_owned(),
            target: target_spec,
            params: serde_json::json!({
                "timeout_ms": applied.as_millis() as u64,
                "vantage_segment": segment,
            }),
        },
    }
}

/// The env-independent replay inputs parsed from a vantage witness: the segment
/// to probe from, the target, and the applied timeout. Pure and Docker-free, so
/// "a witness missing a field cannot replay" is a guard that runs offline,
/// before [`replay_vantage_probe`] stands a lab up. A missing or ill-typed field
/// is `Error::InvalidTarget`, fail-closed: a witness that cannot be read cannot
/// be replayed, and that is not a silent default (ADR-0022, #29).
fn parse_vantage_witness(witness: &Reproduction) -> Result<(String, String, Duration)> {
    let invalid = |reason: &str| Error::InvalidTarget {
        spec: witness.target.clone(),
        reason: reason.to_owned(),
    };
    if witness.target.is_empty() {
        return Err(invalid("replay witness has an empty target"));
    }
    let segment = witness
        .params
        .get("vantage_segment")
        .and_then(|v| v.as_str())
        // Reject a blank or whitespace-only segment here, so the error blames the
        // witness rather than leaking to `vantage_network` as a weaker
        // "environment has no such segment".
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid("replay witness has no vantage_segment"))?;
    let timeout_ms = witness
        .params
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| invalid("replay witness has no timeout_ms"))?;
    Ok((
        segment.to_owned(),
        witness.target.clone(),
        Duration::from_millis(timeout_ms),
    ))
}

/// Replay a vantage probe from its witness against `env`: the first piece of
/// ADR-0022's pinned replay (#29). It reconstructs the exact probe the witness
/// records, brings `env` up fresh, runs it from the recorded vantage segment,
/// and returns the observation, so a caller can check it reproduces the original.
///
/// The witness is parsed before any Docker work, so a witness that cannot be
/// replayed fails closed without standing a lab up. The target is re-resolved
/// through the scope from `env` (so a replay cannot aim outside scope any more
/// than the original could), and the lab is always torn down, mirroring
/// [`run_in_lab`](crate::runner): a teardown failure warns but does not mask the
/// observation.
///
/// The guarantee is narrower than byte-reproducibility: the same observation
/// against the same `Environment`. Image-digest and data-pack pinning (ADR-0019,
/// ADR-0018) are a later milestone, so image drift in `env` is not pinned here.
/// Its only M1 caller is the replay guard; the auto-generation that calls it in
/// a codified regression (ADR-0022, ADR-0015) is deferred.
// allow(dead_code): no M1 production caller. This is the first piece of
// ADR-0022's pinned replay (#29); the codify step that calls it in a generated
// regression is deferred, and the replay guard exercises it under `cfg(test)`,
// which dead_code does not count.
#[allow(dead_code)]
pub(crate) async fn replay_vantage_probe(
    docker: &Docker,
    env: &Environment,
    witness: &Reproduction,
) -> Result<Observation<bool>> {
    let (segment, target, timeout) = parse_vantage_witness(witness)?;
    let scoped = Scope::from_environment(env).resolve(&target)?;

    let lab = bring_up(docker, env).await?;
    // Find the network, then probe; keep the result so teardown always runs,
    // mirroring run_in_lab (a teardown failure warns, it does not mask the
    // observation).
    let probed = match vantage_network(&lab, &segment) {
        Ok(net) => tcp_reachable_from(docker, net, &scoped, timeout)
            .await
            .map(|(observation, _draft)| observation),
        Err(e) => Err(e),
    };
    if let Err(e) = lab.teardown().await {
        eprintln!("redstep: teardown after a replay also failed: {e}");
    }
    probed
}

/// The lab network for `segment`, or `Error::LabUnavailable` if the environment
/// declares no such segment (fail-closed: a witness naming a segment the
/// environment does not have cannot be replayed). Pure over a built lab (no
/// Docker call), so the lookup and its fail-closed absence are testable offline.
fn vantage_network<'a>(lab: &'a RunningLab, segment: &str) -> Result<&'a LabNetwork> {
    lab.networks()
        .iter()
        .find(|n| n.segment() == segment)
        .ok_or_else(|| Error::LabUnavailable {
            reason: format!(
                "environment declares no segment {segment:?} to replay the vantage from"
            ),
        })
}

impl RunningLab {
    /// The networks this lab created, one per segment.
    pub fn networks(&self) -> &[LabNetwork] {
        &self.networks
    }

    /// The containers this lab created, one per workload.
    pub fn containers(&self) -> &[LabContainer] {
        &self.containers
    }

    /// Remove every container and network this lab created. The normal,
    /// error-surfacing teardown path.
    ///
    /// `torn_down` is set whether or not `remove_all` succeeded, but only once
    /// this future runs to completion (the assignment is after the `.await`): a
    /// teardown that *completed* is the caller's result to handle (the returned
    /// `Err`, which `run_in_lab` warns), not something the `Drop` backstop
    /// retries. The backstop fires when `teardown` did not complete: never
    /// called, or its future dropped (cancelled) before `torn_down` was set (the
    /// `Drop` impl).
    pub async fn teardown(mut self) -> Result<()> {
        let result = remove_all(&self.docker, &self.containers, &self.networks).await;
        self.torn_down = true;
        result
    }
}

impl Drop for RunningLab {
    fn drop(&mut self) {
        if self.torn_down {
            return;
        }
        // Backstop for a teardown that did not complete: never called, or its
        // future dropped mid-removal (a `?`/panic/cancel between `bring_up` and a
        // completed teardown). Not for a teardown that ran to completion and
        // failed: that error is the caller's, surfaced by `teardown`, and is not
        // retried here. Drop cannot be async, and `block_on` panics when it runs
        // on a thread that is already inside a runtime (the common case fires
        // there). So run the removal on a dedicated thread, which has no ambient
        // runtime, and join it. Best effort: warn, never panic.
        let docker = self.docker.clone();
        let containers = std::mem::take(&mut self.containers);
        let networks = std::mem::take(&mut self.networks);
        let ok = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return false;
            };
            rt.block_on(remove_all(&docker, &containers, &networks))
                .is_ok()
        })
        .join()
        .unwrap_or(false);
        if !ok {
            eprintln!(
                "redstep: lab teardown backstop could not remove every object; \
                 some Docker networks or containers may remain"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::Confidence;

    /// Guard: dropping a `RunningLab` without calling `teardown`, from inside an
    /// active tokio runtime, does not panic (the backstop runs on a dedicated
    /// thread). Mutation: replace the `std::thread::spawn(...).join()` with a
    /// direct `block_on` on a fresh runtime -> this panics with "Cannot start a
    /// runtime from within a runtime" -> the test fails. The connection is lazy
    /// and the lab is empty, so no Docker daemon is needed.
    #[test]
    fn drop_without_teardown_does_not_panic_inside_a_runtime() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("lazy connect");
            let lab = RunningLab {
                docker,
                networks: Vec::new(),
                containers: Vec::new(),
                torn_down: false,
            };
            drop(lab);
        });
    }

    use std::collections::HashSet;

    /// A prober that answers from canned sets, so the gate's decision logic is
    /// tested without Docker. `reach`ed `(network, target)` pairs resolve to
    /// reachable; `fail`ed ones return `LabUnavailable`.
    struct MockProber {
        reachable: HashSet<(String, String)>,
        fail: HashSet<(String, String)>,
    }

    impl MockProber {
        fn new() -> Self {
            Self {
                reachable: HashSet::new(),
                fail: HashSet::new(),
            }
        }
        fn reach(mut self, network: &str, target: &str) -> Self {
            self.reachable
                .insert((network.to_owned(), target.to_owned()));
            self
        }
        fn failing(mut self, network: &str, target: &str) -> Self {
            self.fail.insert((network.to_owned(), target.to_owned()));
            self
        }
    }

    impl Prober for MockProber {
        async fn reaches(&self, network: &str, target: &str) -> Result<bool> {
            let key = (network.to_owned(), target.to_owned());
            if self.fail.contains(&key) {
                return Err(Error::LabUnavailable {
                    reason: "mock probe failure".to_owned(),
                });
            }
            Ok(self.reachable.contains(&key))
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    fn net(segment: &str, name: &str) -> LabNetwork {
        LabNetwork {
            segment: segment.to_owned(),
            name: name.to_owned(),
        }
    }

    fn container(workload: &str, segment: &str, name: &str) -> LabContainer {
        LabContainer {
            workload: workload.to_owned(),
            segment: segment.to_owned(),
            name: name.to_owned(),
        }
    }

    /// A lab with the given networks and containers; `torn_down` so `Drop` is a
    /// no-op on this fabricated state. The `Docker` handle is lazy and never used
    /// by `check_boundaries`.
    fn lab(networks: Vec<LabNetwork>, containers: Vec<LabContainer>) -> RunningLab {
        RunningLab {
            docker: Docker::connect_with_local_defaults().expect("lazy connect"),
            networks,
            containers,
            torn_down: true,
        }
    }

    /// The MVP topology: internet/internal, web/api/db in internal, the
    /// internet -> internal boundary blocked.
    fn mvp_env() -> Environment {
        Environment::builder()
            .segment("internal")
            .segment("internet")
            .workload("web", "busybox:1", "internal")
            .workload("api", "busybox:1", "internal")
            .workload("db", "busybox:1", "internal")
            .vantage("internet")
            .boundary("internet", "internal", &[])
            .build()
            .expect("the MVP topology is valid")
    }

    fn mvp_lab() -> RunningLab {
        lab(
            vec![net("internal", "n-internal"), net("internet", "n-internet")],
            vec![
                container("web", "internal", "c-web"),
                container("api", "internal", "c-api"),
                container("db", "internal", "c-db"),
            ],
        )
    }

    /// A mock prober whose positive controls (from the internal network) reach
    /// every internal workload. Forbidden reachability from the internet network
    /// is added per test.
    fn controls_ok() -> MockProber {
        MockProber::new()
            .reach("n-internal", "c-web")
            .reach("n-internal", "c-api")
            .reach("n-internal", "c-db")
    }

    /// Guard: with every forbidden path blocked and controls reachable, the check
    /// passes. Mutation: negate the forbidden `reaches` test -> a blocked path
    /// reads as reachable -> BoundaryViolated -> this fails.
    #[test]
    fn check_passes_when_every_forbidden_path_is_blocked() {
        let result = block_on(check_boundaries(&mvp_env(), &mvp_lab(), &controls_ok()));
        assert!(result.is_ok(), "an isolated lab passes: {result:?}");
    }

    /// Guard: a forbidden path reachable to the FIRST workload is refused.
    #[test]
    fn check_refuses_when_the_first_workload_is_reachable() {
        let prober = controls_ok().reach("n-internet", "c-web");
        let result = block_on(check_boundaries(&mvp_env(), &mvp_lab(), &prober));
        assert!(
            matches!(&result, Err(Error::BoundaryViolated { from, to }) if from == "internet" && to == "internal"),
            "got {result:?}"
        );
    }

    /// Guard: a forbidden path reachable to a NON-first workload (db) is refused.
    /// This is the one the `.find`-first bug would miss. Mutation: probe only the
    /// first `to` workload (`.find` instead of the `.filter` loop) -> `db` is
    /// never probed, the check returns `Ok` -> this fails.
    #[test]
    fn check_refuses_when_a_non_first_workload_is_reachable() {
        let prober = controls_ok().reach("n-internet", "c-db");
        let result = block_on(check_boundaries(&mvp_env(), &mvp_lab(), &prober));
        assert!(
            matches!(&result, Err(Error::BoundaryViolated { from, to }) if from == "internet" && to == "internal"),
            "got {result:?}"
        );
    }

    /// Guard: a positive control that cannot reach its own-segment target fails
    /// closed (the probe is untrustworthy), rather than certifying isolation.
    /// Mutation: drop the control arm -> the forbidden probe runs and finds the
    /// path blocked -> `Ok` -> this fails.
    #[test]
    fn check_fails_closed_when_the_positive_control_cannot_reach() {
        // Controls reach api and db, but not web.
        let prober = MockProber::new()
            .reach("n-internal", "c-api")
            .reach("n-internal", "c-db");
        let result = block_on(check_boundaries(&mvp_env(), &mvp_lab(), &prober));
        assert!(
            matches!(&result, Err(Error::LabUnavailable { reason }) if reason.contains("untrustworthy")),
            "got {result:?}"
        );
    }

    /// Guard: a probe error propagates as a refusal (fail-closed), not swallowed.
    #[test]
    fn check_fails_closed_when_a_probe_errors() {
        let prober = controls_ok().failing("n-internet", "c-web");
        let result = block_on(check_boundaries(&mvp_env(), &mvp_lab(), &prober));
        assert!(
            matches!(&result, Err(Error::LabUnavailable { .. })),
            "got {result:?}"
        );
    }

    /// Guard: a boundary whose `to` segment has no workload is a vacuous block, so
    /// a lab with no containers passes.
    #[test]
    fn check_skips_a_boundary_with_no_workload_to_reach() {
        let empty = lab(
            vec![net("internal", "n-internal"), net("internet", "n-internet")],
            Vec::new(),
        );
        let result = block_on(check_boundaries(&mvp_env(), &empty, &controls_ok()));
        assert!(
            result.is_ok(),
            "nothing to reach is vacuously blocked: {result:?}"
        );
    }

    /// Guard: every declared boundary is checked, not just the first. A two-
    /// boundary topology with the violation on the second. Mutation: `break`
    /// after the first boundary -> the second's violation is missed -> `Ok` ->
    /// this fails.
    #[test]
    fn check_covers_every_boundary_not_just_the_first() {
        let env = Environment::builder()
            .segment("a")
            .segment("b")
            .workload("wa", "busybox:1", "a")
            .workload("wb", "busybox:1", "b")
            .vantage("a")
            .boundary("a", "b", &[])
            .boundary("b", "a", &[])
            .build()
            .expect("valid");
        let two = lab(
            vec![net("a", "n-a"), net("b", "n-b")],
            vec![container("wa", "a", "c-wa"), container("wb", "b", "c-wb")],
        );
        // Controls reach each workload on its own net; the b -> a forbidden path
        // (the second boundary) is reachable, the a -> b one is not.
        let prober = MockProber::new()
            .reach("n-b", "c-wb")
            .reach("n-a", "c-wa")
            .reach("n-b", "c-wa");
        let result = block_on(check_boundaries(&env, &two, &prober));
        assert!(
            matches!(&result, Err(Error::BoundaryViolated { from, to }) if from == "b" && to == "a"),
            "got {result:?}"
        );
    }

    /// Guard: `nc_result` reads exit 0 as a completed connect, exit 1 as
    /// indeterminate (busybox `nc` cannot surface a refusal), and any other code
    /// or an abnormal probe fails closed rather than reading as a clean
    /// "unreachable" (CLAUDE.md row 6). Mutation: the exit-1 arm to `Connected`
    /// -> an unreachable target reads as reachable -> this fails; the `other =>
    /// Err` arm to `Ok(Indeterminate)` -> a crashed probe reads as a clean
    /// not-reachable -> the Err assertion fails.
    #[test]
    fn nc_result_reads_a_finished_probe_and_fails_closed() {
        use bollard::models::ContainerStateStatusEnum::{CREATED, EXITED};
        let state = |status, code| ContainerState {
            status,
            exit_code: code,
            ..Default::default()
        };
        assert_eq!(
            nc_result(&state(Some(EXITED), Some(0))).unwrap(),
            ConnectOutcome::Connected
        );
        assert_eq!(
            nc_result(&state(Some(EXITED), Some(1))).unwrap(),
            ConnectOutcome::Indeterminate
        );
        for abnormal in [
            state(Some(EXITED), Some(137)), // crashed / OOM-killed
            state(Some(EXITED), None),      // exited without a code
            state(Some(CREATED), Some(0)),  // never ran
        ] {
            assert!(
                matches!(nc_result(&abnormal), Err(Error::LabUnavailable { .. })),
                "an abnormal probe must fail closed: {:?}",
                abnormal.status
            );
        }
    }

    /// Guard: the vantage probe command is argv run directly, never a shell line,
    /// so a crafted host or port cannot inject a command into the probe container.
    /// Mutation: build the command as `["sh", "-c", format!(...)]` -> the no-shell
    /// assertion fails; drop the host argument -> the host-is-one-argument
    /// assertion fails.
    #[test]
    fn nc_cmd_is_argv_not_a_shell_line() {
        let hostile = "db; rm -rf /";
        let cmd = nc_cmd(hostile, 5432, 2);
        assert_eq!(cmd[0], "nc", "the probe runs nc directly");
        assert!(
            !cmd.iter().any(|a| a == "sh" || a == "-c"),
            "no shell wrapper, got {cmd:?}"
        );
        assert!(
            cmd.contains(&hostile.to_owned()),
            "the host is one argument, not interpreted: {cmd:?}"
        );
        assert!(cmd.contains(&"5432".to_owned()) && cmd.contains(&"2".to_owned()));
    }

    /// Guard: `classify_probe` reads a clean ping outcome and fails closed on
    /// anything else. Mutation: change the `_ => Err` arm to `Ok(false)` -> the
    /// abnormal cases read as "blocked" -> the Err assertions fail; flip the
    /// `Some(0)`/`Some(1)` arms -> the reachable/blocked assertions fail.
    #[test]
    fn classify_probe_reads_clean_outcomes_and_fails_closed() {
        use bollard::models::ContainerStateStatusEnum::{CREATED, EXITED, RUNNING};
        let state = |status, code| ContainerState {
            status,
            exit_code: code,
            ..Default::default()
        };
        assert!(matches!(
            classify_probe(&state(Some(EXITED), Some(0))),
            Ok(true)
        ));
        assert!(matches!(
            classify_probe(&state(Some(EXITED), Some(1))),
            Ok(false)
        ));
        for abnormal in [
            state(Some(EXITED), Some(137)), // OOM-killed
            state(Some(EXITED), None),      // exited without a code
            state(Some(CREATED), Some(0)),  // never ran
            state(Some(RUNNING), Some(0)),  // not actually exited
            state(None, Some(0)),           // no status
        ] {
            assert!(
                matches!(classify_probe(&abnormal), Err(Error::LabUnavailable { .. })),
                "abnormal state must fail closed: {:?}",
                abnormal.status
            );
        }
    }

    /// The vantage executor is Linux containers (egress-less bridge networks,
    /// busybox `nc`), so its integration test needs a daemon in Linux-container
    /// mode, not merely a reachable one: a Windows-container daemon reports
    /// success for `docker info` but cannot run the probe. Skip unless `OSType`
    /// is `linux`. (Mirrors the gate in `tests/environment.rs`.)
    fn linux_docker_available() -> bool {
        std::process::Command::new("docker")
            .args(["info", "--format", "{{.OSType}}"])
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "linux")
            .unwrap_or(false)
    }

    /// Guard (Docker, Linux CI leg; self-skips without a daemon): the vantage TCP
    /// executor observes a listening target as reachable from a probe on the
    /// target's own network, and unreachable from a probe on a different,
    /// isolated network where the target's name does not even resolve, matching
    /// what the attacker's vantage would see (#27). It also checks the draft does
    /// not masquerade as a native host-run connect: the capability name marks it
    /// as a vantage probe and the reproduction records the vantage network.
    /// Mutation: in `tcp_reachable_from`, run the probe on a hard-coded network
    /// rather than the `vantage` passed -> the cross-network probe resolves and
    /// reaches the listener -> the unreachable assertion fails.
    ///
    /// It builds its own two egress-less networks and a listening busybox target
    /// rather than a full lab, because a TCP probe is meaningful only against a
    /// listener and the MVP stand-ins do not listen (the end-to-end demo with a
    /// listening db is #28). It lives in-crate, not in `tests/`, because the typed
    /// signature takes a `LabNetwork` (private fields) and a `ScopedTarget` (only
    /// the resolver builds one), neither constructible from an external crate.
    #[test]
    fn tcp_reachable_from_sees_a_listener_on_its_own_network_only() {
        if !linux_docker_available() {
            eprintln!(
                "skipping tcp_reachable_from_sees_a_listener_on_its_own_network_only: no Linux Docker daemon"
            );
            return;
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let tag = format!("redstep-vantage-{}", std::process::id());
            let net_a = format!("{tag}-a");
            let net_b = format!("{tag}-b");
            let listener = format!("{tag}-listener");
            let port = 9000u16;

            // The probe and the listener both run from PROBE_IMAGE; pull it once
            // (`run_probe_cmd`'s create path does not pull, unlike `bring_up`).
            pull_image(&docker, PROBE_IMAGE)
                .await
                .expect("pull the probe image");

            for name in [&net_a, &net_b] {
                docker
                    .create_network(NetworkCreateRequest {
                        name: name.clone(),
                        internal: Some(true),
                        ..Default::default()
                    })
                    .await
                    .expect("create network");
            }

            // A re-listening busybox target on net_a.
            docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: Some(listener.clone()),
                        ..Default::default()
                    }),
                    ContainerCreateBody {
                        image: Some(PROBE_IMAGE.to_owned()),
                        cmd: Some(vec![
                            "sh".to_owned(),
                            "-c".to_owned(),
                            format!("while true; do nc -l -p {port} >/dev/null 2>&1; done"),
                        ]),
                        networking_config: Some(NetworkingConfig {
                            endpoints_config: Some(HashMap::from([(
                                net_a.clone(),
                                EndpointSettings::default(),
                            )])),
                        }),
                        ..Default::default()
                    },
                )
                .await
                .expect("create listener");
            docker
                .start_container(
                    &listener,
                    None::<bollard::query_parameters::StartContainerOptions>,
                )
                .await
                .expect("start listener");

            let spec = format!("{listener}:{port}");
            let scope = crate::scope::Scope::builder()
                .allow(&spec)
                .expect("valid spec")
                .build();
            let target = scope.resolve(&spec).expect("in scope");

            let same_net =
                tcp_reachable_from(&docker, &net("a", &net_a), &target, Duration::from_secs(2))
                    .await;
            let cross_net =
                tcp_reachable_from(&docker, &net("b", &net_b), &target, Duration::from_secs(2))
                    .await;

            // Clean up before asserting so a failed assertion does not leak.
            let _ = docker
                .remove_container(
                    &listener,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;
            for name in [&net_a, &net_b] {
                let _ = docker.remove_network(name).await;
            }

            let (same, same_draft) = same_net.expect("same-network probe ran");
            assert!(
                same.value,
                "a listener on the probe's own network is reachable"
            );
            // The draft marks itself a vantage probe, names its source as the
            // vantage segment, and records that segment in the witness, so it is
            // not mistaken for a native host-run tcp_connect and can be replayed.
            assert_eq!(same_draft.capability, "tcp_connect_vantage");
            assert_eq!(same_draft.target, spec);
            assert_eq!(
                same_draft.source,
                Some(NodeRef::Vantage {
                    segment: "a".to_owned()
                }),
                "the draft names its source as the vantage segment"
            );
            assert_eq!(
                same_draft.reproduction.params["vantage_segment"].as_str(),
                Some("a"),
                "the reproduction records the stable segment the probe ran from"
            );
            // The evidence record must mirror the observation the probe returned,
            // not a hard-coded value: the record feeds the report, the canonical
            // JSON and the replay witness (ADR-0004), so a desynced record is a
            // faithful-looking projection of a lie. This is the only guard (on
            // the CI Docker leg) that `tcp_reachable_from` wires the real
            // observation and the real segment into the draft; `vantage_draft`'s
            // offline tests cannot see which values the caller passes it.
            assert_eq!(
                same_draft.observed,
                serde_json::Value::Bool(same.value),
                "the draft's observed mirrors the reachable observation"
            );
            assert_eq!(
                same_draft.confidence, same.confidence,
                "the draft's confidence mirrors the reachable observation"
            );

            let (cross, cross_draft) = cross_net.expect("cross-network probe ran");
            assert!(
                !cross.value,
                "a listener whose name does not resolve on a different, isolated network is not reachable from the vantage"
            );
            // The unreachable record must mirror its observation too (the decisive
            // false/Low case): without this, a draft wired to a constant `true`
            // would pass the same-net assertion above and go uncaught here.
            assert_eq!(
                cross_draft.observed,
                serde_json::Value::Bool(cross.value),
                "the draft's observed mirrors the unreachable observation"
            );
            assert_eq!(
                cross_draft.confidence, cross.confidence,
                "the draft's confidence mirrors the unreachable observation"
            );
        });
    }

    /// Guard: a vantage draft names its source as a structured `NodeRef::Vantage`
    /// and records the stable segment (not the run-scoped network name) in the
    /// witness, so a replay can reconstruct it. Pure, no Docker. Mutation: in
    /// `vantage_draft` set `source: None`, or key the witness param
    /// `vantage_network` with a run-scoped name instead of `vantage_segment` ->
    /// the literal assertion fails (the Docker path only reaches one segment, so
    /// it cannot catch a hard-coded one here).
    #[test]
    fn vantage_draft_names_its_source_and_witness() {
        let observation = Observation {
            value: true,
            confidence: Confidence::High,
        };
        let draft = vantage_draft(
            "internet",
            "db:5432".to_owned(),
            &observation,
            "reachable",
            Duration::from_millis(2_000),
        );
        assert_eq!(draft.capability, "tcp_connect_vantage");
        assert_eq!(
            draft.source,
            Some(NodeRef::Vantage {
                segment: "internet".to_owned()
            }),
            "the draft names its source as the vantage segment"
        );
        assert_eq!(
            draft.reproduction.params["vantage_segment"].as_str(),
            Some("internet"),
            "the witness records the stable segment, not the run-scoped network"
        );
        assert_eq!(draft.reproduction.params["timeout_ms"], 2_000);
    }

    /// Guard: the vantage draft mirrors the observation and the probed target
    /// rather than hard-coding them, so the recorded evidence matches what the
    /// probe actually saw. The sibling to `build_draft_mirrors_the_observation`
    /// for the vantage path. It uses the decisive unreachable/`Low` case and a
    /// distinctive summary and target, which the source/witness test above does
    /// not, so a hard-coded value cannot pass as a mirrored one. Mutation: set
    /// `observed` to a fixed `true`, `summary` to a constant, or `target` to a
    /// constant in `vantage_draft` -> this fails (the Docker path asserts the
    /// returned observation, not the draft's copy of it, so it cannot catch this).
    #[test]
    fn vantage_draft_mirrors_the_observation() {
        let observation = Observation {
            value: false,
            confidence: Confidence::Low,
        };
        let draft = vantage_draft(
            "internet",
            "db:5432".to_owned(),
            &observation,
            "unreachable",
            Duration::from_millis(2_000),
        );
        assert_eq!(draft.target, "db:5432");
        assert_eq!(draft.intensity, Intensity::Safe);
        assert_eq!(draft.observed, serde_json::Value::Bool(false));
        assert_eq!(draft.confidence, Confidence::Low);
        assert_eq!(draft.summary, "unreachable");
        assert_eq!(draft.reproduction.capability, "tcp_connect_vantage");
        assert_eq!(draft.reproduction.target, "db:5432");
    }

    /// Guard: a witness whose replay inputs cannot be read is rejected rather
    /// than replayed with a default (a witness that cannot be read cannot be
    /// replayed; ADR-0022). Covers a complete witness parsing, a missing
    /// segment, a blank/whitespace segment, a wrong-typed segment, a missing
    /// timeout, a wrong-typed timeout, and an empty target. Mutations, each
    /// caught by one of the `is_err` assertions: delete `.filter(..trim..)` ->
    /// the blank-segment case passes; replace the segment `.ok_or_else(..)?`
    /// with `.unwrap_or("")` -> the missing/wrong-typed cases pass; drop the
    /// `timeout_ms` `.ok_or_else(..)?` -> the missing/wrong-typed timeout cases
    /// pass; drop the empty-target check -> the empty-target case passes.
    #[test]
    fn parse_vantage_witness_rejects_an_incomplete_witness() {
        let complete = Reproduction {
            capability: "tcp_connect_vantage".to_owned(),
            target: "db:5432".to_owned(),
            params: serde_json::json!({ "timeout_ms": 2_000, "vantage_segment": "internet" }),
        };
        let (segment, target, timeout) =
            parse_vantage_witness(&complete).expect("a complete witness parses");
        assert_eq!(segment, "internet");
        assert_eq!(target, "db:5432");
        assert_eq!(timeout, Duration::from_millis(2_000));

        // Each of these cannot be replayed and must error, not default.
        let rejected = [
            (
                "no segment",
                serde_json::json!({ "timeout_ms": 2_000 }),
                "db:5432",
            ),
            (
                "blank segment",
                serde_json::json!({ "timeout_ms": 2_000, "vantage_segment": "   " }),
                "db:5432",
            ),
            (
                "numeric segment",
                serde_json::json!({ "timeout_ms": 2_000, "vantage_segment": 5 }),
                "db:5432",
            ),
            (
                "no timeout",
                serde_json::json!({ "vantage_segment": "internet" }),
                "db:5432",
            ),
            (
                "string timeout",
                serde_json::json!({ "timeout_ms": "2000", "vantage_segment": "internet" }),
                "db:5432",
            ),
            (
                "empty target",
                serde_json::json!({ "timeout_ms": 2_000, "vantage_segment": "internet" }),
                "",
            ),
        ];
        for (label, params, target) in rejected {
            let witness = Reproduction {
                capability: "tcp_connect_vantage".to_owned(),
                target: target.to_owned(),
                params,
            };
            assert!(
                parse_vantage_witness(&witness).is_err(),
                "a witness with {label} cannot be replayed"
            );
        }
    }

    /// Guard: the replay segment lookup returns the network for the *named*
    /// segment, not merely the first, and fails closed when the environment
    /// declares no such segment. Pure, no Docker (the fabricated lab is
    /// `torn_down`). The networks are ordered so the wanted segment is not first.
    /// Mutation: in `vantage_network`, replace the `find` with `networks().first()`
    /// -> the `"internet"` lookup returns the `"internal"` network -> the segment
    /// assertion fails; make the absent case default to the first network instead
    /// of erroring -> the `is_err` assertion fails.
    #[test]
    fn vantage_network_finds_the_named_segment_or_fails_closed() {
        let lab = lab(
            vec![
                net("internal", "net-internal"),
                net("internet", "net-internet"),
            ],
            vec![],
        );
        let found = vantage_network(&lab, "internet").expect("the internet segment is present");
        assert_eq!(
            found.segment(),
            "internet",
            "the lookup returns the named segment's network, not the first"
        );
        assert!(
            vantage_network(&lab, "dmz").is_err(),
            "a segment the environment does not declare fails closed"
        );
    }

    /// Guard: replay re-resolves the witness target through the scope gate
    /// before standing a lab up, so a crafted witness naming a host outside the
    /// environment's scope fails closed (`Error::OutOfScope`) with no Docker
    /// work (ADR-0006). The witness target is attacker-influenced data read back
    /// from a reproduction, so it must not be trusted verbatim. Runs offline
    /// because the resolve precedes `bring_up`; the lazy `Docker` handle is never
    /// used. Mutation: in `replay_vantage_probe`, resolve the target against a
    /// witness-trusting scope (e.g. `Scope::builder().allow(&target)?.build()`)
    /// instead of `Scope::from_environment(env)` -> `evil:1234` resolves ->
    /// replay reaches `bring_up` and no longer returns `OutOfScope` -> this fails.
    #[test]
    fn replay_re_resolves_the_witness_target_through_scope() {
        let env = mvp_env();
        let witness = Reproduction {
            capability: "tcp_connect_vantage".to_owned(),
            target: "evil:1234".to_owned(),
            params: serde_json::json!({ "timeout_ms": 2_000, "vantage_segment": "internet" }),
        };
        let docker = Docker::connect_with_local_defaults().expect("lazy connect");
        let result = block_on(replay_vantage_probe(&docker, &env, &witness));
        assert!(
            matches!(result, Err(Error::OutOfScope { .. })),
            "a witness target outside the env scope is refused before bring-up, got {result:?}"
        );
    }

    /// Guard: a vantage probe recorded against the MVP lab replays from its
    /// witness through the full pipeline (parse, bring-up, resolve, probe,
    /// teardown) and agrees with the recording that `db` is unreachable from the
    /// `internet` vantage (ADR-0022, #29). The witness is produced by the real
    /// recorder, not hand-assembled. The name says "agrees on an unreachable
    /// target", not "reproduces an observation": an all-unreachable MVP lab
    /// cannot distinguish a reproduced `false` from a hard-coded one, so this
    /// proves the pipeline runs end to end and does not disagree, while the
    /// segment-selection and witness-shape mutations are carried by the offline
    /// guards above. Mutation: break `parse_vantage_witness` so it rejects the
    /// recorded witness, or `vantage_network` so the `internet` segment is not
    /// found -> `replay` returns `Err` -> the `expect` panics -> this fails.
    /// Docker-gated, self-skipping. RK-010: it asserts the reproduced
    /// observation, not a global Docker object count.
    #[test]
    fn replay_vantage_probe_agrees_with_the_recording_on_an_unreachable_target() {
        if !linux_docker_available() {
            eprintln!(
                "skipping replay_vantage_probe_agrees_with_the_recording_on_an_unreachable_target: no Linux Docker daemon"
            );
            return;
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let env = Environment::builder()
                .segment("internal")
                .segment("internet")
                .workload("db", PROBE_IMAGE, "internal")
                .vantage("internet")
                .boundary("internet", "internal", &[])
                .build()
                .expect("a valid environment");

            // Record a real vantage probe: db is unreachable from the internet
            // vantage (cross-segment, and the stand-in does not listen).
            let lab = bring_up(&docker, &env).await.expect("bring up the lab");
            let internet = vantage_network(&lab, "internet").expect("the internet network");
            let scoped = Scope::from_environment(&env)
                .resolve("db:5432")
                .expect("db is in scope");
            let (recorded, draft) =
                tcp_reachable_from(&docker, internet, &scoped, Duration::from_secs(2))
                    .await
                    .expect("the probe ran");
            lab.teardown().await.expect("teardown after recording");

            // Replay from the recorded witness and check it reproduces.
            let replayed = replay_vantage_probe(&docker, &env, &draft.reproduction)
                .await
                .expect("replay from the witness runs");
            assert_eq!(
                replayed.value, recorded.value,
                "replaying the witness reproduces the recorded observation"
            );
            assert_eq!(replayed.confidence, recorded.confidence);
        });
    }
}
