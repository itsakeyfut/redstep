//! Bring an [`Environment`] up as Docker networks and containers, and tear it
//! down (Decision C: bollard; Decision F layer 1 and Decision N: egress-less
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
//! The MVP realises the membership-only model (Decision N): a boundary is
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
//! network and reuses `tcp_connect`'s classification (#27, a Decision B
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
use crate::evidence::{EvidenceDraft, Reproduction};
use crate::intensity::Intensity;
use crate::observation::Observation;
use crate::scope::ScopedTarget;

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
/// runs (Decision N step 4). For each boundary (an empty `allow` means the path
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
/// a routed or port-level boundary: the firewall gateway (Decision N, Phase 4 /
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
/// cannot prove the port closed), so the native and vantage paths agree on what a
/// connect means. The confidence still differs by path in the one way that
/// matters: a `Low` "unreachable" from a single vantage connect cannot by itself
/// certify that a boundary held (the oracle's default `High` keeps it out of a
/// confident PASS); that certification is [`boundary_self_check`]'s job, with its
/// positive control. The draft is *not* a native `tcp_connect` record: it carries
/// a distinct capability name and records the vantage network, so a reader cannot
/// mistake an in-lab vantage probe for a host-run connect. An abnormal probe is
/// `Error::LabUnavailable`, fail-closed.
///
/// The recorded reproduction is minimal and not yet a faithful replay witness
/// (Decision D's `source` node and Decision V's pinned replay are a follow-up):
/// it records the applied timeout and the vantage network, not the full lab the
/// probe ran against.
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
    let draft = EvidenceDraft {
        capability: "tcp_connect_vantage",
        target: spec.clone(),
        intensity: Intensity::Safe,
        observed: serde_json::Value::Bool(observation.value),
        confidence: observation.confidence,
        summary: connect_summary(outcome).to_owned(),
        reproduction: Reproduction {
            capability: "tcp_connect_vantage".to_owned(),
            target: spec,
            params: serde_json::json!({
                "timeout_ms": applied.as_millis() as u64,
                "vantage_network": vantage.name(),
            }),
        },
    };
    Ok((observation, draft))
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
        // Backstop for a forgotten teardown or a panic. Drop cannot be async,
        // and `block_on` panics when it runs on a thread that is already inside
        // a runtime (the common case: a `?`/panic/cancel between `bring_up` and
        // an explicit teardown). So run the removal on a dedicated thread, which
        // has no ambient runtime, and join it. Best effort: warn, never panic.
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
            // The draft marks itself a vantage probe and records the vantage
            // network, so it is not mistaken for a native host-run tcp_connect.
            assert_eq!(same_draft.capability, "tcp_connect_vantage");
            assert_eq!(same_draft.target, spec);
            assert_eq!(
                same_draft.reproduction.params["vantage_network"].as_str(),
                Some(net_a.as_str()),
                "the reproduction records which vantage the probe ran from"
            );

            let (cross, _) = cross_net.expect("cross-network probe ran");
            assert!(
                !cross.value,
                "a listener whose name does not resolve on a different, isolated network is not reachable from the vantage"
            );
        });
    }
}
