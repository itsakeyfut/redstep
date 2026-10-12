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
//! path is actually blocked is [`boundary_self_check`] (Decision N step 4),
//! which probes it behaviourally with a positive control and refuses a run whose
//! forbidden path is reachable.

use std::collections::HashMap;

use bollard::Docker;
use bollard::models::{
    ContainerCreateBody, EndpointSettings, NetworkCreateRequest, NetworkingConfig,
};
use bollard::query_parameters::{CreateContainerOptions, RemoveContainerOptions};

use crate::environment::Environment;
use crate::error::{Error, Result};

/// A segment's Docker network, paired with the segment it was built from so a
/// later unit (#19's boundary self-check) can map a segment to its network
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
/// built from so a later unit can find a named workload's container and its
/// segment without reparsing the name.
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

/// A tiny pinned image that can `ping`, for the self-check's probe containers (a
/// workload image like `postgres:16` may not carry `ping`).
const PROBE_IMAGE: &str = "busybox:1.37";

/// Verify every declared-forbidden path is actually blocked, before any test
/// runs (Decision N step 4). For each boundary (an empty `allow` means the path
/// is blocked, and a non-empty one is refused at build), a probe container in
/// the `from` segment must fail to reach a workload in the `to` segment, while a
/// positive-control probe in the `to` segment does reach it, so a broken probe
/// cannot read as isolation (the gap #18's review found).
///
/// Returns `Ok(())` only when every forbidden path is verified blocked. A
/// reachable forbidden path is [`Error::BoundaryViolated`]; a control that
/// cannot reach, or any probe failure, is [`Error::LabUnavailable`], so the run
/// fails closed rather than proceeding on a lab whose isolation is uncertain.
/// The result is distinct from a test verdict.
///
/// Reachability is ICMP to the target's container name, which Docker's embedded
/// DNS resolves only for peers on the same network, so it needs no listener and
/// a path that opens only because the target was wrongly attached to the `from`
/// network is detected.
pub async fn boundary_self_check(
    docker: &Docker,
    env: &Environment,
    lab: &RunningLab,
) -> Result<()> {
    pull_image(docker, PROBE_IMAGE).await?;

    for boundary in env.boundaries() {
        let from = boundary.from();
        let to = boundary.to();

        let Some(target) = lab.containers().iter().find(|c| c.segment() == to) else {
            // Nothing in the `to` segment to reach; the path is vacuously blocked.
            continue;
        };
        let from_net = segment_network(lab, from)?;
        let to_net = segment_network(lab, to)?;

        // Positive control: reachable from its own segment, so a later
        // "unreachable" is a real block rather than a broken probe.
        if !probe_reaches(docker, to_net, target.name()).await? {
            return Err(Error::LabUnavailable {
                reason: format!(
                    "boundary self-check could not reach {to} workload {:?} from its own segment; \
                     the probe is untrustworthy, so isolation cannot be certified",
                    target.workload()
                ),
            });
        }

        // The forbidden path must be blocked.
        if probe_reaches(docker, from_net, target.name()).await? {
            return Err(Error::BoundaryViolated {
                from: from.to_owned(),
                to: to.to_owned(),
            });
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

/// Whether a probe container on `network` can reach `target` (a container name
/// Docker's DNS resolves on that network) by ICMP. The probe is removed before
/// returning, even on error.
async fn probe_reaches(docker: &Docker, network: &str, target: &str) -> Result<bool> {
    let name = format!("{}-probe", run_id());
    let result = run_probe(docker, &name, network, target).await;
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

async fn run_probe(docker: &Docker, name: &str, network: &str, target: &str) -> Result<bool> {
    let endpoints = HashMap::from([(network.to_owned(), EndpointSettings::default())]);
    docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some(name.to_owned()),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some(PROBE_IMAGE.to_owned()),
                cmd: Some(vec![
                    "ping".to_owned(),
                    "-c".to_owned(),
                    "1".to_owned(),
                    "-w".to_owned(),
                    "2".to_owned(),
                    target.to_owned(),
                ]),
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
    Ok(probe_exit(docker, name).await? == 0)
}

/// Poll until the probe container exits and return its exit code, bounded so a
/// stuck probe fails the check rather than hanging it (`ping -w 2` exits within
/// a few seconds).
async fn probe_exit(docker: &Docker, name: &str) -> Result<i64> {
    for _ in 0..40 {
        let info = docker
            .inspect_container(
                name,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .map_err(lab_unavailable)?;
        let state = info.state.unwrap_or_default();
        if state.running != Some(true) {
            return Ok(state.exit_code.unwrap_or(-1));
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err(Error::LabUnavailable {
        reason: format!("boundary self-check probe {name:?} did not exit within the timeout"),
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
}
