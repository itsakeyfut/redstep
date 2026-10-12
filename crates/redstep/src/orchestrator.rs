//! Bring an [`Environment`] up as Docker networks and containers, and tear it
//! down (Decision C: bollard; Decision F layer 1 and Decision N: egress-less
//! isolation).
//!
//! The environment/network layer (docs/rules/design.md section 2): this is the
//! only module that uses bollard, and it depends on the pure [`Environment`]
//! model. Each segment becomes one Docker network created `internal: true`, so
//! nothing in the lab has a route to the internet or to production
//! (docs/rules/security.md section 1). Each workload becomes a container
//! attached to its segment's network *only* (via `network_mode`, never the
//! default bridge, which would re-add egress). Teardown removes everything, and
//! [`RunningLab`]'s `Drop` is a best-effort backstop so an interrupted or
//! panicking run does not leak a network or a container for a later run to
//! inherit.
//!
//! The boundary self-check that gates test execution (Decision N step 4) is a
//! later unit (#19) built on [`RunningLab`]; this unit stands the lab up and
//! proves, in its integration test, that an internal segment has no egress.

use bollard::Docker;
use bollard::models::{ContainerCreateBody, HostConfig, NetworkCreateRequest};
use bollard::query_parameters::{CreateContainerOptions, RemoveContainerOptions};

use crate::environment::Environment;
use crate::error::{Error, Result};

/// A running lab: the Docker networks and containers a [`bring_up`] created,
/// held by name so [`teardown`](RunningLab::teardown) can remove exactly them.
///
/// The normal path is the explicit async [`teardown`](RunningLab::teardown).
/// `Drop` is the backstop: if teardown was not called (an early return, a
/// panic), it removes what it can on a short-lived runtime and warns on failure,
/// never panicking. A leaked network or container is a resource leak, not a
/// scope escape (the networks are egress-less), but teardown is not optional
/// (docs/rules/security.md section 1).
pub struct RunningLab {
    docker: Docker,
    /// Created network names, for teardown.
    networks: Vec<String>,
    /// Created container names, for teardown.
    containers: Vec<String>,
    torn_down: bool,
}

/// A short, process-unique tag so concurrent or repeated runs do not collide and
/// teardown targets exactly this run's objects.
fn run_tag() -> String {
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

fn orchestration(err: impl std::fmt::Display) -> Error {
    Error::Orchestration {
        reason: err.to_string(),
    }
}

/// Bring `env` up: one egress-less network per segment, then each workload as a
/// container attached to its segment's network. `docker` is injected so a test
/// controls the connection. On any failure, what was already created is torn
/// down before returning, so a partial lab never leaks.
pub async fn bring_up(docker: &Docker, env: &Environment) -> Result<RunningLab> {
    let tag = run_tag();
    let mut lab = RunningLab {
        docker: docker.clone(),
        networks: Vec::new(),
        containers: Vec::new(),
        torn_down: false,
    };

    match build(docker, env, &tag, &mut lab).await {
        Ok(()) => Ok(lab),
        Err(e) => {
            // Tear down the partial lab before surfacing the error.
            let _ = lab.teardown_inner().await;
            lab.torn_down = true;
            Err(e)
        }
    }
}

/// The network name for a segment in this run.
fn network_name(tag: &str, segment: &str) -> String {
    format!("{tag}-net-{segment}")
}

/// The container name for a workload in this run.
fn container_name(tag: &str, workload: &str) -> String {
    format!("{tag}-{workload}")
}

async fn build(docker: &Docker, env: &Environment, tag: &str, lab: &mut RunningLab) -> Result<()> {
    for segment in env.segments() {
        let name = network_name(tag, segment.name());
        docker
            .create_network(NetworkCreateRequest {
                name: name.clone(),
                internal: Some(true),
                ..Default::default()
            })
            .await
            .map_err(orchestration)?;
        lab.networks.push(name);
    }

    for workload in env.workloads() {
        let cname = container_name(tag, workload.name());
        let net = network_name(tag, workload.segment());
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
                    host_config: Some(HostConfig {
                        // Attach to the segment network ONLY. network_mode
                        // replaces the default bridge, so the container gets no
                        // egress path (security.md section 1).
                        network_mode: Some(net),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .map_err(orchestration)?;
        lab.containers.push(cname.clone());
        docker
            .start_container(
                &cname,
                None::<bollard::query_parameters::StartContainerOptions>,
            )
            .await
            .map_err(orchestration)?;
    }

    Ok(())
}

impl RunningLab {
    /// The names of the networks this lab created, one per segment.
    pub fn networks(&self) -> &[String] {
        &self.networks
    }

    /// The names of the containers this lab created, one per workload.
    pub fn containers(&self) -> &[String] {
        &self.containers
    }

    /// Remove every container and network this lab created. The normal,
    /// error-surfacing teardown path.
    pub async fn teardown(mut self) -> Result<()> {
        let result = self.teardown_inner().await;
        self.torn_down = true;
        result
    }

    async fn teardown_inner(&mut self) -> Result<()> {
        let mut first_err: Option<Error> = None;
        for name in &self.containers {
            if let Err(e) = self
                .docker
                .remove_container(
                    name,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await
            {
                first_err.get_or_insert_with(|| orchestration(e));
            }
        }
        for name in &self.networks {
            if let Err(e) = self.docker.remove_network(name).await {
                first_err.get_or_insert_with(|| orchestration(e));
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Drop for RunningLab {
    fn drop(&mut self) {
        if self.torn_down {
            return;
        }
        // Best-effort backstop for a forgotten teardown or a panic. Drop cannot
        // be async, and blocking inside an active runtime panics, so run the
        // removal on a fresh current-thread runtime and swallow any failure: a
        // leak is better than a panic in Drop.
        let built = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        match built {
            Ok(rt) => {
                if rt.block_on(self.teardown_inner()).is_err() {
                    eprintln!(
                        "redstep: lab teardown backstop could not remove every object; \
                         some Docker networks or containers may remain"
                    );
                }
            }
            Err(_) => {
                eprintln!(
                    "redstep: lab teardown backstop could not start a runtime; \
                     some Docker networks or containers may remain"
                );
            }
        }
    }
}
