//! Integration tests for the lab orchestrator (#18). These need a Docker daemon
//! and self-skip where one is absent (docs/rules/test.md), so the gate stays
//! green on a bare runner while the real lab is exercised on the `ubuntu-latest`
//! CI leg. They send traffic only inside Docker objects they create, never to a
//! real external host (docs/rules/test.md), and clean up what they make.

use std::time::Duration;

use bollard::Docker;
use bollard::models::{ContainerCreateBody, HostConfig, NetworkCreateRequest};
use bollard::query_parameters::{
    CreateContainerOptions, InspectContainerOptions, InspectNetworkOptions, RemoveContainerOptions,
    StartContainerOptions,
};
use redstep::{Environment, bring_up};

/// A tiny image that stays alive on `sleep` and can run `nc`, for the stand-in
/// workloads and the egress probe/rendezvous. Pinned for reproducibility
/// (Decision R); the real vulnerable images are the H slice.
const STANDIN_IMAGE: &str = "busybox:1.37";

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
}

/// The MVP topology with stand-in images (#18 proves orchestration, not real
/// services): internet/internal, web/api/db in internal, the vantage external,
/// the internet -> internal path blocked.
fn mvp() -> Environment {
    Environment::builder()
        .segment("internal")
        .segment("internet")
        .workload("web", STANDIN_IMAGE, "internal")
        .workload("api", STANDIN_IMAGE, "internal")
        .workload("db", STANDIN_IMAGE, "internal")
        .vantage("internet")
        .boundary("internet", "internal", &[])
        .build()
        .expect("the MVP topology is valid")
}

/// Guard: bringing up the MVP lab creates a network per segment and a container
/// per workload attached to its segment's network only (never the default
/// bridge, which would re-add egress), and teardown removes them all. Mutation:
/// skip creating a network, or attach a container to the wrong network, or make
/// `teardown` skip its removals -> the matching assertion fails.
#[test]
fn brings_up_and_tears_down_the_mvp_lab() {
    if !docker_available() {
        eprintln!("skipping brings_up_and_tears_down_the_mvp_lab: no Docker daemon");
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
        let lab = bring_up(&docker, &mvp())
            .await
            .expect("bring up the MVP lab");

        assert_eq!(lab.networks().len(), 2, "one network per segment");
        assert_eq!(lab.containers().len(), 3, "one container per workload");

        for net in lab.networks() {
            docker
                .inspect_network(net, None::<InspectNetworkOptions>)
                .await
                .unwrap_or_else(|e| panic!("network {net} should exist: {e}"));
        }

        for container in lab.containers() {
            let info = docker
                .inspect_container(container, None::<InspectContainerOptions>)
                .await
                .unwrap_or_else(|e| panic!("container {container} should exist: {e}"));
            let networks = info
                .network_settings
                .and_then(|s| s.networks)
                .unwrap_or_default();
            assert!(
                networks.keys().any(|k| lab.networks().contains(k)),
                "{container} is attached to a lab segment network, got {:?}",
                networks.keys().collect::<Vec<_>>()
            );
            assert!(
                !networks.contains_key("bridge"),
                "{container} must not be on the default bridge (that would re-add egress)"
            );
        }

        let networks: Vec<String> = lab.networks().to_vec();
        lab.teardown().await.expect("teardown removes every object");
        for net in &networks {
            assert!(
                docker
                    .inspect_network(net, None::<InspectNetworkOptions>)
                    .await
                    .is_err(),
                "network {net} should be gone after teardown"
            );
        }
    });
}

/// Guard: a container in an `internal: true` segment cannot reach a rendezvous
/// on a non-internal network, i.e. the segment has no egress (Decision F layer
/// 1, Decision N). The rendezvous lives inside this test's own Docker, never a
/// real external host (docs/rules/test.md). Mutation: create the internal
/// segment network with `internal: Some(false)` -> the probe reaches the
/// rendezvous and exits zero -> this fails.
#[test]
fn internal_segment_cannot_reach_a_lab_external_rendezvous() {
    if !docker_available() {
        eprintln!(
            "skipping internal_segment_cannot_reach_a_lab_external_rendezvous: no Docker daemon"
        );
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
        let tag = format!("redstep-egress-{}", std::process::id());
        let rdv_net = format!("{tag}-rdv-net");
        let internal_net = format!("{tag}-internal-net");
        let rendezvous = format!("{tag}-rendezvous");
        let probe = format!("{tag}-probe");
        let port = "9099";

        // Rendezvous network: default driver, not internal, so a container on it
        // is reachable from a non-isolated peer. Internal segment: egress-less.
        docker
            .create_network(NetworkCreateRequest {
                name: rdv_net.clone(),
                ..Default::default()
            })
            .await
            .expect("create rendezvous network");
        docker
            .create_network(NetworkCreateRequest {
                name: internal_net.clone(),
                internal: Some(true),
                ..Default::default()
            })
            .await
            .expect("create internal network");

        // Rendezvous listens on the rendezvous network.
        run_container(&docker, &rendezvous, &rdv_net, vec!["nc", "-l", "-p", port]).await;
        let rendezvous_ip = container_ip(&docker, &rendezvous, &rdv_net).await;

        // Probe in the internal segment attempts to reach the rendezvous IP.
        run_container(
            &docker,
            &probe,
            &internal_net,
            vec!["nc", "-w", "3", &rendezvous_ip, port],
        )
        .await;
        let exit = wait_exit(&docker, &probe).await;

        // Clean up before asserting, so a failed assertion does not leak.
        for c in [&probe, &rendezvous] {
            let _ = docker
                .remove_container(
                    c,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;
        }
        for n in [&internal_net, &rdv_net] {
            let _ = docker.remove_network(n).await;
        }

        assert_ne!(
            exit, 0,
            "the probe reached the rendezvous from an internal segment; egress is not blocked"
        );
    });
}

/// Create and start a container on `network` running `cmd`.
async fn run_container(docker: &Docker, name: &str, network: &str, cmd: Vec<&str>) {
    docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some(name.to_owned()),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some(STANDIN_IMAGE.to_owned()),
                cmd: Some(cmd.into_iter().map(str::to_owned).collect()),
                host_config: Some(HostConfig {
                    network_mode: Some(network.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("create {name}: {e}"));
    docker
        .start_container(name, None::<StartContainerOptions>)
        .await
        .unwrap_or_else(|e| panic!("start {name}: {e}"));
}

/// The container's IPv4 address on `network`.
async fn container_ip(docker: &Docker, name: &str, network: &str) -> String {
    let info = docker
        .inspect_container(name, None::<InspectContainerOptions>)
        .await
        .unwrap_or_else(|e| panic!("inspect {name}: {e}"));
    info.network_settings
        .and_then(|s| s.networks)
        .and_then(|mut m| m.remove(network))
        .and_then(|e| e.ip_address)
        .filter(|ip| !ip.is_empty())
        .unwrap_or_else(|| panic!("{name} has no IP on {network}"))
}

/// Poll until `name` has exited and return its exit code. Bounded so a stuck
/// container fails the test rather than hanging it (the probe's `nc -w 3` exits
/// within a few seconds).
async fn wait_exit(docker: &Docker, name: &str) -> i64 {
    for _ in 0..40 {
        let info = docker
            .inspect_container(name, None::<InspectContainerOptions>)
            .await
            .unwrap_or_else(|e| panic!("inspect {name}: {e}"));
        let state = info.state.unwrap_or_default();
        if state.running != Some(true) {
            return state.exit_code.unwrap_or(-1);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("{name} did not exit within the timeout");
}
