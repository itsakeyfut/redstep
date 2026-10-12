//! Integration tests for the lab orchestrator (#18). These need a Docker daemon
//! and self-skip where one is absent (docs/rules/test.md), so the gate stays
//! green on a bare runner while the real lab is exercised on the `ubuntu-latest`
//! CI leg. They send traffic only inside Docker objects they create, never to a
//! real external host (docs/rules/test.md), and clean up what they make.
//!
//! The egress-less flag is checked structurally (each lab network is
//! `internal: true`), which a dropped `internal: Some(true)` in the orchestrator
//! would fail. That a declared-forbidden path is actually blocked is the
//! boundary self-check (Decision N step 4), driven against a `bring_up` lab with
//! a positive control.

use bollard::Docker;
use bollard::models::NetworkConnectRequest;
use bollard::query_parameters::{InspectContainerOptions, InspectNetworkOptions};
use redstep::{Environment, Error, boundary_self_check, bring_up};

/// A tiny pinned image for the stand-in workloads (#18 proves orchestration, not
/// real services; the real vulnerable images are the H slice).
const STANDIN_IMAGE: &str = "busybox:1.37";

/// The lab is Linux containers (egress-less bridge networks, busybox), so it
/// needs a daemon in Linux-container mode, not merely a reachable daemon: a
/// Windows-container daemon reports success for `docker info` but cannot run the
/// lab. Skip unless `OSType` is `linux`.
fn linux_docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["info", "--format", "{{.OSType}}"])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "linux")
        .unwrap_or(false)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
}

/// The MVP topology with stand-in images: internet/internal, web/api/db in
/// internal, the vantage external, the internet -> internal path blocked.
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

/// Guard: bringing up the MVP lab creates one network per segment, each
/// egress-less (`internal: true`), and one container per workload attached to
/// its own segment's network only (never the default bridge, which would re-add
/// egress), and teardown removes them all. Mutations: drop `internal: Some(true)`
/// in `bring_up` -> the `internal == Some(true)` assertion fails; attach a
/// container to the wrong segment's network, or also to the bridge -> the
/// exact-network assertion fails; make `teardown` skip its removals -> the
/// post-teardown `inspect_network` assertion fails.
#[test]
fn brings_up_and_tears_down_the_mvp_lab() {
    if !linux_docker_available() {
        eprintln!("skipping brings_up_and_tears_down_the_mvp_lab: no Linux Docker daemon");
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
        let lab = bring_up(&docker, &mvp())
            .await
            .expect("bring up the MVP lab");

        assert_eq!(lab.networks().len(), 2, "one network per segment");
        assert_eq!(lab.containers().len(), 3, "one container per workload");

        // Every lab network exists and is egress-less.
        for net in lab.networks() {
            let info = docker
                .inspect_network(net.name(), None::<InspectNetworkOptions>)
                .await
                .unwrap_or_else(|e| panic!("network {} should exist: {e}", net.name()));
            assert_eq!(
                info.internal,
                Some(true),
                "network {} for segment {} must be egress-less",
                net.name(),
                net.segment()
            );
        }

        // Every container is attached to exactly its own segment's network.
        for container in lab.containers() {
            let expected_net = lab
                .networks()
                .iter()
                .find(|n| n.segment() == container.segment())
                .unwrap_or_else(|| panic!("no network for segment {}", container.segment()))
                .name();
            let info = docker
                .inspect_container(container.name(), None::<InspectContainerOptions>)
                .await
                .unwrap_or_else(|e| panic!("container {} should exist: {e}", container.name()));
            let attached: Vec<String> = info
                .network_settings
                .and_then(|s| s.networks)
                .map(|m| m.into_keys().collect())
                .unwrap_or_default();
            assert_eq!(
                attached,
                vec![expected_net.to_owned()],
                "container {} must be on exactly its segment network",
                container.name()
            );
        }

        let network_names: Vec<String> =
            lab.networks().iter().map(|n| n.name().to_owned()).collect();
        lab.teardown().await.expect("teardown removes every object");
        for net in &network_names {
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

/// Guard: the boundary self-check passes over a correctly-isolated MVP lab, so a
/// run could proceed. The happy-path companion to the refusal below.
#[test]
fn self_check_passes_for_an_isolated_lab() {
    if !linux_docker_available() {
        eprintln!("skipping self_check_passes_for_an_isolated_lab: no Linux Docker daemon");
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
        let env = mvp();
        let lab = bring_up(&docker, &env).await.expect("bring up the MVP lab");
        let result = boundary_self_check(&docker, &env, &lab).await;
        let teardown = lab.teardown().await;
        result.expect("an isolated lab passes the self-check");
        teardown.expect("teardown removes every object");
    });
}

/// Guard: the self-check refuses a lab whose forbidden pair has been connected
/// (an `internal` workload attached to the `internet` network too, the realistic
/// bring-up bug), rather than letting the run proceed. Mutation: treat a
/// reachable forbidden probe as not-violated (drop the `probe_reaches -> Err`
/// arm in `boundary_self_check`) -> the broken lab passes -> this fails.
#[test]
fn self_check_refuses_a_lab_whose_forbidden_pair_is_connected() {
    if !linux_docker_available() {
        eprintln!(
            "skipping self_check_refuses_a_lab_whose_forbidden_pair_is_connected: no Linux Docker daemon"
        );
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
        let env = mvp();
        let lab = bring_up(&docker, &env).await.expect("bring up the MVP lab");

        // Break isolation the realistic way: attach an internal workload onto the
        // internet network, so internet -> internal is now reachable.
        let internet_net = lab
            .networks()
            .iter()
            .find(|n| n.segment() == "internet")
            .expect("internet network")
            .name()
            .to_owned();
        let internal_container = lab
            .containers()
            .iter()
            .find(|c| c.segment() == "internal")
            .expect("an internal workload")
            .name()
            .to_owned();
        docker
            .connect_network(
                &internet_net,
                NetworkConnectRequest {
                    container: internal_container,
                    ..Default::default()
                },
            )
            .await
            .expect("connect the internal workload to the internet network");

        let result = boundary_self_check(&docker, &env, &lab).await;
        let _ = lab.teardown().await;

        assert!(
            matches!(&result, Err(Error::BoundaryViolated { from, to }) if from == "internet" && to == "internal"),
            "a connected forbidden pair must be refused, got {result:?}"
        );
    });
}
