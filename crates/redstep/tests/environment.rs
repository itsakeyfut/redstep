//! Integration tests for the lab orchestrator (#18). These need a Docker daemon
//! and self-skip where one is absent (docs/rules/test.md), so the gate stays
//! green on a bare runner while the real lab is exercised on the `ubuntu-latest`
//! CI leg. They send traffic only inside Docker objects they create, never to a
//! real external host (docs/rules/test.md), and clean up what they make.
//!
//! The egress-less flag is checked structurally here (each lab network is
//! `internal: true`), which a dropped `internal: Some(true)` in the orchestrator
//! would fail. That a forbidden path is actually blocked at run time is the
//! boundary self-check (Decision N step 4), a later unit (#19): a behavioural
//! egress probe belongs there, driven against a `bring_up` lab with a positive
//! control, not here where it would be confounded by Docker's inter-network
//! isolation.

use bollard::Docker;
use bollard::query_parameters::{InspectContainerOptions, InspectNetworkOptions};
use redstep::{Environment, bring_up};

/// A tiny pinned image for the stand-in workloads (#18 proves orchestration, not
/// real services; the real vulnerable images are the H slice).
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
