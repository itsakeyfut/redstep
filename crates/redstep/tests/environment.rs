//! Integration tests for the lab orchestrator (#18, #19) and the lab-wired run
//! path (#28). These need a Docker daemon and self-skip where one is absent
//! (docs/rules/test.md), so the gate stays green on a bare runner while the real
//! lab is exercised on the `ubuntu-latest` CI leg. They send traffic only inside
//! Docker objects they create, never to a real external host (docs/rules/test.md),
//! and clean up what they make.
//!
//! The egress-less flag is checked structurally (each lab network is
//! `internal: true`), which a dropped `internal: Some(true)` in the orchestrator
//! would fail. That a declared-forbidden path is actually blocked is the
//! boundary self-check (ADR-0011 step 4), driven against a `bring_up` lab with
//! a positive control. The run path brings the lab up, gates on the self-check,
//! runs the boundary demo (`attacker_cannot_connect_to_db`) from the attacker's vantage, and
//! tears the lab down (#28).
//!
//! The same shape has an assume-breach twin (ADR-0017): `assume_breach_dmz()`
//! places the foothold on an internal DMZ segment and
//! `assume_breach_dmz_foothold_is_contained` verdicts the internal database
//! unreachable from it, with a positive control and the self-check.

use bollard::Docker;

use bollard::models::NetworkConnectRequest;
use bollard::query_parameters::{InspectContainerOptions, InspectNetworkOptions};

use redstep::{
    Confidence, Environment, Error, RunError, Scope, TestContext, WorkloadKind,
    boundary_self_check, bring_up, report, run_in_lab, run_in_running_lab,
};

/// A tiny pinned image for the stand-in workloads (#18 proves orchestration, not
/// real services; the real vulnerable images are the H slice).
const STANDIN_IMAGE: &str = "busybox:1.37";

/// The lab tests default to SKIPPED and run only when `REDSTEP_RUN_DOCKER_TESTS`
/// is set, so a local `cargo test` creates no lab containers; CI opts in. When the
/// opt-in is set, the daemon MUST be present and in Linux-container mode (a
/// Windows-container daemon reports success for `docker info` but cannot run the
/// lab), and its absence is a loud `assert!` failure, not a skip: a silent skip in
/// CI would leave the Docker-gated guards unrun while CI stayed green.
/// (Mirrors the gate in `orchestrator.rs`.)
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

/// Guard: without the opt-in, the lab gate is closed, so the integration lab tests
/// create no containers (#98). A no-op in CI, where `REDSTEP_RUN_DOCKER_TESTS` is
/// set. Mutation: drop the `is_none() -> return false` short-circuit in this file's
/// `linux_docker_available()` -> on a machine with a Linux Docker daemon and the var
/// unset it probes and returns `true` -> this assertion fails. (Mirrors the guard in
/// `orchestrator.rs`; this one covers this file's own copy of the gate.)
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
        .standin("web", STANDIN_IMAGE, "internal")
        .standin("api", STANDIN_IMAGE, "internal")
        .standin("db", STANDIN_IMAGE, "internal")
        .vantage("internet")
        .boundary("internet", "internal", &[])
        .build()
        .expect("the MVP topology is valid")
}

/// An assume-breach topology: the attacker's foothold is a taken DMZ host
/// (`vantage("dmz")`), a listening `web` sits in the DMZ, a listening `db` sits in
/// `internal`, and the `dmz` -> `internal` path is blocked by a membership
/// boundary. It is the assume-breach twin of `mvp()`'s external vantage (#96,
/// ADR-0017): the foothold reaches its own segment but is contained from internal.
/// The port-level firewall boundary is a separate sub of #95 and deliberately not
/// used here; this containment rests on the membership boundary and the self-check.
///
/// Both `web` and `db` run a real listener on purpose. `db` listening on 5432 is
/// what makes the containment probe non-vacuous: a stand-in `db` would read
/// unreachable because nothing listens, so the probe could not tell "blocked by
/// the boundary" from "dead port" (RK-008). With `db` listening, a `dmz` foothold
/// reads it unreachable only because of the segment isolation, and a foothold
/// moved onto `internal` reads it reachable, so the containment leg actually turns
/// on reachability. `api` stays a stand-in: nothing probes it.
fn assume_breach_dmz() -> Environment {
    // A listener loop reused for both hosts: busybox's default command would exit
    // and leave nothing to connect to, which would read as unreachable.
    let listen = |port: &str| -> Vec<String> {
        vec![
            "sh".to_owned(),
            "-c".to_owned(),
            format!("while true; do nc -l -p {port} >/dev/null 2>&1; done"),
        ]
    };
    let web_cmd = listen("80");
    let db_cmd = listen("5432");
    Environment::builder()
        .segment("dmz")
        .segment("internal")
        .service_cmd(
            "web",
            STANDIN_IMAGE,
            "dmz",
            &web_cmd.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .standin("api", STANDIN_IMAGE, "internal")
        .service_cmd(
            "db",
            STANDIN_IMAGE,
            "internal",
            &db_cmd.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .vantage("dmz")
        .boundary("dmz", "internal", &[])
        .build()
        .expect("the assume-breach DMZ topology is valid")
}

/// A gateway-mediated topology: a `dmz` foothold segment, an `internal` segment
/// with a `web` stand-in, and a `dmz -> internal` boundary enforced by a firewall
/// gateway permitting `web:80`. The gateway is dual-homed on both segment
/// networks and proxies `web:80` (ADR-0024). This fixture is for the structural
/// bring-up/teardown test below; `gateway_enforces_the_port_boundary` exercises
/// the reachability semantics with real listeners.
fn gateway_topology() -> Environment {
    Environment::builder()
        .segment("dmz")
        .segment("internal")
        .standin("foot", STANDIN_IMAGE, "dmz")
        .standin("web", STANDIN_IMAGE, "internal")
        .vantage("dmz")
        .gateway_boundary("dmz", "internal", &["web:80"])
        .build()
        .expect("the gateway topology is valid")
}

/// Guard: bringing up the MVP lab creates one network per segment, each
/// egress-less (`internal: true`), and one container per workload attached to
/// its own segment's network only (never the default bridge, which would re-add
/// egress), and teardown removes them all. Mutations: drop `internal: Some(true)`
/// in `bring_up` -> the `internal == Some(true)` assertion fails; attach a
/// container to the wrong segment's network, or also to the bridge -> the
/// exact-network assertion fails; make `teardown` skip its removals -> the
/// post-teardown `inspect_network` assertion fails; make `provision`'s gateway
/// filter admit every boundary (`.filter(|_| true)`) -> the MVP's plain boundary
/// spawns a gateway and the `gateways().is_empty()` assertion fails.
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
        assert!(
            lab.gateways().is_empty(),
            "the MVP's only boundary is membership-only, so no gateway is brought up"
        );

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

/// Guard: a gateway-mediated topology brings up with the gateway container
/// dual-homed on EXACTLY its two segment networks (both egress-less), is
/// self-check-clean, and tears down so the gateway container and both networks
/// are gone. Checked by this run's OWN object names, never a global count
/// (RK-010). This is the STRUCTURAL guard (the gateway's attachment and
/// teardown); the reachability semantics of the proxy are
/// `gateway_enforces_the_port_boundary`. The self-check passes here because the
/// gateway's `socat` listener for `web:80` accepts the probe (it accepts before
/// dialing upstream, so `web` need not actually serve 80 for the positive
/// control to connect; ADR-0024). The lab tests default-skip; opt in with
/// `REDSTEP_RUN_DOCKER_TESTS` (RK-013/014), so the model-level guards in
/// `environment.rs` carry the offline criteria. Mutations: drop the
/// `connect_network` in `provision` so the gateway is on one network, or let it
/// also join the default bridge -> the exact-two-networks assertion fails; drop
/// the gateway from `remove_all` -> the gone-after-teardown assertion fails.
#[test]
fn gateway_mediates_a_declared_inter_segment_path() {
    if !linux_docker_available() {
        eprintln!(
            "skipping gateway_mediates_a_declared_inter_segment_path: no Linux Docker daemon"
        );
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
        let env = gateway_topology();
        let lab = bring_up(&docker, &env)
            .await
            .expect("bring up the gateway topology");

        assert_eq!(lab.gateways().len(), 1, "one gateway per gateway boundary");
        let gateway = &lab.gateways()[0];
        assert_eq!(gateway.from(), "dmz");
        assert_eq!(gateway.to(), "internal");

        // Fail-closed by construction: no forwarding, so the self-check finds the
        // internal `web` unreachable from the dmz foothold (with its own positive
        // control in `internal`) and the topology certifies isolated.
        boundary_self_check(&docker, &env, &lab)
            .await
            .expect("the gateway topology is self-check-clean (no cross-segment path yet)");

        // The gateway is attached to EXACTLY its two segment networks, both
        // egress-less, and nothing else (never the default bridge).
        let net_for = |segment: &str| {
            lab.networks()
                .iter()
                .find(|n| n.segment() == segment)
                .unwrap_or_else(|| panic!("no network for segment {segment}"))
                .name()
                .to_owned()
        };
        let dmz_net = net_for("dmz");
        let internal_net = net_for("internal");
        let info = docker
            .inspect_container(gateway.name(), None::<InspectContainerOptions>)
            .await
            .unwrap_or_else(|e| panic!("gateway {} should exist: {e}", gateway.name()));
        let mut attached: Vec<String> = info
            .network_settings
            .and_then(|s| s.networks)
            .map(|m| m.into_keys().collect())
            .unwrap_or_default();
        attached.sort();
        let mut expected = vec![dmz_net.clone(), internal_net.clone()];
        expected.sort();
        assert_eq!(
            attached, expected,
            "the gateway must be dual-homed on exactly its two segment networks"
        );
        for net in [&dmz_net, &internal_net] {
            let ninfo = docker
                .inspect_network(net, None::<InspectNetworkOptions>)
                .await
                .unwrap_or_else(|e| panic!("network {net} should exist: {e}"));
            assert_eq!(
                ninfo.internal,
                Some(true),
                "network {net} must be egress-less"
            );
        }

        let gateway_name = gateway.name().to_owned();
        lab.teardown().await.expect("teardown removes every object");
        assert!(
            docker
                .inspect_container(&gateway_name, None::<InspectContainerOptions>)
                .await
                .is_err(),
            "gateway container {gateway_name} should be gone after teardown"
        );
        for net in [&dmz_net, &internal_net] {
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

/// A gateway-ENFORCED topology (#114): `dmz -> internal` enforced by a gateway
/// allowing `api:8080` and `web:80`. Every target runs a real listener so the
/// reachability checks are non-vacuous (RK-008): `api` listens on 8080 (allowed)
/// AND 5432 (a served-but-denied port), `web` on 80 (allowed), and `db` on 5432
/// (`db` is a non-allowed workload that nonetheless serves a port). So "api:5432
/// unreachable" and "db:5432 unreachable" turn on the gateway blocking them, not
/// on a dead port.
fn gateway_enforced_topology() -> Environment {
    // A listener loop per port, backgrounded, so one container serves several
    // ports and stays up (busybox's default command would exit at once).
    let listen = |ports: &[&str]| -> Vec<String> {
        let loops = ports
            .iter()
            .map(|p| format!("while true; do nc -l -p {p} >/dev/null 2>&1; done &"))
            .collect::<Vec<_>>()
            .join(" ");
        vec!["sh".to_owned(), "-c".to_owned(), format!("{loops} wait")]
    };
    let api_cmd = listen(&["8080", "5432"]);
    let web_cmd = listen(&["80"]);
    let db_cmd = listen(&["5432"]);
    Environment::builder()
        .segment("dmz")
        .segment("internal")
        .standin("foot", STANDIN_IMAGE, "dmz")
        .service_cmd(
            "api",
            STANDIN_IMAGE,
            "internal",
            &api_cmd.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .service_cmd(
            "web",
            STANDIN_IMAGE,
            "internal",
            &web_cmd.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .service_cmd(
            "db",
            STANDIN_IMAGE,
            "internal",
            &db_cmd.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .vantage("dmz")
        .gateway_boundary("dmz", "internal", &["api:8080", "web:80"])
        .build()
        .expect("the gateway-enforced topology is valid")
}

/// Guard: the gateway enforces the port boundary (#114). The self-check certifies
/// the lab (allowed paths reachable through the gateway, non-allowed workloads
/// not), and from the DMZ vantage the real reachability capability sees: the
/// allowed `api:8080` and `web:80` reachable; the served-but-denied `api:5432`
/// unreachable (the gateway proxies only 8080 for `api`); and the non-allowed
/// `db:5432` unreachable (db is not aliased on the gateway). `api:5432` and
/// `db:5432` are served, so their unreachability is the boundary, not a dead port
/// (RK-008). The lab tests default-skip; opt in with `REDSTEP_RUN_DOCKER_TESTS`
/// (RK-013/014), and the per-element decision logic (RK-009) and `gateway_cmd`
/// are pinned offline in `orchestrator.rs`. Mutations: open `api:5432` in
/// `gateway_cmd` (an extra listener) -> `api:5432` becomes reachable -> the
/// denied-port assertion fails; drop the gateway branch in `check_boundaries` (or
/// a socat listener) -> the self-check or the allowed-path assertions fail.
#[test]
fn gateway_enforces_the_port_boundary() {
    if !linux_docker_available() {
        eprintln!("skipping gateway_enforces_the_port_boundary: no Linux Docker daemon");
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
        let env = gateway_enforced_topology();
        let lab = bring_up(&docker, &env)
            .await
            .expect("bring up the gateway-enforced lab");

        // The self-check certifies the enforced boundary: allowed paths reachable
        // through the gateway (positive control), non-allowed workloads not.
        let self_check = boundary_self_check(&docker, &env, &lab).await;

        // The real reachability capability, from the DMZ vantage, observes the
        // enforcement: allowed ports reachable, the served-but-denied port and the
        // non-allowed workload not. Captured so teardown runs on whatever returns.
        let discovered = {
            let scope = Scope::from_environment(&env);
            let vantage = lab
                .networks()
                .iter()
                .find(|n| n.segment() == env.vantage_segment())
                .cloned()
                .expect("the dmz vantage network is in the running lab");
            let ctx = TestContext::new_in_lab(scope, docker.clone(), vantage);
            let targets = vec![
                ctx.resolve("api:8080").expect("api:8080 resolves"),
                ctx.resolve("web:80").expect("web:80 resolves"),
                ctx.resolve("api:5432").expect("api:5432 resolves"),
                ctx.resolve("db:5432").expect("db:5432 resolves"),
            ];
            ctx.discover_services_from_vantage(&targets).await
        };

        let _ = lab.teardown().await;

        self_check.expect("the self-check certifies the enforced boundary");
        let discovered = discovered.expect("the enumeration runs");
        let reachable = |i: usize| discovered[i].1.observation.value;
        assert!(
            reachable(0),
            "api:8080 is allowed, so reachable via the gateway"
        );
        assert!(
            reachable(1),
            "web:80 is allowed, so reachable via the gateway"
        );
        assert!(
            !reachable(2),
            "api:5432 is a served-but-denied port, so blocked by the gateway"
        );
        assert!(
            !reachable(3),
            "db:5432 is a non-allowed workload, so blocked by the gateway"
        );
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
/// bring-up bug), rather than letting the run proceed. The broken workload is
/// `db`, not the first-declared `internal` one, so this also guards that the
/// check probes every `to` workload rather than a representative. Mutation:
/// treat a reachable forbidden probe as not-violated (drop the `BoundaryViolated`
/// arm in `check_boundaries`) -> the broken lab passes -> this fails.
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
        // Break a non-first internal workload (db), so the test fails unless the
        // check probes every workload in the segment, not just the first.
        let internal_container = lab
            .containers()
            .iter()
            .find(|c| c.workload() == "db")
            .expect("the db workload")
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

/// The boundary demo's security test: from the attacker's vantage, the database
/// must not be reachable by TCP. It resolves `db` through the lab scope and probes
/// it from the vantage; the observation is `false` at `Low` (busybox `nc` cannot
/// prove a port closed), so it opts down to `min_confidence(Low)` explicitly. The
/// `High` certification that the boundary actually holds is the self-check gate
/// the run runs first, not this probe (#28, ADR-0010/ADR-0011 note). Registered by the
/// macro and run via the lab-wired runner; since the sibling assume-breach guard
/// adds a second registered test in this binary, both run against both topologies,
/// and this one passes against `assume_breach_dmz()` too (db is unreachable from
/// the DMZ vantage there).
#[redstep::security_test]
async fn attacker_cannot_connect_to_db(ctx: &TestContext) -> redstep::Result<()> {
    let target = ctx.resolve("db:5432")?;
    let recorded = ctx.connect_from_vantage(&target).await?;
    ctx.expect(&recorded)
        .min_confidence(Confidence::Low)
        .to_be(false);
    Ok(())
}

/// Guard: running against the isolated MVP lab brings it up, the self-check
/// passes, `attacker_cannot_connect_to_db` runs from the `internet` vantage and
/// PASSes (the DB is unreachable), and the report is PASS with the probe's
/// evidence linked and resolvable to a record for `db:5432`. Mutations: make
/// `connect_from_vantage` observe `true` (probe a reachable listener) -> the demo
/// is `Fail` -> the Pass assertion fails; drop the evidence draft in
/// `connect_from_vantage` -> the linked id does not resolve -> the evidence
/// assertion fails.
///
/// Teardown is not re-asserted here. That `teardown` removes every object is
/// #18's guard (`brings_up_and_tears_down_the_mvp_lab`, which inspects the named
/// networks it owns), and `run_in_lab` calls it on every path with the `Drop`
/// backstop behind it. A global `redstep-` network count would be unsound: the
/// binary's tests run in parallel and each creates such networks, so a before/
/// after delta flakes on a neighbour rather than on this run's teardown.
#[test]
fn run_in_lab_passes_the_boundary_demo() {
    if !linux_docker_available() {
        eprintln!("skipping run_in_lab_passes_the_boundary_demo: no Linux Docker daemon");
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");

        let summary = run_in_lab(&docker, &mvp())
            .await
            .expect("the run against an isolated lab succeeds");

        let run = summary
            .runs
            .iter()
            .find(|r| r.name.ends_with("attacker_cannot_connect_to_db"))
            .expect("the boundary demo ran");
        assert_eq!(
            run.verdict,
            redstep::Verdict::Pass,
            "db is unreachable from the attacker, so the demo passes: {run:?}"
        );
        // The judgement links to a real evidence record for the probe it ran, not
        // a dangling id: resolve it and check it is the vantage probe of db:5432.
        let evidence_id = run
            .judgements
            .iter()
            .find_map(|j| j.evidence)
            .expect("the demo's judgement is linked to evidence");
        let record = summary
            .evidence
            .records()
            .iter()
            .find(|e| e.id == evidence_id)
            .expect("the linked evidence id resolves to a record");
        assert_eq!(
            record.target, "db:5432",
            "the evidence records the probed target"
        );
        assert_eq!(
            record.capability, "tcp_connect_vantage",
            "recorded as a vantage probe, not a host-run connect"
        );
        assert_eq!(report::build(&summary).exit_code, 0, "the report is PASS");
    });
}

/// Guard: a lab whose forbidden pair is connected is refused by the self-check
/// gate before any test runs, so the run returns an error and never a PASS. The
/// lab is stood up with `bring_up`, broken the realistic way (the `db` container
/// attached to the `internet` network too), then handed to `run_in_running_lab`.
/// Mutation: remove the `boundary_self_check` gate in `run_in_running_lab` -> the
/// connected lab runs the demo and returns `Ok` -> the `Err(BoundaryViolated)`
/// assertion fails. (Reordering the gate after the test loop does not flip this:
/// the gate's `?` still returns the error whatever order it runs in; only
/// removing the gate lets the run reach `Ok`.)
#[test]
fn a_connected_lab_is_refused_before_any_test_runs() {
    if !linux_docker_available() {
        eprintln!(
            "skipping a_connected_lab_is_refused_before_any_test_runs: no Linux Docker daemon"
        );
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
        let env = mvp();
        let lab = bring_up(&docker, &env).await.expect("bring up the MVP lab");

        let internet_net = lab
            .networks()
            .iter()
            .find(|n| n.segment() == "internet")
            .expect("internet network")
            .name()
            .to_owned();
        let db_container = lab
            .containers()
            .iter()
            .find(|c| c.workload() == "db")
            .expect("the db workload")
            .name()
            .to_owned();
        docker
            .connect_network(
                &internet_net,
                NetworkConnectRequest {
                    container: db_container,
                    ..Default::default()
                },
            )
            .await
            .expect("connect db to the internet network");

        let result = run_in_running_lab(&docker, &env, &lab).await;
        let _ = lab.teardown().await;

        assert!(
            matches!(&result, Err(RunError::Lab(Error::BoundaryViolated { from, to })) if from == "internet" && to == "internal"),
            "a connected forbidden pair must refuse the run before any test, got {result:?}"
        );
    });
}

/// The assume-breach containment test: from a taken DMZ foothold, the internal
/// database must not be reachable, so the blast radius of a DMZ compromise stops
/// at the `dmz`/`internal` boundary. The observation of `db` is `false` at `Low`
/// (busybox `nc` cannot prove a port closed), so it opts down to
/// `min_confidence(Low)`, exactly like the external demo; the `High` certification
/// that the boundary holds is the self-check the run runs first (ADR-0011), not
/// this probe. In `assume_breach_dmz()` `db` runs a real listener on 5432, so this
/// `false` is the segment isolation blocking a reachable service, not a dead port
/// (RK-008). Registered by the macro and run via the lab-wired runner in BOTH labs
/// of this binary: against `mvp()` too, where `db` is a listener-less stand-in
/// unreachable from the `internet` vantage, so it passes there as well and does not
/// disturb `run_in_lab_passes_the_boundary_demo`.
#[redstep::security_test]
async fn dmz_foothold_cannot_reach_db(ctx: &TestContext) -> redstep::Result<()> {
    let target = ctx.resolve("db:5432")?;
    let recorded = ctx.connect_from_vantage(&target).await?;
    ctx.expect(&recorded)
        .min_confidence(Confidence::Low)
        .to_be(false);
    Ok(())
}

/// Guard (Docker): an assume-breach DMZ foothold is contained from the internal
/// segment, realizing and guarding ADR-0017's assume-breach vantage (#96). Over
/// one brought-up `assume_breach_dmz()` lab, where both `web` (dmz) and `db`
/// (internal) run real listeners:
///
/// 1. the run passes the boundary self-check and `dmz_foothold_cannot_reach_db`
///    verdicts `Pass` (the listening `db` is unreachable from the DMZ vantage,
///    blocked by the segment isolation), and the report exit code is 0;
/// 2. POSITIVE CONTROL: the same foothold DOES reach the DMZ `web:80` listener at
///    `High`, so the probe apparatus and the foothold are live and "cannot reach
///    db" is not a dead probe (RK-008). The control is a direct
///    `connect_from_vantage` against the still-running lab, not a
///    `#[security_test]`: reaching one's own segment is not a finding, and a
///    registered test asserting reachability would also run against `mvp()` (where
///    `web` is a listener-less stand-in in a different segment) and break both this
///    guard's and `run_in_lab_passes_the_boundary_demo`'s `exit_code == 0`.
///
/// Mutations: move the vantage to `internal` -> the listening `db` is now
/// same-segment and reachable -> the containment leg's `Pass` assertion fails (and
/// `web`, now cross-segment, also fails the control); drop the `web` listener ->
/// the positive control reads unreachable -> the control assertion fails; attach
/// `db` to the `dmz` network (as `a_connected_lab_is_refused_before_any_test_runs`
/// does) -> the self-check refuses the run -> `outcome.expect` fails. Dropping the
/// `dmz` -> `internal` boundary does NOT fail this guard (Docker isolates the
/// separate networks regardless), so the declared boundary the self-check rests on
/// is pinned offline by `assume_breach_dmz_declares_the_internal_boundary`.
#[test]
fn assume_breach_dmz_foothold_is_contained() {
    if !linux_docker_available() {
        eprintln!("skipping assume_breach_dmz_foothold_is_contained: no Linux Docker daemon");
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
        let env = assume_breach_dmz();
        let lab = bring_up(&docker, &env)
            .await
            .expect("bring up the assume-breach DMZ lab");

        // The self-check gates the run, then the registered tests run from the DMZ
        // vantage. Its outcome is held until after the positive control, because
        // the control probe below needs the lab still up and a direct caller owns
        // teardown.
        let outcome = run_in_running_lab(&docker, &env, &lab).await;

        // Leg 2, the positive control: a direct probe of the DMZ `web:80` listener
        // from the same vantage, built exactly as `run_in_running_lab` builds a
        // test's context (the vantage segment's network and the environment scope,
        // runner.rs). Captured as a `Result` so teardown runs whatever it returns
        // and a probe error does not pre-empt teardown or the run's own error.
        let control = {
            let scope = Scope::from_environment(&env);
            let vantage = lab
                .networks()
                .iter()
                .find(|n| n.segment() == env.vantage_segment())
                .cloned()
                .expect("the dmz vantage network is in the running lab");
            let control_ctx = TestContext::new_in_lab(scope, docker.clone(), vantage);
            let web = control_ctx
                .resolve("web:80")
                .expect("web:80 resolves in the lab scope");
            control_ctx.connect_from_vantage(&web).await
        };

        let _ = lab.teardown().await;

        // Leg 1 first, so a self-check refusal or a Docker error in the run is the
        // panic the reader sees, not a downstream control error. The run passed the
        // self-check (so it is `Ok`), the containment test passed, and no registered
        // test failed.
        let summary = outcome.expect("the assume-breach run passes the self-check and runs");
        let run = summary
            .runs
            .iter()
            .find(|r| r.name.ends_with("dmz_foothold_cannot_reach_db"))
            .expect("the containment test ran");
        assert_eq!(
            run.verdict,
            redstep::Verdict::Pass,
            "db is unreachable from the DMZ foothold, so containment holds: {run:?}"
        );
        assert_eq!(
            report::build(&summary).exit_code,
            0,
            "every test passes against the assume-breach lab"
        );

        // Leg 2: the foothold really can reach its own segment's listener, so the
        // containment above is a live probe, not a dead one.
        let control = control.expect("the positive-control probe runs");
        assert!(
            control.observation.value,
            "positive control: the DMZ foothold reaches web:80, so 'cannot reach db' is a live probe"
        );
        assert_eq!(
            control.observation.confidence,
            Confidence::High,
            "a reached listener is a High-confidence positive control"
        );
    });
}

/// Guard (offline): `assume_breach_dmz()` declares the `dmz` -> `internal`
/// boundary, places the vantage on `dmz`, and keeps a listening `db` in
/// `internal`. The Docker guard `assume_breach_dmz_foothold_is_contained` cannot
/// catch a dropped boundary, because Docker isolates the separate segment networks
/// regardless of any declared boundary: the containment probe still reads
/// unreachable and the self-check then has nothing to certify, so the whole Docker
/// guard stays green. The declared boundary the self-check rests on is therefore
/// pinned here, with no Docker. Mutations: drop `.boundary("dmz","internal",&[])`
/// -> the boundary assertion fails; move the vantage off `dmz` -> the vantage
/// assertion fails; make `db` a `standin` -> the listener assertion fails (the
/// containment probe would then be a dead port, not a blocked reachable service,
/// RK-008).
#[test]
fn assume_breach_dmz_declares_the_internal_boundary() {
    let env = assume_breach_dmz();
    assert!(
        env.boundaries()
            .iter()
            .any(|b| b.from() == "dmz" && b.to() == "internal" && b.allow().is_empty()),
        "the topology must declare the dmz -> internal membership boundary the self-check certifies"
    );
    assert_eq!(
        env.vantage_segment(),
        "dmz",
        "the foothold is on the dmz segment"
    );
    let db = env
        .workloads()
        .iter()
        .find(|w| w.name() == "db")
        .expect("db is a declared workload");
    assert_eq!(db.segment(), "internal", "db sits behind the boundary");
    assert!(
        matches!(db.kind(), WorkloadKind::Service { .. }),
        "db runs a real listener, so the containment probe tests a reachable service, not a dead port"
    );
}

/// Guard (Docker): network service discovery from the assume-breach DMZ vantage
/// (#111, ATT&CK T1046). `discover_services_from_vantage` over `web:80` (in the
/// vantage's own `dmz` segment, listening) and `db:5432` (in `internal`, across
/// the boundary) enumerates per-target reachability, paired with its target: `web`
/// is reachable at `High`, `db` is not reachable at `Low` (busybox `nc` cannot
/// prove a port closed), each recorded under the discovery technique. So the
/// enumeration distinguishes a service the foothold reaches from one the boundary
/// contains, attributed to the vantage, each with its own confidence.
///
/// It drains the recorded drafts and asserts the capability each bears, because
/// that attribution (the whole point of the technique) is checked by nothing else:
/// the offline `vantage_draft_stamps_the_given_capability` pins the pure helper's
/// echo of a given constant, not which constant this METHOD passes, and the
/// returned `Recorded` does not expose the capability. Mutations: have
/// `discover_services_from_vantage` pass `TCP_CONNECT_VANTAGE` -> the drained-draft
/// capability assertion fails; point the first target across the boundary or stop
/// the `web` listener -> the `web` reachable assertion fails; reverse the result
/// order -> the paired-target assertions fail. Driven through the real `bring_up`.
#[test]
fn discovery_from_the_dmz_vantage_enumerates_reachability() {
    if !linux_docker_available() {
        eprintln!(
            "skipping discovery_from_the_dmz_vantage_enumerates_reachability: no Linux Docker daemon"
        );
        return;
    }
    runtime().block_on(async {
        let docker = Docker::connect_with_local_defaults().expect("connect to Docker");
        let env = assume_breach_dmz();
        let lab = bring_up(&docker, &env)
            .await
            .expect("bring up the assume-breach DMZ lab");

        // Enumerate from the DMZ vantage, over the same lab-bound context the runner
        // builds (the vantage segment's network and the environment scope). Captured
        // (with the drafts it recorded) so teardown runs whatever it returns.
        let (discovered, drafts) = {
            let scope = Scope::from_environment(&env);
            let vantage = lab
                .networks()
                .iter()
                .find(|n| n.segment() == env.vantage_segment())
                .cloned()
                .expect("the dmz vantage network is in the running lab");
            let ctx = TestContext::new_in_lab(scope, docker.clone(), vantage);
            let targets = vec![
                ctx.resolve("web:80")
                    .expect("web:80 resolves in the lab scope"),
                ctx.resolve("db:5432")
                    .expect("db:5432 resolves in the lab scope"),
            ];
            let discovered = ctx.discover_services_from_vantage(&targets).await;
            (discovered, ctx.take_evidence_drafts())
        };

        let _ = lab.teardown().await;

        let discovered = discovered.expect("the discovery enumeration runs");
        assert_eq!(discovered.len(), 2, "one result per target, in input order");
        // The target is paired into each result, in input order.
        assert_eq!(discovered[0].0.host(), "web");
        assert_eq!(discovered[1].0.host(), "db");
        // web:80 is in the vantage's own dmz segment and listening, so reachable.
        assert!(
            discovered[0].1.observation.value,
            "web:80 is reachable from the dmz foothold (its own segment)"
        );
        assert_eq!(
            discovered[0].1.observation.confidence,
            Confidence::High,
            "a reached listener is High-confidence"
        );
        // db:5432 is in internal, across the dmz -> internal boundary, so contained:
        // not reachable, and at Low (never a confident closed).
        assert!(
            !discovered[1].1.observation.value,
            "db:5432 is contained from the dmz foothold (across the boundary)"
        );
        assert_eq!(
            discovered[1].1.observation.confidence,
            Confidence::Low,
            "a non-connect reads Low, not a confident closed"
        );
        // Every recorded draft is attributed to the discovery technique (#111's
        // point), not to a bare connect probe.
        assert_eq!(drafts.len(), 2, "one draft per target");
        for draft in &drafts {
            assert_eq!(
                draft.capability, "network_service_discovery_vantage",
                "discovery stamps its own technique"
            );
        }
    });
}
