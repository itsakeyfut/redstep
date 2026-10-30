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

use bollard::Docker;

use bollard::models::NetworkConnectRequest;
use bollard::query_parameters::{InspectContainerOptions, InspectNetworkOptions};

use redstep::{
    Confidence, Environment, Error, RunError, Scope, TestContext, boundary_self_check, bring_up,
    report, run_in_lab, run_in_running_lab,
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
/// (`vantage("dmz")`), a listening `web` sits in the DMZ, and `api`/`db` are in
/// `internal` with the `dmz` -> `internal` path blocked by a membership boundary.
/// It is the assume-breach twin of `mvp()`'s external vantage (#96, ADR-0017): the
/// foothold reaches its own segment but is contained from internal. The port-level
/// firewall boundary is a separate sub of #95 and deliberately not used here; this
/// containment rests on the membership boundary and the self-check.
fn assume_breach_dmz() -> Environment {
    Environment::builder()
        .segment("dmz")
        .segment("internal")
        // A listening DMZ host, so the foothold's same-segment reach is a real
        // High-confidence positive control: busybox's default command would exit
        // and leave nothing to connect to, which would read as unreachable.
        .service_cmd(
            "web",
            STANDIN_IMAGE,
            "dmz",
            &[
                "sh",
                "-c",
                "while true; do nc -l -p 80 >/dev/null 2>&1; done",
            ],
        )
        .standin("api", STANDIN_IMAGE, "internal")
        .standin("db", STANDIN_IMAGE, "internal")
        .vantage("dmz")
        .boundary("dmz", "internal", &[])
        .build()
        .expect("the assume-breach DMZ topology is valid")
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
/// macro and run only via the lab-wired runner.
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
/// at the `dmz`/`internal` boundary. `db` is `false` at `Low` (busybox `nc`
/// cannot prove a port closed), so it opts down to `min_confidence(Low)`, exactly
/// like the external demo; the `High` certification that the boundary holds is the
/// self-check the run runs first (ADR-0011), not this probe. Registered by the
/// macro and run only via the lab-wired runner. It also runs against `mvp()` in
/// this binary, where `db` is equally unreachable from the `internet` vantage, so
/// it passes there too and does not disturb `run_in_lab_passes_the_boundary_demo`.
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
/// one brought-up `assume_breach_dmz()` lab:
///
/// 1. the run passes the boundary self-check and `dmz_foothold_cannot_reach_db`
///    verdicts `Pass` (db unreachable from the DMZ vantage), and the report exit
///    code is 0;
/// 2. POSITIVE CONTROL: the same foothold DOES reach the DMZ `web:80` listener at
///    `High`, so "cannot reach db" is a real boundary rather than a dead probe or
///    a missing `nc` (RK-008). The control is a direct `connect_from_vantage`
///    against the still-running lab, not a `#[security_test]`: reaching one's own
///    segment is not a finding, and a registered test asserting reachability would
///    also run against `mvp()` (where `web` is not reachable from `internet`) and
///    break the external demo guard.
///
/// Mutations: move the vantage to `internal`, or drop the `dmz` -> `internal`
/// boundary in `assume_breach_dmz()` -> the foothold reaches db -> the containment
/// leg's `Pass` assertion fails; drop the `web` `service_cmd` listener -> the
/// positive control reads unreachable -> the control assertion fails; break the
/// `dmz` -> `internal` isolation -> the self-check refuses the run -> the
/// `outcome.expect` fails.
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

        // Legs 1 + the self-check: gate on the self-check, then run the registered
        // tests from the DMZ vantage. Held until after the positive control so the
        // lab is still up for the direct probe (a direct caller owns teardown).
        let outcome = run_in_running_lab(&docker, &env, &lab).await;

        // Leg 2, the positive control: a direct probe of the DMZ `web:80` listener
        // from the same vantage, built exactly as `run_in_running_lab` builds a
        // test's context (the vantage segment's network and the environment scope).
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
        let control = control_ctx
            .connect_from_vantage(&web)
            .await
            .expect("the positive-control probe runs");

        let _ = lab.teardown().await;

        // Leg 1: the run passed the self-check (so it is `Ok`) and the containment
        // test passed, and no registered test failed.
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
        // containment above is a real boundary and not a dead probe.
        assert!(
            control.observation.value,
            "positive control: the DMZ foothold reaches web:80, so 'cannot reach db' is a real boundary"
        );
        assert_eq!(
            control.observation.confidence,
            Confidence::High,
            "a reached listener is a High-confidence positive control"
        );
    });
}
