//! Integration tests for the native TcpConnect capability against real local
//! ports. They drive the capability through `TestContext::run` on an external
//! crate path, so the public surface and the scope gate are exercised as a
//! user would.
//!
//! These assert the observation, which is the capability's real job against a
//! real socket. The evidence record's shape is guarded by the unit tests
//! (`build_draft_mirrors_the_observation`, including the decisive Low path, which
//! these cannot reach), and its collection into the run's store by
//! `run_collects_evidence_into_the_store` in `public_api.rs`; the evidence sink
//! is crate-internal, so an external path cannot drain it here.
//!
//! Each builds its own current-thread runtime rather than using `#[tokio::test]`
//! (the crate does not enable tokio's macros), which also keeps the scope
//! allowlist built from the ephemeral port the OS just handed out.

use redstep::{Confidence, Scope, TcpConnect, TestContext};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime builds")
}

/// Guard: a port with a listener bound observes reachable (High). Mutation: flip
/// the reachable mapping in `classify_connect` -> this fails.
#[test]
fn tcp_connect_open_port_observes_reachable() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a local port");
    let port = listener.local_addr().expect("local addr").port();
    let spec = format!("127.0.0.1:{port}");

    let scope = Scope::builder().allow(&spec).expect("valid spec").build();
    let ctx = TestContext::new(scope);
    let target = ctx.resolve(&spec).expect("in scope");

    let recorded = runtime()
        .block_on(ctx.run(TcpConnect::new(target)))
        .expect("the capability runs");

    assert!(recorded.observation.value, "a bound port is reachable");
    assert_eq!(recorded.observation.confidence, Confidence::High);
}

/// Guard: a port with no listener observes unreachable (High, a refusal).
/// Mutation: flip the reachable mapping -> this fails.
#[test]
fn tcp_connect_closed_port_observes_unreachable() {
    // Bind to claim an ephemeral port, then drop it so the port is closed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a local port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    let spec = format!("127.0.0.1:{port}");

    let scope = Scope::builder().allow(&spec).expect("valid spec").build();
    let ctx = TestContext::new(scope);
    let target = ctx.resolve(&spec).expect("in scope");

    let recorded = runtime()
        .block_on(ctx.run(TcpConnect::new(target)))
        .expect("the capability runs");

    assert!(!recorded.observation.value, "a closed port is unreachable");
    assert_eq!(recorded.observation.confidence, Confidence::High);
}
