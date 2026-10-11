//! Integration tests for the native TcpConnect capability against real local
//! ports. They drive the capability through `TestContext::run` on an external
//! crate path, so the public surface and the scope gate are exercised as a
//! user would.
//!
//! Each builds its own current-thread runtime rather than using `#[tokio::test]`
//! (the crate does not enable tokio's macros), which also keeps the scope
//! allowlist built from the ephemeral port the OS just handed out.

use redstep::{Confidence, Intensity, Scope, TcpConnect, TestContext};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime builds")
}

/// Guard: a port with a listener bound observes reachable (High), and emits an
/// evidence record naming the capability, the target, and Safe intensity.
/// Mutation: flip the reachable mapping in `classify_connect` -> this fails.
#[test]
fn tcp_connect_open_port_observes_reachable() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a local port");
    let port = listener.local_addr().expect("local addr").port();
    let spec = format!("127.0.0.1:{port}");

    let scope = Scope::builder().allow(&spec).expect("valid spec").build();
    let ctx = TestContext::new(scope);
    let target = ctx.resolve(&spec).expect("in scope");

    let (observation, evidence) = runtime()
        .block_on(ctx.run(TcpConnect::new(target)))
        .expect("the capability runs");

    assert!(observation.value, "a bound port is reachable");
    assert_eq!(observation.confidence, Confidence::High);
    assert_eq!(evidence.capability, "tcp_connect");
    assert_eq!(evidence.target, spec);
    assert_eq!(evidence.intensity, Intensity::Safe);
    assert!(evidence.reachable);
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

    let (observation, evidence) = runtime()
        .block_on(ctx.run(TcpConnect::new(target)))
        .expect("the capability runs");

    assert!(!observation.value, "a closed port is unreachable");
    assert_eq!(observation.confidence, Confidence::High);
    assert!(!evidence.reachable);
}
