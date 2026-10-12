//! A native TCP-connect capability: does a `host:port` accept a connection?
//!
//! This is the `Safe` primitive the boundary demo rests on. Only two outcomes
//! are confident: a connection that opened is reachable (`High`), and a
//! connection the target *refused* (an RST, `ConnectionRefused`) is unreachable
//! (`High`). Everything else is a weak signal and lands at `Low`: a timeout
//! (no reply came) and any other connect error (a DNS failure, a network- or
//! host-unreachable, a local permission or resource error) all mean the probe
//! did not establish that the port is closed, only that no connection was made.
//! Reading any of those as a confident "unreachable" would let an unrelated
//! failure read as "the boundary held" (a false PASS). The oracle requires
//! `High` confidence by default before a verdict rests on a signal (a test opts
//! down explicitly with `min_confidence(Low)`), which is what keeps a `Low`
//! observation out of a confident conclusion.

use std::time::Duration;

use crate::capability::Capability;
use crate::evidence::{EvidenceDraft, Reproduction};
use crate::intensity::Intensity;
use crate::observation::{Confidence, Observation};
use crate::scope::ScopedTarget;

/// How long to wait for a connection before calling it a timeout. Every network
/// action is bounded (docs/rules/perf.md).
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Observe whether a scope-resolved `host:port` accepts a TCP connection.
pub struct TcpConnect {
    target: ScopedTarget,
    timeout: Duration,
}

impl TcpConnect {
    /// Target a scope-resolved address. The `ScopedTarget` argument is the
    /// gate: only the scope resolver produces one, so this cannot be built with
    /// a raw address.
    pub fn new(target: ScopedTarget) -> Self {
        Self {
            target,
            timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Override the connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The connection timeout this capability will use.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Capability for TcpConnect {
    type Value = bool;

    fn name(&self) -> &'static str {
        "tcp_connect"
    }

    fn intensity(&self) -> Intensity {
        Intensity::Safe
    }

    async fn execute(&self) -> crate::Result<(Observation<bool>, EvidenceDraft)> {
        let target = format!("{}:{}", self.target.host(), self.target.port());
        let dial = target.clone();
        let outcome = connect_outcome(self.timeout, async move {
            tokio::net::TcpStream::connect(dial).await.map(|_stream| ())
        })
        .await;

        let observation = classify_connect(outcome);
        let draft = build_draft(
            self.name(),
            target,
            self.intensity(),
            self.timeout,
            &observation,
        );
        Ok((observation, draft))
    }
}

/// What a connection attempt established. Only a completed handshake and an
/// explicit refusal are confident; everything else is ambiguous.
#[derive(Debug, PartialEq, Eq)]
enum ConnectOutcome {
    /// The handshake completed: the port accepts a connection.
    Connected,
    /// The target refused the connection (an RST): the port is closed.
    Refused,
    /// No connection, and no proof the port is closed: a timeout, a DNS or
    /// network failure, a local error. Ambiguous.
    Indeterminate,
}

/// Drive a connect future under a timeout and classify the outcome. Generic
/// over the future, so each outcome is tested with `ready`/`pending` rather
/// than a real socket. Only `ConnectionRefused` is a refusal; every other error
/// kind, like a timeout, is `Indeterminate`, because it does not establish that
/// the port is closed.
async fn connect_outcome<F>(timeout: Duration, connect: F) -> ConnectOutcome
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(())) => ConnectOutcome::Connected,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            ConnectOutcome::Refused
        }
        Ok(Err(_other)) => ConnectOutcome::Indeterminate,
        Err(_elapsed) => ConnectOutcome::Indeterminate,
    }
}

/// Map a connection outcome to a reachability observation. Pure, so the mapping
/// is tested without a socket. Connected and Refused are `High`; Indeterminate
/// (timeout or any non-refusal error) is unreachable at `Low`, so an unrelated
/// failure cannot read as a confident boundary hold.
fn classify_connect(outcome: ConnectOutcome) -> Observation<bool> {
    match outcome {
        ConnectOutcome::Connected => Observation {
            value: true,
            confidence: Confidence::High,
        },
        ConnectOutcome::Refused => Observation {
            value: false,
            confidence: Confidence::High,
        },
        ConnectOutcome::Indeterminate => Observation {
            value: false,
            confidence: Confidence::Low,
        },
    }
}

/// Compose the evidence draft from the observation. Pure, so that the draft
/// mirroring the observation (not a hard-coded value) is testable without a
/// socket. The observed value is erased to a JSON bool so the record stays
/// capability-neutral (Decision D); the reproduction restates the target and the
/// timeout, which together re-run the same connect (Decision V's witness).
fn build_draft(
    capability: &'static str,
    target: String,
    intensity: Intensity,
    timeout: Duration,
    observation: &Observation<bool>,
) -> EvidenceDraft {
    EvidenceDraft {
        capability,
        target: target.clone(),
        intensity,
        observed: serde_json::Value::Bool(observation.value),
        confidence: observation.confidence,
        summary: if observation.value {
            "reachable"
        } else {
            "unreachable"
        }
        .to_owned(),
        reproduction: Reproduction {
            capability: capability.to_owned(),
            target,
            params: serde_json::json!({ "timeout_ms": timeout.as_millis() as u64 }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("current-thread runtime with time builds")
    }

    /// Guard: `connect_outcome` classifies each result, and only a refusal is a
    /// refusal. Mutation: widen the refusal arm to catch any `Err` -> the
    /// PermissionDenied/NotFound cases become Refused -> fails; change the
    /// timeout arm to Connected/Refused -> the pending case fails. This pins the
    /// row-6 rule that a non-refusal error is not a confident closed port.
    #[test]
    fn connect_outcome_classifies_each_result() {
        let rt = time_runtime();
        let long = Duration::from_secs(5);

        assert_eq!(
            rt.block_on(connect_outcome(long, std::future::ready(Ok(())))),
            ConnectOutcome::Connected
        );
        assert_eq!(
            rt.block_on(connect_outcome(
                long,
                std::future::ready(Err(std::io::ErrorKind::ConnectionRefused.into())),
            )),
            ConnectOutcome::Refused
        );
        for other in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::AddrNotAvailable,
        ] {
            assert_eq!(
                rt.block_on(connect_outcome(long, std::future::ready(Err(other.into())))),
                ConnectOutcome::Indeterminate,
                "a {other:?} error is not a refusal"
            );
        }
        assert_eq!(
            rt.block_on(connect_outcome(
                Duration::from_millis(10),
                std::future::pending::<std::io::Result<()>>(),
            )),
            ConnectOutcome::Indeterminate,
            "a connect that never resolves times out"
        );
    }

    /// Guard: the outcome maps to the right reachability and confidence.
    /// Mutation: swap a value, or raise the Indeterminate confidence to High ->
    /// fails. The reachable/unreachable mapping and the weak-signal rule are
    /// pinned here, without a socket.
    #[test]
    fn classify_connect_maps_outcome_to_confidence() {
        assert_eq!(
            classify_connect(ConnectOutcome::Connected),
            Observation {
                value: true,
                confidence: Confidence::High
            }
        );
        assert_eq!(
            classify_connect(ConnectOutcome::Refused),
            Observation {
                value: false,
                confidence: Confidence::High
            }
        );
        assert_eq!(
            classify_connect(ConnectOutcome::Indeterminate),
            Observation {
                value: false,
                confidence: Confidence::Low
            }
        );
    }

    /// Guard: the draft mirrors the observation, including on the decisive Low
    /// path: `observed` tracks the value, `confidence` is not hard-coded, and the
    /// summary matches. Mutation: set `confidence` to a fixed `High`, hard-code
    /// `observed` to `true`, or fix `summary` to `"reachable"` in `build_draft`
    /// -> this fails (the integration tests only reach the reachable/High case,
    /// so they cannot catch it). The reproduction restates the timeout so a
    /// witness can re-run the same connect.
    #[test]
    fn build_draft_mirrors_the_observation() {
        let observation = Observation {
            value: false,
            confidence: Confidence::Low,
        };
        let draft = build_draft(
            "tcp_connect",
            "web:80".to_owned(),
            Intensity::Safe,
            Duration::from_millis(250),
            &observation,
        );
        assert_eq!(draft.capability, "tcp_connect");
        assert_eq!(draft.target, "web:80");
        assert_eq!(draft.intensity, Intensity::Safe);
        assert_eq!(draft.observed, serde_json::Value::Bool(false));
        assert_eq!(draft.confidence, Confidence::Low);
        assert_eq!(draft.summary, "unreachable");
        assert_eq!(draft.reproduction.target, "web:80");
        assert_eq!(draft.reproduction.params["timeout_ms"], 250);
    }

    /// Guard: `execute` against a bound port wires the live observation into the
    /// draft (observed/true, confidence mirrored) with a reproduction that
    /// restates the target. Mutation: have `execute` build the draft from a
    /// constant, or pass a different observation to `build_draft`, than the one it
    /// returns -> the observed value, target, or confidence disagrees -> fails.
    /// This proves the `execute` -> `build_draft` wiring end to end, which the
    /// isolated `build_draft` test cannot.
    #[test]
    fn execute_emits_a_mirrored_draft_for_a_live_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a local port");
        let port = listener.local_addr().expect("local addr").port();
        let spec = format!("127.0.0.1:{port}");

        let scope = crate::scope::Scope::builder()
            .allow(&spec)
            .expect("valid spec")
            .build();
        let target = scope.resolve(&spec).expect("in scope");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime with net builds");
        let (observation, draft) = rt
            .block_on(TcpConnect::new(target).execute())
            .expect("the capability runs");

        assert!(observation.value, "a bound port is reachable");
        assert_eq!(draft.observed, serde_json::Value::Bool(true));
        assert_eq!(draft.target, spec);
        assert_eq!(draft.reproduction.target, spec);
        assert_eq!(draft.confidence, observation.confidence);
    }

    /// Guard: `with_timeout` sets the timeout the capability will use. Mutation:
    /// drop the assignment in `with_timeout` -> the getter returns the default
    /// -> fails.
    #[test]
    fn with_timeout_sets_the_timeout() {
        let scope = crate::scope::Scope::builder()
            .allow("web:80")
            .expect("valid spec")
            .build();
        let target = scope.resolve("web:80").expect("in scope");
        let capability = TcpConnect::new(target).with_timeout(Duration::from_millis(250));
        assert_eq!(capability.timeout(), Duration::from_millis(250));
    }
}
