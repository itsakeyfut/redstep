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
//! failure read as "the boundary held" (a false PASS). The oracle unit (#4)
//! requires `High` before a verdict rests on a signal, which is what keeps a
//! `Low` observation out of a confident conclusion.

use std::time::Duration;

use crate::capability::Capability;
use crate::evidence::Evidence;
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

    async fn execute(&self) -> crate::Result<(Observation<bool>, Evidence)> {
        let target = format!("{}:{}", self.target.host(), self.target.port());
        let dial = target.clone();
        let outcome = connect_outcome(self.timeout, async move {
            tokio::net::TcpStream::connect(dial).await.map(|_stream| ())
        })
        .await;

        let observation = classify_connect(outcome);
        let evidence = build_evidence(self.name(), target, self.intensity(), &observation);
        Ok((observation, evidence))
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

/// Compose the evidence record from the observation. Pure, so that the record
/// mirroring the observation (not a hard-coded value) is testable without a
/// socket.
fn build_evidence(
    capability: &'static str,
    target: String,
    intensity: Intensity,
    observation: &Observation<bool>,
) -> Evidence {
    Evidence {
        capability,
        target,
        intensity,
        reachable: observation.value,
        confidence: observation.confidence,
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

    /// Guard: the evidence mirrors the observation, including on the decisive
    /// Low path. Mutation: set `confidence` to a fixed `High` in `build_evidence`
    /// -> this fails (the integration tests only reach High, so they cannot).
    #[test]
    fn build_evidence_mirrors_the_observation() {
        let observation = Observation {
            value: false,
            confidence: Confidence::Low,
        };
        let evidence = build_evidence(
            "tcp_connect",
            "web:80".to_owned(),
            Intensity::Safe,
            &observation,
        );
        assert_eq!(evidence.capability, "tcp_connect");
        assert_eq!(evidence.target, "web:80");
        assert_eq!(evidence.intensity, Intensity::Safe);
        assert!(!evidence.reachable);
        assert_eq!(evidence.confidence, Confidence::Low);
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
