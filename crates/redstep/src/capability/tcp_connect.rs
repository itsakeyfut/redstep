//! A native TCP-connect capability: does a `host:port` accept a connection?
//!
//! This is the `Safe` primitive the boundary demo rests on. A connection that
//! opens is reachable; one that is refused is unreachable; a connection that
//! times out is treated as unreachable but at `Low` confidence, because a
//! transient timeout is a weak signal and must not read as a confident "the
//! boundary held" (a false PASS). The oracle unit (#4) is what then requires
//! `High` confidence before a verdict rests on it.

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
        let addr = format!("{}:{}", self.target.host(), self.target.port());
        let (connected, timed_out) = connect_flags(self.timeout, async move {
            tokio::net::TcpStream::connect(addr).await.map(|_stream| ())
        })
        .await;

        let observation = classify_connect(connected, timed_out);
        let evidence = Evidence {
            capability: self.name(),
            target: format!("{}:{}", self.target.host(), self.target.port()),
            intensity: self.intensity(),
            reachable: observation.value,
            confidence: observation.confidence,
        };
        Ok((observation, evidence))
    }
}

/// Drive a connect future under a timeout and reduce it to two flags:
/// `(connected, timed_out)`. Generic over the future so the three outcomes are
/// tested with `ready`/`pending` rather than a real socket: a future that
/// resolves `Ok` connected, one that resolves `Err` was refused, and one that
/// never resolves times out.
async fn connect_flags<F>(timeout: Duration, connect: F) -> (bool, bool)
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(())) => (true, false),
        Ok(Err(_io)) => (false, false),
        Err(_elapsed) => (false, true),
    }
}

/// Map a connection outcome to a reachability observation. Pure, so the mapping
/// is tested without a socket.
///
/// A connection that opened is reachable, `High`. A refused connection (no
/// timeout, did not connect) is unreachable, `High`. A timeout is unreachable
/// but `Low`: a weak signal that must not read as a confident boundary hold.
fn classify_connect(connected: bool, timed_out: bool) -> Observation<bool> {
    if connected {
        Observation {
            value: true,
            confidence: Confidence::High,
        }
    } else if timed_out {
        Observation {
            value: false,
            confidence: Confidence::Low,
        }
    } else {
        Observation {
            value: false,
            confidence: Confidence::High,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard: the connection outcome maps to the right reachability and
    /// confidence. Mutation: swap the reachable value, or raise the timeout
    /// confidence to High -> fails. This is where the reachable/unreachable
    /// mapping and the weak-timeout-signal rule are pinned, without a socket.
    fn time_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("current-thread runtime with time builds")
    }

    /// Guard: `connect_flags` reduces each connect outcome to the right flags,
    /// deterministically and without a socket. Mutation: change the timeout arm
    /// to `(false, false)` -> `connect_flags_times_out` fails; swap the Ok/Err
    /// arms -> the connected/refused cases fail. This guards the wiring that a
    /// real socket's timeout feeds `classify_connect`.
    #[test]
    fn connect_flags_reduces_each_outcome() {
        let rt = time_runtime();
        assert_eq!(
            rt.block_on(connect_flags(
                Duration::from_secs(5),
                std::future::ready(Ok(()))
            )),
            (true, false),
            "a connect that resolves Ok is connected"
        );
        assert_eq!(
            rt.block_on(connect_flags(
                Duration::from_secs(5),
                std::future::ready(Err(std::io::ErrorKind::ConnectionRefused.into())),
            )),
            (false, false),
            "a connect that resolves Err was refused, not timed out"
        );
        assert_eq!(
            rt.block_on(connect_flags(
                Duration::from_millis(10),
                std::future::pending::<std::io::Result<()>>(),
            )),
            (false, true),
            "a connect that never resolves times out"
        );
    }

    #[test]
    fn classify_connect_maps_outcome_to_confidence() {
        assert_eq!(
            classify_connect(true, false),
            Observation {
                value: true,
                confidence: Confidence::High
            }
        );
        assert_eq!(
            classify_connect(false, false),
            Observation {
                value: false,
                confidence: Confidence::High
            }
        );
        assert_eq!(
            classify_connect(false, true),
            Observation {
                value: false,
                confidence: Confidence::Low
            }
        );
    }
}
