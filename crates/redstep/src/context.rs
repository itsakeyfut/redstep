//! The entry point a security test is handed.
//!
//! For the runner MVP it holds the scope and offers resolution, a minimal
//! assertion, and running a capability. A capability *registry* (the plugin
//! side of Decision B) and the evidence *sink* (Decision D, recording into the
//! context rather than returning the record) are later; `run` returns the
//! evidence for now.
//!
//! A test holds `&TestContext` (the `#[security_test]` signature and
//! `registry::TestFn` both take a shared reference), so the evidence sink, when
//! it lands, records through a shared `&self` and must be interior-mutable
//! (a `RefCell`; a `Mutex` only if tests ever run concurrently, which the
//! runner's sequential model rules out). A `RefCell` borrow must not be held
//! across an `.await`, or a capability that records mid-await re-enters the
//! borrow and panics. Keep a record as borrow / push / drop.

use crate::capability::Capability;
use crate::error::{Error, Result};
use crate::evidence::Evidence;
use crate::intensity::Intensity;
use crate::observation::Observation;
use crate::scope::{Scope, ScopedTarget};

/// What a `#[security_test]` receives: `async fn NAME(ctx: &TestContext) -> redstep::Result<()>`.
pub struct TestContext {
    scope: Scope,
}

impl TestContext {
    /// Build a context over a resolved scope. The runner builds one per run;
    /// a test constructs one directly.
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    /// Resolve a `host:port` target through the scope gate. An out-of-scope or
    /// malformed target is an error before any action (docs/rules/security.md
    /// section 2).
    pub fn resolve(&self, spec: &str) -> Result<ScopedTarget> {
        self.scope.resolve(spec)
    }

    /// The minimal assertion for the runner MVP: `Ok(())` when the condition
    /// holds, [`Error::Check`] otherwise. The verdict oracle (Decision J)
    /// replaces this with Observation and Expectation; it exists now so a test
    /// can fail as an `Err` rather than a panic.
    pub fn check(&self, condition: bool, message: &str) -> Result<()> {
        if condition {
            Ok(())
        } else {
            Err(Error::Check(message.to_owned()))
        }
    }

    /// Run a capability and return its observation and evidence.
    ///
    /// This is the one invocation path. It checks the intensity as a value
    /// before executing and refuses anything but `Safe`, because the
    /// authorization and isolation proof the higher rungs require are not built
    /// yet (See Decision F). The capability already holds a
    /// [`ScopedTarget`], so the scope gate is enforced by the type: this cannot
    /// be handed a raw address.
    pub async fn run<C: Capability>(
        &self,
        capability: C,
    ) -> Result<(Observation<C::Value>, Evidence)> {
        if capability.intensity() != Intensity::Safe {
            return Err(Error::IntensityRefused {
                got: capability.intensity(),
            });
        }
        capability.execute().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::Confidence;

    /// A capability that is not `Safe` and panics if executed, so a test can
    /// prove the intensity gate refuses it before it runs.
    struct NonSafe;

    impl Capability for NonSafe {
        type Value = ();

        fn name(&self) -> &'static str {
            "non_safe_stub"
        }

        fn intensity(&self) -> Intensity {
            Intensity::Controlled
        }

        async fn execute(&self) -> Result<(Observation<()>, Evidence)> {
            panic!("a refused capability must not execute");
        }
    }

    /// Guard: `run` refuses a non-Safe capability and does not execute it.
    /// Mutation: drop the intensity check in `run` -> `execute` runs, panics,
    /// and the test fails. The panicking stub is what proves "does not execute".
    #[test]
    fn non_safe_capability_is_refused() {
        let ctx = TestContext::new(Scope::default());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");
        let result = runtime.block_on(ctx.run(NonSafe));
        assert!(matches!(
            result,
            Err(Error::IntensityRefused {
                got: Intensity::Controlled
            })
        ));
    }

    /// Guard: a Safe capability is run and its observation and evidence are
    /// returned. Mutation: make `run` refuse Safe too -> this fails.
    #[test]
    fn safe_capability_runs() {
        struct AlwaysReachable;
        impl Capability for AlwaysReachable {
            type Value = bool;
            fn name(&self) -> &'static str {
                "always_reachable_stub"
            }
            fn intensity(&self) -> Intensity {
                Intensity::Safe
            }
            async fn execute(&self) -> Result<(Observation<bool>, Evidence)> {
                Ok((
                    Observation {
                        value: true,
                        confidence: Confidence::High,
                    },
                    Evidence {
                        capability: self.name(),
                        target: "stub:0".to_owned(),
                        intensity: self.intensity(),
                        reachable: true,
                        confidence: Confidence::High,
                    },
                ))
            }
        }

        let ctx = TestContext::new(Scope::default());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");
        let (observation, evidence) = runtime
            .block_on(ctx.run(AlwaysReachable))
            .expect("a Safe capability runs");
        assert!(observation.value);
        assert_eq!(evidence.capability, "always_reachable_stub");
    }
}
