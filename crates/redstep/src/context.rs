//! The entry point a security test is handed.
//!
//! It holds the scope and offers resolution, a bare assertion (`check`),
//! running a capability (`run`), and declaring an expectation over an
//! observation (`expect`, the oracle entry). It records each expectation's
//! [`Judgement`] in an interior-mutable sink the runner drains per test; a
//! capability *registry* (the plugin side of Decision B) and the *evidence*
//! sink (Decision D, recording the evidence record rather than returning it)
//! are still later.
//!
//! A test holds `&TestContext` (the `#[security_test]` signature and
//! `registry::TestFn` both take a shared reference), so the sink records
//! through a shared `&self` and is interior-mutable (a `RefCell`; a `Mutex`
//! only if tests ever run concurrently, which the runner's sequential model
//! rules out). A `RefCell` borrow must not be held across an `.await`:
//! `record` is borrow / push / drop, with no await in between.

use std::cell::RefCell;
use std::fmt::Debug;

use crate::capability::Capability;
use crate::error::{Error, Result};
use crate::evidence::Evidence;
use crate::expectation::{Expectation, Judgement, judge};
use crate::intensity::Intensity;
use crate::observation::{Confidence, Observation};
use crate::scope::{Scope, ScopedTarget};
use crate::verdict::Verdict;

/// What a `#[security_test]` receives: `async fn NAME(ctx: &TestContext) -> redstep::Result<()>`.
pub struct TestContext {
    scope: Scope,
    judgements: RefCell<Vec<Judgement>>,
}

impl TestContext {
    /// Build a context over a resolved scope. The runner builds one per test;
    /// a test constructs one directly.
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            judgements: RefCell::new(Vec::new()),
        }
    }

    /// Resolve a `host:port` target through the scope gate. An out-of-scope or
    /// malformed target is an error before any action (docs/rules/security.md
    /// section 2).
    pub fn resolve(&self, spec: &str) -> Result<ScopedTarget> {
        self.scope.resolve(spec)
    }

    /// A bare boolean assertion: `Ok(())` when the condition holds,
    /// [`Error::Check`] otherwise (which stops the test and verdicts it `Fail`).
    /// Use [`expect`](Self::expect) for an assertion over an `Observation`; this
    /// is for a plain condition that is not an observation.
    pub fn check(&self, condition: bool, message: &str) -> Result<()> {
        if condition {
            Ok(())
        } else {
            Err(Error::Check(message.to_owned()))
        }
    }

    /// Declare an expectation over an observation. The oracle judges it, records
    /// the [`Judgement`] (the runner aggregates the recorded judgements into the
    /// test's verdict), and returns the [`Verdict`]. The body continues, so
    /// several expectations accumulate (See Decision J).
    ///
    /// ```ignore
    /// let verdict = ctx.expect(&observation).min_confidence(Confidence::High).to_be(false);
    /// ```
    pub fn expect<'a, T>(&'a self, observation: &'a Observation<T>) -> ExpectationBuilder<'a, T> {
        ExpectationBuilder {
            ctx: self,
            observation,
            min_confidence: Confidence::Low,
        }
    }

    /// Record a judgement in the sink. Borrow, push, drop: no await is held
    /// across the borrow.
    fn record(&self, judgement: Judgement) {
        self.judgements.borrow_mut().push(judgement);
    }

    /// Drain the judgements recorded during one test. The runner calls this
    /// after the test body to aggregate them into the verdict.
    pub(crate) fn take_judgements(&self) -> Vec<Judgement> {
        std::mem::take(&mut self.judgements.borrow_mut())
    }

    /// Run a capability and return its observation and evidence.
    ///
    /// This is the intended invocation path: it checks the intensity as a value
    /// and refuses anything but `Safe`, because the authorization and isolation
    /// proof the higher rungs require are not built yet (See Decision F). The
    /// check lives here rather than in the type system: `Capability::execute` is
    /// a public trait method a hand-written capability could call directly, so
    /// the gate is a runtime check this one place holds. Making it unbypassable
    /// (sealing the trait, a crate-private `execute`) is scheduled before the
    /// first non-Safe capability lands.
    ///
    /// The shipped [`TcpConnect`](crate::TcpConnect) holds a
    /// [`ScopedTarget`] (only the resolver produces one), so for it the scope
    /// gate is type-enforced; the trait does not require that of every
    /// capability, so that guarantee is per-capability, not trait-wide.
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

/// Builds an expectation over an observation and judges it. Returned by
/// [`TestContext::expect`]; `min_confidence` is optional (default: accept any),
/// and `to_be` is the terminal that judges, records the judgement, and returns
/// the verdict.
pub struct ExpectationBuilder<'a, T> {
    ctx: &'a TestContext,
    observation: &'a Observation<T>,
    min_confidence: Confidence,
}

impl<'a, T: PartialEq + Debug> ExpectationBuilder<'a, T> {
    /// Require at least this confidence; a weaker observation is `Inconclusive`.
    pub fn min_confidence(mut self, minimum: Confidence) -> Self {
        self.min_confidence = minimum;
        self
    }

    /// Expect the observed value to be `expected`. Judges, records the
    /// judgement, and returns the verdict.
    pub fn to_be(self, expected: T) -> Verdict {
        let expectation = Expectation::to_be(expected).min_confidence(self.min_confidence);
        let judgement = judge(self.observation, &expectation);
        let verdict = judgement.verdict;
        self.ctx.record(judgement);
        verdict
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

    /// An Aggressive capability that panics if executed.
    struct Aggressive;

    impl Capability for Aggressive {
        type Value = ();

        fn name(&self) -> &'static str {
            "aggressive_stub"
        }

        fn intensity(&self) -> Intensity {
            Intensity::Aggressive
        }

        async fn execute(&self) -> Result<(Observation<()>, Evidence)> {
            panic!("a refused capability must not execute");
        }
    }

    /// Guard: `run` refuses a Controlled capability without executing it, and
    /// reports the intensity it saw. Mutation: drop the intensity check -> the
    /// panicking stub runs and the test fails; hard-code `got` -> the pair of
    /// this and `aggressive_capability_is_refused` disagree, so one fails.
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

    /// Guard: Aggressive is refused too, not only Controlled. Mutation: narrow
    /// the gate to refuse only Controlled (`intensity() == Controlled`) -> the
    /// Aggressive stub runs, panics, and this fails. Without it the gate could
    /// let the most dangerous rung through.
    #[test]
    fn aggressive_capability_is_refused() {
        let ctx = TestContext::new(Scope::default());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");
        let result = runtime.block_on(ctx.run(Aggressive));
        assert!(matches!(
            result,
            Err(Error::IntensityRefused {
                got: Intensity::Aggressive
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
