//! The entry point a security test is handed.
//!
//! It holds the scope and offers resolution, a bare assertion (`check`),
//! running a capability (`run`), and declaring an expectation over an
//! observation (`expect`, the oracle entry). It records each expectation's
//! [`Judgement`] and each capability execution's [`EvidenceDraft`] in two
//! interior-mutable sinks the runner drains per test; a capability *registry*
//! (the plugin side of Decision B) is still later.
//!
//! A test holds `&TestContext` (the `#[security_test]` signature and
//! `registry::TestFn` both take a shared reference), so the sinks record
//! through a shared `&self` and are interior-mutable (a `RefCell`; a `Mutex`
//! only if tests ever run concurrently, which the runner's sequential model
//! rules out). A `RefCell` borrow must not be held across an `.await`:
//! `record` and the evidence push are borrow / push / drop, with no await in
//! between.

use std::cell::RefCell;
use std::fmt::Debug;

use crate::capability::Capability;
use crate::error::{Error, Result};
use crate::evidence::{DraftRef, EvidenceDraft};
use crate::expectation::{Expectation, Judgement, judge};
use crate::intensity::Intensity;
use crate::observation::{Confidence, Observation};
use crate::scope::{Scope, ScopedTarget};
use crate::verdict::Verdict;

/// What a `#[security_test]` receives: `async fn NAME(ctx: &TestContext) -> redstep::Result<()>`.
pub struct TestContext {
    scope: Scope,
    /// Each recorded judgement with the per-test reference to the evidence it
    /// judged, if any. The runner resolves the reference to an
    /// [`EvidenceId`](crate::EvidenceId) (issue #14); a bare `check` carries
    /// `None`.
    judgements: RefCell<Vec<(Judgement, Option<DraftRef>)>>,
    evidence_drafts: RefCell<Vec<EvidenceDraft>>,
}

impl TestContext {
    /// Build a context over a resolved scope. The runner builds one per test;
    /// a test constructs one directly.
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            judgements: RefCell::new(Vec::new()),
            evidence_drafts: RefCell::new(Vec::new()),
        }
    }

    /// Resolve a `host:port` target through the scope gate. An out-of-scope or
    /// malformed target is an error before any action (docs/rules/security.md
    /// section 2).
    pub fn resolve(&self, spec: &str) -> Result<ScopedTarget> {
        self.scope.resolve(spec)
    }

    /// A bare boolean assertion, for a plain condition that is not an
    /// observation: records a `Pass` judgement when it holds and a `Fail`
    /// (returning [`Error::Check`], which stops the test) when it does not. It
    /// is confidence-blind, so a weak signal gets a confident verdict; use
    /// [`expect`](Self::expect) for anything observed, where the confidence gate
    /// applies. A test that records no judgement at all is `Inconclusive`, so a
    /// passing `check` is what makes a check-only test `Pass`.
    pub fn check(&self, condition: bool, message: &str) -> Result<()> {
        let verdict = if condition {
            Verdict::Pass
        } else {
            Verdict::Fail
        };
        self.record(
            Judgement {
                verdict,
                expected: "condition holds".to_owned(),
                actual: message.to_owned(),
                confidence: Confidence::High,
                evidence: None,
            },
            // A bare check came from no capability, so it rests on no evidence.
            None,
        );
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
    /// Accepts both what [`run`](Self::run) returns ([`Observed`], which links the
    /// judgement to its evidence) and a bare [`Observation`] (a hand-built or
    /// non-capability signal, which links to nothing), through the [`Judged`]
    /// seam. The evidence reference rides on `Observed`, not on the pure
    /// `Observation` (Decision J, issue #14).
    ///
    /// ```ignore
    /// let observed = ctx.run(capability).await?;
    /// let verdict = ctx.expect(&observed).to_be(false);                      // requires High by default
    /// let verdict = ctx.expect(&observed).min_confidence(Confidence::Low).to_be(false);  // opt down
    /// ```
    pub fn expect<'a, T, J: Judged<T>>(&'a self, judged: &'a J) -> ExpectationBuilder<'a, T> {
        ExpectationBuilder {
            ctx: self,
            observation: judged.observation(),
            evidence: judged.evidence(),
            min_confidence: Confidence::High,
        }
    }

    /// Record a judgement, with the per-test reference to the evidence it judged
    /// (if any), in the sink. Borrow, push, drop: no await is held across the
    /// borrow.
    fn record(&self, judgement: Judgement, evidence: Option<DraftRef>) {
        self.judgements.borrow_mut().push((judgement, evidence));
    }

    /// Drain the judgements recorded during one test, each with its per-test
    /// evidence reference. The runner calls this after the test body to aggregate
    /// them into the verdict and resolve the reference to an `EvidenceId`.
    pub(crate) fn take_judgements(&self) -> Vec<(Judgement, Option<DraftRef>)> {
        std::mem::take(&mut self.judgements.borrow_mut())
    }

    /// Drain the evidence drafts recorded during one test, in execution order.
    /// The runner calls this after the test body and appends each to the run's
    /// [`EvidenceStore`](crate::EvidenceStore), which mints the
    /// [`Evidence`](crate::Evidence) and assigns the ids (Decision D). It returns
    /// drafts, not records: only the store gives a record its id and timestamp.
    pub(crate) fn take_evidence_drafts(&self) -> Vec<EvidenceDraft> {
        std::mem::take(&mut self.evidence_drafts.borrow_mut())
    }

    /// Run a capability and return its [`Observed`] result, recording one
    /// evidence draft.
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
    /// On a successful execution the capability's [`EvidenceDraft`] is recorded in
    /// the evidence sink and `run` returns an [`Observed`] that carries the
    /// observation the test asserts on and a per-test reference to that draft.
    /// Passing the `Observed` to [`expect`](Self::expect) links the resulting
    /// judgement to the evidence; the runner resolves the reference to an
    /// [`EvidenceId`](crate::EvidenceId) when it drains the drafts into the store
    /// (Decision D, issue #14). An `execute` that errors records nothing, because
    /// the draft is the product of a completed action. The shipped
    /// [`TcpConnect`](crate::TcpConnect) holds a [`ScopedTarget`] (only the
    /// resolver produces one), so for it the scope gate is type-enforced; the
    /// trait does not require that of every capability, so that guarantee is
    /// per-capability, not trait-wide.
    pub async fn run<C: Capability>(&self, capability: C) -> Result<Observed<C::Value>> {
        if capability.intensity() != Intensity::Safe {
            return Err(Error::IntensityRefused {
                got: capability.intensity(),
            });
        }
        let (observation, draft) = capability.execute().await?;
        // Borrow / push / drop, with no await across the borrow. The draft's
        // per-test index is its position in the sink, which the runner offsets by
        // the test's base id to resolve the run-scoped `EvidenceId`.
        let evidence = {
            let mut drafts = self.evidence_drafts.borrow_mut();
            let index = drafts.len();
            drafts.push(draft);
            DraftRef::new(index)
        };
        Ok(Observed {
            observation,
            evidence,
        })
    }
}

/// What [`TestContext::run`] returns: the capability's [`Observation`] and a
/// per-test reference to the evidence it produced. Passing it to
/// [`expect`](TestContext::expect) links the judgement to that evidence
/// automatically. The reference rides here, not on the pure `Observation`, so the
/// observation stays a plain signal and only a capability's result carries a link
/// (Decision J, issue #14). Only `run` constructs one.
pub struct Observed<T> {
    /// The signal the capability observed.
    pub observation: Observation<T>,
    evidence: DraftRef,
}

/// The input [`expect`](TestContext::expect) accepts: an [`Observed`] result,
/// which links its judgement to evidence, or a bare [`Observation`], which does
/// not. Sealed, so the only implementors are these two: it is an internal seam
/// for `expect`, not an extension point.
pub trait Judged<T>: sealed::Sealed {
    /// The observation to judge.
    fn observation(&self) -> &Observation<T>;
    /// The evidence the observation came from, if any.
    fn evidence(&self) -> Option<DraftRef>;
}

impl<T> Judged<T> for Observation<T> {
    fn observation(&self) -> &Observation<T> {
        self
    }
    fn evidence(&self) -> Option<DraftRef> {
        None
    }
}

impl<T> Judged<T> for Observed<T> {
    fn observation(&self) -> &Observation<T> {
        &self.observation
    }
    fn evidence(&self) -> Option<DraftRef> {
        Some(self.evidence)
    }
}

mod sealed {
    use crate::observation::Observation;

    pub trait Sealed {}
    impl<T> Sealed for Observation<T> {}
    impl<T> Sealed for super::Observed<T> {}
}

/// Builds an expectation over an observation and judges it. Returned by
/// [`TestContext::expect`]; `min_confidence` is optional (default: require
/// `High`), and `to_be` is the terminal that judges, records the judgement, and
/// returns the verdict.
///
/// `#[must_use]`: a builder dropped without calling `to_be` records nothing, so
/// a forgotten terminal would silently assert nothing. The warning turns that
/// into a compile-time catch rather than a vacuous `Inconclusive`.
#[must_use = "call .to_be(expected) to judge and record the expectation"]
pub struct ExpectationBuilder<'a, T> {
    ctx: &'a TestContext,
    observation: &'a Observation<T>,
    evidence: Option<DraftRef>,
    min_confidence: Confidence,
}

impl<'a, T: PartialEq + Debug> ExpectationBuilder<'a, T> {
    /// Require at least this confidence; a weaker observation is `Inconclusive`.
    pub fn min_confidence(mut self, minimum: Confidence) -> Self {
        self.min_confidence = minimum;
        self
    }

    /// Expect the observed value to be `expected`. Judges, records the judgement
    /// with the reference to the evidence it judged (if the observation came from
    /// a capability), and returns the verdict.
    pub fn to_be(self, expected: T) -> Verdict {
        let expectation = Expectation::to_be(expected).min_confidence(self.min_confidence);
        let judgement = judge(self.observation, &expectation);
        let verdict = judgement.verdict;
        self.ctx.record(judgement, self.evidence);
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

        async fn execute(&self) -> Result<(Observation<()>, EvidenceDraft)> {
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

        async fn execute(&self) -> Result<(Observation<()>, EvidenceDraft)> {
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

    /// A Safe stub capability that observes a reachable target, for the run path.
    struct AlwaysReachable;
    impl Capability for AlwaysReachable {
        type Value = bool;
        fn name(&self) -> &'static str {
            "always_reachable_stub"
        }
        fn intensity(&self) -> Intensity {
            Intensity::Safe
        }
        async fn execute(&self) -> Result<(Observation<bool>, EvidenceDraft)> {
            Ok((
                Observation {
                    value: true,
                    confidence: Confidence::High,
                },
                EvidenceDraft {
                    capability: self.name(),
                    target: "stub:0".to_owned(),
                    intensity: self.intensity(),
                    observed: serde_json::Value::Bool(true),
                    confidence: Confidence::High,
                    summary: "reachable".to_owned(),
                    reproduction: crate::evidence::Reproduction {
                        capability: self.name().to_owned(),
                        target: "stub:0".to_owned(),
                        params: serde_json::json!({}),
                    },
                },
            ))
        }
    }

    /// Guard: a Safe capability is run and its observation is returned in the
    /// `Observed` result. Mutation: make `run` refuse Safe too -> this fails.
    #[test]
    fn safe_capability_runs() {
        let ctx = TestContext::new(Scope::default());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");
        let observed = runtime
            .block_on(ctx.run(AlwaysReachable))
            .expect("a Safe capability runs");
        assert!(observed.observation.value);
    }

    /// Guard: `run` records exactly one evidence draft per execution, mirroring
    /// the capability's result, and `take_evidence_drafts` drains it. Mutation:
    /// make `run` skip the `evidence_drafts.push`, or push twice -> the count is
    /// not 1 -> fails. This pins the "exactly one record per execution" criterion
    /// before the runner collects it.
    #[test]
    fn run_records_exactly_one_evidence_draft() {
        let ctx = TestContext::new(Scope::default());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");
        runtime
            .block_on(ctx.run(AlwaysReachable))
            .expect("a Safe capability runs");

        let drafts = ctx.take_evidence_drafts();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].capability, "always_reachable_stub");
        assert_eq!(drafts[0].observed, serde_json::Value::Bool(true));
        // Drained, not left behind: a second drain is empty.
        assert!(ctx.take_evidence_drafts().is_empty());
    }

    /// Guard: expecting over a capability's `Observed` result carries the per-test
    /// reference to its draft into the recorded judgement, while a bare
    /// `Observation` and a `check` carry none. Mutation: make `Observed`'s
    /// `Judged::evidence` return `None` -> the run's judgement loses its reference
    /// -> fails; make `Observation`'s return `Some(..)`, or make `check` record a
    /// reference -> a link appears where there is no evidence -> fails. This is
    /// the link at the `ExpectationBuilder` seam, before the runner resolves it.
    #[test]
    fn expect_over_a_run_links_the_judgement_to_its_draft() {
        let ctx = TestContext::new(Scope::default());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");

        let observed = runtime
            .block_on(ctx.run(AlwaysReachable))
            .expect("a Safe capability runs");
        ctx.expect(&observed).to_be(true);
        // A hand-built observation came from no capability.
        let raw = Observation {
            value: true,
            confidence: Confidence::High,
        };
        ctx.expect(&raw).to_be(true);
        ctx.check(true, "holds").expect("the check passes");

        let pairs = ctx.take_judgements();
        assert_eq!(pairs.len(), 3);
        assert_eq!(
            pairs[0].1.map(|r| r.index()),
            Some(0),
            "the run's judgement references its draft"
        );
        assert_eq!(pairs[1].1, None, "a raw observation references no evidence");
        assert_eq!(pairs[2].1, None, "a check references no evidence");
    }
}
