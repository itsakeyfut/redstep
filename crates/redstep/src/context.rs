//! The entry point a security test is handed.
//!
//! It holds the scope and offers resolution, a bare assertion (`check`),
//! running a capability (`run`, which returns a [`Recorded`]), and declaring an
//! expectation over an observation (`expect`, the oracle entry). It records each
//! expectation's [`Judgement`] and each capability execution's [`EvidenceDraft`]
//! in two interior-mutable sinks the runner drains per test; expecting over a
//! `Recorded` carries a reference to that execution's draft into the judgement,
//! which the runner resolves to an evidence id (issue #14). A capability
//! *registry* (the plugin side of ADR-0002) is still later.
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
use std::time::Duration;

use bollard::Docker;

use crate::capability::{Capability, IntensityCleared};
use crate::error::{Error, Result};
use crate::evidence::{DraftRef, EvidenceDraft};
use crate::expectation::{Diagnostic, Expectation, Judgement, judge};
use crate::observation::{Confidence, Observation};
use crate::orchestrator::{
    HTTP_IDOR_VANTAGE, HTTP_PATH_TRAVERSAL_VANTAGE, HTTP_SQLI_VANTAGE, LabNetwork,
    http_witness_exploit_from, ssrf_exploit_from, ssrf_token, tcp_reachable_from,
};
use crate::scope::{Scope, ScopedTarget};
use crate::verdict::Verdict;

/// The connect timeout for a vantage reachability probe ([`TestContext::connect_from_vantage`]),
/// matching [`TcpConnect`](crate::TcpConnect)'s host-run default. Every network
/// action is bounded (docs/rules/perf.md).
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// What a `#[security_test]` receives: `async fn NAME(ctx: &TestContext) -> redstep::Result<()>`.
pub struct TestContext {
    scope: Scope,
    /// The attacker's vantage in a running lab, when the run is lab-wired
    /// ([`run_in_lab`](crate::run_in_lab)). `None` for a host-in-process run
    /// (the `--allow` path): [`connect_from_vantage`](Self::connect_from_vantage) needs it, [`run`](Self::run)
    /// does not. It is what lets a capability act from inside the lab rather than
    /// from the host, which reaches every segment and so cannot observe a
    /// boundary (#28, ADR-0003).
    lab: Option<VantageBinding>,
    /// Each recorded judgement with the per-test reference to the evidence it
    /// judged, if any. The reference sits *beside* the `Judgement` rather than in
    /// it because `Judgement.evidence` is a run-scoped [`EvidenceId`](crate::EvidenceId)
    /// the store does not assign until the runner drains the drafts; the runner
    /// resolves this per-test reference to that id then (issue #14). A bare
    /// `check` carries `None`.
    judgements: RefCell<Vec<(Judgement, Option<DraftRef>)>>,
    evidence_drafts: RefCell<Vec<EvidenceDraft>>,
}

/// The attacker's vantage bound to a lab-wired run: the Docker handle and the
/// network of the vantage segment, from which [`TestContext::connect_from_vantage`] drives a
/// probe. Both are cheap to clone (a `Docker` is an `Arc` handle), so the runner
/// builds one per test.
struct VantageBinding {
    docker: Docker,
    vantage_network: LabNetwork,
}

impl TestContext {
    /// Build a context over a resolved scope, with no lab bound (the
    /// host-in-process path). The runner builds one per test; a test constructs
    /// one directly. [`connect_from_vantage`](Self::connect_from_vantage) is unavailable on such a context.
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            lab: None,
            judgements: RefCell::new(Vec::new()),
            evidence_drafts: RefCell::new(Vec::new()),
        }
    }

    /// Build a context bound to a running lab's attacker vantage, so
    /// [`connect_from_vantage`](Self::connect_from_vantage) can drive a probe from inside the lab. The lab-wired
    /// runner ([`run_in_lab`](crate::run_in_lab)) builds one per test from the
    /// vantage segment's [`LabNetwork`] (#28).
    pub fn new_in_lab(scope: Scope, docker: Docker, vantage_network: LabNetwork) -> Self {
        Self {
            scope,
            lab: Some(VantageBinding {
                docker,
                vantage_network,
            }),
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
        // The built-in check produces the FAIL diagnostic (ADR-0009); a bare
        // check knows only its own condition, so the cause restates it.
        let diagnostic = (!condition).then(|| Diagnostic {
            probable_cause: format!("the asserted condition did not hold: {message}"),
            remediation: "review the condition and the state it checks".to_owned(),
        });
        self.record(
            Judgement {
                verdict,
                expected: "condition holds".to_owned(),
                actual: message.to_owned(),
                confidence: Confidence::High,
                evidence: None,
                diagnostic,
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
    /// several expectations accumulate (See ADR-0010).
    ///
    /// Accepts both what [`run`](Self::run) returns ([`Recorded`], which links the
    /// judgement to its evidence) and a bare [`Observation`] (a hand-built or
    /// non-capability signal, which links to nothing), through the [`Expectable`]
    /// seam. The evidence reference rides on `Recorded`, not on the pure
    /// `Observation` (ADR-0010, issue #14). A `Recorded` must be judged on the
    /// same context that produced it; see [`Recorded`].
    ///
    /// ```ignore
    /// let recorded = ctx.run(capability).await?;
    /// let verdict = ctx.expect(&recorded).to_be(false);                      // requires High by default
    /// let verdict = ctx.expect(&recorded).min_confidence(Confidence::Low).to_be(false);  // opt down
    /// ```
    pub fn expect<'a, T, S: Expectable<T>>(&'a self, subject: &'a S) -> ExpectationBuilder<'a, T> {
        ExpectationBuilder {
            ctx: self,
            observation: subject.observation(),
            draft_ref: subject.draft_ref(),
            diagnostic: subject.diagnostic(),
            min_confidence: Confidence::High,
        }
    }

    /// Record a judgement, with the per-test reference to the evidence it judged
    /// (if any), in the sink. Borrow, push, drop: no await is held across the
    /// borrow.
    fn record(&self, judgement: Judgement, draft_ref: Option<DraftRef>) {
        self.judgements.borrow_mut().push((judgement, draft_ref));
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
    /// [`Evidence`](crate::Evidence) and assigns the ids (ADR-0004). It returns
    /// drafts, not records: only the store gives a record its id and timestamp.
    pub(crate) fn take_evidence_drafts(&self) -> Vec<EvidenceDraft> {
        std::mem::take(&mut self.evidence_drafts.borrow_mut())
    }

    /// Run a capability and return its [`Recorded`] result, recording one
    /// evidence draft.
    ///
    /// This is the gate seam: it calls `IntensityCleared::issue`, which refuses
    /// anything but `Safe` (the authorization and isolation proof the higher
    /// rungs require are not built yet, See ADR-0006), and the resulting
    /// [`IntensityCleared`] is what `Capability::execute` requires. `execute`
    /// cannot be reached without a token, and nothing outside the crate can mint
    /// one or implement a capability, so the gate is compiler-held against
    /// external code. In-crate, that `run` mints the token from the capability's
    /// *own* intensity is this seam's convention, not a compiler fact (the token
    /// is not bound to the capability); it is guarded by the refusal tests below,
    /// and binding it is deferred to the first non-`Safe` capability (#9).
    ///
    /// On a successful execution the capability's [`EvidenceDraft`] is recorded in
    /// the evidence sink and `run` returns a [`Recorded`] that carries the
    /// observation the test asserts on and a per-test reference to that draft.
    /// Passing the `Recorded` to [`expect`](Self::expect) links the resulting
    /// judgement to the evidence; the runner resolves the reference to an
    /// [`EvidenceId`](crate::EvidenceId) when it drains the drafts into the store
    /// (ADR-0004, issue #14). An `execute` that errors records nothing, because
    /// the draft is the product of a completed action. The shipped
    /// [`TcpConnect`](crate::TcpConnect) holds a [`ScopedTarget`] (only the
    /// resolver produces one), so for it the scope gate is type-enforced; the
    /// trait does not require that of every capability, so that guarantee is
    /// per-capability, not trait-wide.
    ///
    /// This runs the capability *host-in-process*. A capability whose observation
    /// must come from the attacker's vantage must not be run here: the host has a
    /// route to every segment, so a host-run reachability check against a lab is a
    /// vacuous PASS (RK-008, the confound #27/#28 exist to kill). Today the only
    /// vantage path is [`connect_from_vantage`](Self::connect_from_vantage), a
    /// bespoke method kept off this trait for exactly that reason. When vantage
    /// execution is generalized (the M3 adapters), it must *require* the vantage by
    /// type, not run a `Capability` host-side and let it stand in for a vantage
    /// observation.
    pub async fn run<C: Capability>(&self, capability: C) -> Result<Recorded<C::Value>> {
        // The gate: `issue` mints the token only for a `Safe` capability, and
        // `execute` cannot be called without it.
        let authorized = IntensityCleared::issue(capability.intensity())?;
        let (observation, draft) = capability.execute(authorized).await?;
        let draft_ref = self.record_draft(draft);
        Ok(Recorded {
            observation,
            draft_ref,
            diagnostic: None,
        })
    }

    /// Attempt a TCP connection to `target` from the attacker's vantage inside the
    /// lab, and return its [`Recorded`] result (the same shape [`run`](Self::run)
    /// returns, so [`expect`](Self::expect) links the judgement to its evidence).
    ///
    /// This is the lab-wired counterpart of `run` for the one MVP capability: it
    /// executes from a container on the vantage network (`tcp_reachable_from`),
    /// not from the host, because the host reaches every segment and so cannot
    /// observe an inter-segment boundary (a vacuous PASS; #28, ADR-0003,
    /// `.claude/review/knowledge.md` RK-008). A completed connect is reachable at
    /// `High`; a failure is unreachable at `Low`, because the probe cannot prove
    /// the port closed (See ADR-0010, and `TcpConnect`), so a test asserting a
    /// boundary holds opts down to `min_confidence(Low)` explicitly, and the
    /// `High` certification that the boundary held is the boundary self-check, not
    /// this probe.
    ///
    /// Errors with [`Error::LabUnavailable`] on a context with no lab bound (a
    /// host run): there is no vantage to act from. Generalizing to "run any
    /// capability from the vantage" waits on the M3 tool adapters, which shape the
    /// in-container seam (one capability in the MVP, as in #27). That seam does
    /// not go through the [`run`](Self::run) intensity gate (it mints no
    /// [`IntensityCleared`]); it is `Safe` by
    /// construction today (busybox `nc`), but it is the path where M3's
    /// Controlled/Aggressive adapters will live, so M3 must require the gate token
    /// here too (#9's deferred full-gate work).
    ///
    /// It trusts the `ScopedTarget`'s existing scope gate and does not re-check it
    /// against this context's own `scope`: a target's scope provenance is not yet
    /// bound per-context. Not reachable today (the only lab-bound context a test
    /// holds is the runner's, whose scope is the full lab membership, and a
    /// `LabNetwork` cannot be fabricated outside the crate), but it would matter
    /// once a run's scope is deliberately narrower than what the vantage can touch.
    pub async fn connect_from_vantage(&self, target: &ScopedTarget) -> Result<Recorded<bool>> {
        let binding = self.lab.as_ref().ok_or_else(|| Error::LabUnavailable {
            reason: "no attacker vantage is bound to this run; connect_from_vantage needs a lab (run_in_lab)"
                .to_owned(),
        })?;
        let (observation, draft) = tcp_reachable_from(
            &binding.docker,
            &binding.vantage_network,
            target,
            DEFAULT_CONNECT_TIMEOUT,
        )
        .await?;
        let draft_ref = self.record_draft(draft);
        Ok(Recorded {
            observation,
            draft_ref,
            diagnostic: None,
        })
    }

    /// Attempt a SQL injection against `target` from the attacker's vantage and
    /// return its [`Recorded`] result, carrying an ADR-0009 domain diagnostic that
    /// [`to_be`](ExpectationBuilder::to_be) attaches if the expectation fails.
    ///
    /// The lab-wired counterpart of [`run`](Self::run) for the SQLi check, parallel
    /// to [`connect_from_vantage`](Self::connect_from_vantage): it runs an injected
    /// request from a container on the vantage network (`http_witness_exploit_from`) and
    /// captures the response body, so the observation and its evidence are what the
    /// attacker's vantage would see, not a host-run request. `request_path` carries
    /// the payload (URL-encoded), and `marker` is the DB-only value whose presence
    /// in the response proves the injection executed. An exploit is observed at
    /// `High`, a clean non-exploit at `High`, and an abnormal probe at `Low`
    /// (Inconclusive under the default gate), so a probe that could not reach the
    /// endpoint never reads as a confident "secure" (ADR-0010, RK-002).
    ///
    /// The diagnostic is the built-in check's, not the author's (ADR-0009): the
    /// test writes `ctx.expect(&recorded).to_be(false)` and the framework supplies
    /// the cause and the remediation. It is carried only when the injection
    /// actually executed (`observation.value`): its text asserts the injection ran,
    /// which is true only then, so a `to_be(true)` expectation observing a clean
    /// `false` gets `judge`'s generic text, not a false "the injection executed".
    /// Errors with [`Error::LabUnavailable`] on a context with no lab bound, like
    /// [`connect_from_vantage`](Self::connect_from_vantage).
    ///
    /// The attack this runs, and what a verdict about it means, are the catalog
    /// entry `docs/attacks/sql-injection.md`.
    pub async fn exploit_sqli_from_vantage(
        &self,
        target: &ScopedTarget,
        request_path: &str,
        marker: &str,
    ) -> Result<Recorded<bool>> {
        let binding = self.lab.as_ref().ok_or_else(|| Error::LabUnavailable {
            reason: "no attacker vantage is bound to this run; exploit_sqli_from_vantage needs a lab (run_in_lab)"
                .to_owned(),
        })?;
        let (observation, draft) = http_witness_exploit_from(
            &binding.docker,
            &binding.vantage_network,
            target,
            HTTP_SQLI_VANTAGE,
            request_path,
            marker,
            &[],
            DEFAULT_CONNECT_TIMEOUT,
        )
        .await?;
        let draft_ref = self.record_draft(draft);
        // Only an executed injection earns the domain diagnostic; its text asserts
        // the injection ran, which holds iff the marker was observed.
        let diagnostic = observation.value.then(|| sqli_diagnostic(marker));
        Ok(Recorded {
            observation,
            draft_ref,
            diagnostic,
        })
    }

    /// Attempt a path traversal against `target` from the attacker's vantage and
    /// return its [`Recorded`] result, carrying an ADR-0009 remediation diagnostic
    /// that [`to_be`](ExpectationBuilder::to_be) attaches if the expectation fails.
    ///
    /// The second native app-security check, parallel to
    /// [`exploit_sqli_from_vantage`](Self::exploit_sqli_from_vantage) and built on
    /// the same HTTP witness seam (`http_witness_exploit_from`), differing only in
    /// the capability name and the diagnostic. `request_path` carries the traversal
    /// payload (an escaping `?path=`, URL-encoded), and `marker` is the body of a
    /// file seeded outside the web root, present in the response only if the
    /// traversal escaped the root and read it. An exploit is observed at `High`, a
    /// clean non-exploit at `High`, and an abnormal probe at `Low` (Inconclusive
    /// under the default gate), so a probe that could not reach the endpoint never
    /// reads as a confident "secure" (ADR-0010, RK-002). The diagnostic is carried
    /// only when the traversal actually read the sentinel (`observation.value`),
    /// like the SQLi check. Errors with [`Error::LabUnavailable`] on a context with
    /// no lab bound.
    ///
    /// The attack this runs, and what a verdict about it means, are the catalog
    /// entry `docs/attacks/path-traversal.md`.
    pub async fn exploit_path_traversal_from_vantage(
        &self,
        target: &ScopedTarget,
        request_path: &str,
        marker: &str,
    ) -> Result<Recorded<bool>> {
        let binding = self.lab.as_ref().ok_or_else(|| Error::LabUnavailable {
            reason: "no attacker vantage is bound to this run; exploit_path_traversal_from_vantage needs a lab (run_in_lab)"
                .to_owned(),
        })?;
        let (observation, draft) = http_witness_exploit_from(
            &binding.docker,
            &binding.vantage_network,
            target,
            HTTP_PATH_TRAVERSAL_VANTAGE,
            request_path,
            marker,
            &[],
            DEFAULT_CONNECT_TIMEOUT,
        )
        .await?;
        let draft_ref = self.record_draft(draft);
        // Only a traversal that read the sentinel earns the domain diagnostic; its
        // text asserts a file outside the web root was read, true iff observed.
        let diagnostic = observation.value.then(|| path_traversal_diagnostic(marker));
        Ok(Recorded {
            observation,
            draft_ref,
            diagnostic,
        })
    }

    /// Attempt an IDOR (broken access control) against `target` from the attacker's
    /// vantage and return its [`Recorded`] result, carrying an ADR-0009 remediation
    /// diagnostic that [`to_be`](ExpectationBuilder::to_be) attaches if the
    /// expectation fails.
    ///
    /// A native app-security check (OWASP A01, object-level authorization / BOLA),
    /// parallel to
    /// [`exploit_sqli_from_vantage`](Self::exploit_sqli_from_vantage) and
    /// [`exploit_path_traversal_from_vantage`](Self::exploit_path_traversal_from_vantage)
    /// and built on the same HTTP witness seam, differing in the capability name,
    /// the diagnostic, and that it carries an identity in `request_headers` (the
    /// attacker's own session or credential). `request_path` requests another user's
    /// object by id, and `marker` is a value present only in that object, so its
    /// appearance proves that object's body was served to this request. An exploit
    /// is observed at `High`, a clean non-exploit at `High`, and an abnormal probe at
    /// `Low` (ADR-0010, RK-002). The diagnostic is carried only when the object was
    /// actually read (`observation.value`), like the siblings.
    ///
    /// A confident "not exploitable" PASS here means only "this identity did not read
    /// that object", NOT "the endpoint enforces ownership". If the target silently
    /// ignores or rejects the credential and answers a marker-less 200 (not a
    /// redirect), the probe never established that the identity took effect, yet it
    /// reads `false`/`High`. So an IDOR check MUST be paired with a positive control:
    /// a baseline read of the attacker's OWN object succeeding in the same run, which
    /// proves the identity authenticated (the fix-replay loop test does exactly this).
    /// Enforcing that corroboration inside the capability is deferred to a follow-up,
    /// under ADR-0010's corroboration-deferred model that the sibling single-probe
    /// checks also sit under.
    ///
    /// `request_headers` legitimately carries a credential (the attacker's token),
    /// and it is recorded VERBATIM in the evidence reproduction and the canonical
    /// JSON so a replay re-sends the same identity (security.md section 4/8: the
    /// store is sensitive, and a witness may capture credentials for a deterministic
    /// replay). The terminal report does not print it, but a shared renderer (the M2
    /// SARIF or HTML attack graph) must redact the `request_headers` key before the
    /// evidence leaves the box; nothing redacts it today, so that is a follow-up (the
    /// named key is the hook). For the playground the token is a non-secret fixture.
    /// Errors with [`Error::LabUnavailable`] on a context with no lab bound.
    ///
    /// The attack this runs, and what a verdict about it means, are the catalog
    /// entry `docs/attacks/idor.md`.
    pub async fn exploit_idor_from_vantage(
        &self,
        target: &ScopedTarget,
        request_path: &str,
        marker: &str,
        request_headers: &[(String, String)],
    ) -> Result<Recorded<bool>> {
        let binding = self.lab.as_ref().ok_or_else(|| Error::LabUnavailable {
            reason: "no attacker vantage is bound to this run; exploit_idor_from_vantage needs a lab (run_in_lab)"
                .to_owned(),
        })?;
        let (observation, draft) = http_witness_exploit_from(
            &binding.docker,
            &binding.vantage_network,
            target,
            HTTP_IDOR_VANTAGE,
            request_path,
            marker,
            request_headers,
            DEFAULT_CONNECT_TIMEOUT,
        )
        .await?;
        let draft_ref = self.record_draft(draft);
        // Only an object actually read across the boundary earns the diagnostic; its
        // text asserts another user's object was served, true iff observed.
        let diagnostic = observation.value.then(|| idor_diagnostic(marker));
        Ok(Recorded {
            observation,
            draft_ref,
            diagnostic,
        })
    }

    /// Coerce `app` (the SSRF target) from the attacker vantage to fetch an in-lab
    /// canary, and witness the request OUT-OF-BAND at the canary, returning the
    /// [`Recorded`] result with an ADR-0009 diagnostic that
    /// [`to_be`](ExpectationBuilder::to_be) attaches on a `Fail`.
    ///
    /// The fourth native app-security check, and the one not on the body-marker
    /// seam: its witness is the per-probe `token` appearing in the canary's logs,
    /// not in the app's own response (`ssrf_exploit_from`, #65). `canary_alias` and
    /// `canary_port` name the canary on the lab network (the coercion URL), and
    /// `canary_container` is its container (whose logs are read); the test resolves
    /// the container name from the running lab. The finding is attributed to `app`,
    /// not the canary. The diagnostic is carried only when the canary was actually
    /// reached (`observation.value`), like the siblings.
    ///
    /// A confident "not exploitable" means only that THIS coercion did not reach
    /// the canary, not that the app is safe: a coercion that never fired (the app
    /// erred before fetching, or ignored the URL) also reaches the canary with
    /// nothing. So an SSRF check MUST be paired with a positive control that the
    /// canary records and that `/fetch` is live (a direct hit on the canary, or an
    /// allowed fetch), else a confident PASS can be vacuous. Enforcing that
    /// corroboration in the capability is deferred under ADR-0010's model.
    /// Errors with [`Error::LabUnavailable`] on a context with no lab bound, or
    /// [`Error::InvalidTarget`] if the canary coordinates would not assemble a safe
    /// coercion request line (a weak token, or an alias carrying CR/LF).
    ///
    /// The attack this runs, and what a verdict about it means, are the catalog
    /// entry `docs/attacks/ssrf.md`.
    pub async fn exploit_ssrf_from_vantage(
        &self,
        app: &ScopedTarget,
        canary_alias: &str,
        canary_port: u16,
        canary_container: &str,
    ) -> Result<Recorded<bool>> {
        let binding = self.lab.as_ref().ok_or_else(|| Error::LabUnavailable {
            reason: "no attacker vantage is bound to this run; exploit_ssrf_from_vantage needs a lab (run_in_lab)"
                .to_owned(),
        })?;
        // Mint a fresh, unique per-probe token here, not from the caller: this
        // coercion's canary callback must be distinguishable and a caller cannot
        // pass a weak or forgeable one.
        let token = ssrf_token();
        let (observation, draft) = ssrf_exploit_from(
            &binding.docker,
            &binding.vantage_network,
            app,
            canary_alias,
            canary_port,
            canary_container,
            &token,
            DEFAULT_CONNECT_TIMEOUT,
        )
        .await?;
        let draft_ref = self.record_draft(draft);
        // Only a coercion that actually reached the canary earns the diagnostic;
        // its text asserts the server reached an internal host, true iff observed.
        let diagnostic = observation.value.then(|| ssrf_diagnostic(canary_alias));
        Ok(Recorded {
            observation,
            draft_ref,
            diagnostic,
        })
    }

    /// Push one evidence draft into the sink and return its per-test reference.
    /// Borrow / push / drop, with no await across the borrow. The draft's per-test
    /// index is its position in the sink, which the runner offsets by the test's
    /// base id to resolve the run-scoped `EvidenceId` (issue #14). Shared by
    /// [`run`](Self::run) and every `*_from_vantage` capability method.
    fn record_draft(&self, draft: EvidenceDraft) -> DraftRef {
        let mut drafts = self.evidence_drafts.borrow_mut();
        let index = drafts.len();
        drafts.push(draft);
        DraftRef::new(index)
    }
}

/// The ADR-0009 domain diagnostic for a successful SQL injection: the cause names
/// the `marker` the injection exfiltrated and that input reached the SQL, and the
/// remediation is a parameterized query. Framework-emitted, not author-written
/// (ADR-0009). Pure, so the text is guarded without Docker
/// (`sqli_diagnostic_names_the_marker_and_the_fix`).
fn sqli_diagnostic(marker: &str) -> Diagnostic {
    Diagnostic {
        probable_cause: format!(
            "the injected request returned {marker:?}, a value present only in the database, \
             so the endpoint interpolated request input into its SQL and the injection executed"
        ),
        remediation: "use a parameterized query (a prepared statement with bound parameters) \
             so request input cannot alter the SQL"
            .to_owned(),
    }
}

/// The ADR-0009 domain diagnostic for a successful path traversal: the cause names
/// the `marker` that was read from outside the intended directory, and the
/// remediation is to canonicalize the resolved path and reject one that escapes
/// that directory. Framework-emitted, not author-written (ADR-0009). Pure, so the text is
/// guarded without Docker (`path_traversal_diagnostic_names_the_marker_and_the_fix`).
fn path_traversal_diagnostic(marker: &str) -> Diagnostic {
    Diagnostic {
        probable_cause: format!(
            "the request returned {marker:?}, the body of a file outside the intended directory, \
             so the endpoint resolved a caller-supplied path without confining it to that directory"
        ),
        remediation: "canonicalize the resolved path and reject any path that resolves outside \
             the intended directory, so a caller cannot traverse to a file beyond it"
            .to_owned(),
    }
}

/// The ADR-0009 domain diagnostic for a successful IDOR: the cause names the
/// `marker`, another user's data, which the endpoint served by id without checking
/// it belongs to the requesting identity; the remediation is to enforce that
/// ownership check. The cause does not claim the request "authenticated as a
/// different user": the check observes only that another user's object came back,
/// not that a credential was validated (the endpoint may ignore identity entirely,
/// as the playground mvp does), so it states what the marker proves and no more.
/// Framework-emitted, not author-written (ADR-0009). Pure, so the text is guarded
/// without Docker (`idor_diagnostic_names_the_marker_and_the_fix`).
fn idor_diagnostic(marker: &str) -> Diagnostic {
    Diagnostic {
        probable_cause: format!(
            "the response returned {marker:?}, a value present only in another user's object, \
             so the endpoint served an object by id without checking that it belongs to the \
             requesting identity"
        ),
        remediation: "enforce an authorization check that the requested object belongs to the \
             requesting identity, so a caller cannot read another user's object by its id"
            .to_owned(),
    }
}

/// The ADR-0009 domain diagnostic for a successful SSRF: the cause names the
/// internal host the server was coerced to reach, and the remediation is to
/// allowlist the permitted outbound hosts and refuse an internal/private target.
/// Framework-emitted, not author-written (ADR-0009). Pure, so the text is guarded
/// without Docker (`ssrf_diagnostic_names_the_host_and_the_fix`).
fn ssrf_diagnostic(canary_alias: &str) -> Diagnostic {
    Diagnostic {
        probable_cause: format!(
            "the target fetched a caller-supplied URL and reached the internal host \
             {canary_alias:?}, so request input chose the server's outbound destination (SSRF)"
        ),
        remediation: "allowlist the hosts the server may fetch and refuse an internal or private \
             target, so request input cannot steer the server's outbound requests"
            .to_owned(),
    }
}

/// What [`TestContext::run`], [`TestContext::connect_from_vantage`] and the
/// `*_from_vantage` capability methods (SQLi, path traversal, IDOR) return:
/// the capability's [`Observation`] and a per-test reference to the evidence it
/// produced. Passing it to [`expect`](TestContext::expect) links the judgement to
/// that evidence automatically.
///
/// The reference is a field here rather than on [`Observation`] because putting
/// it there would force a hand-built observation, `judge`'s input, and the
/// `Observation` a `Capability` returns to all carry a link they cannot fill, and
/// would make `execute`'s observation meaningless until `run` rewrote it. So the
/// observation stays a plain signal and only a capability's result carries a link
/// (ADR-0010, issue #14). Only `run`, `connect_from_vantage`, and the
/// `*_from_vantage` capability methods construct one.
///
/// The reference is a per-test index (see [`DraftRef`]), so a
/// `Recorded` is only meaningful to the context that produced it. Judging one on
/// a different `TestContext` would resolve the index against the wrong test's
/// drafts; the runner hands each test exactly one context, so the honest path
/// cannot hit this, and hardening it against deliberate misuse is left for when a
/// second context per test is a real pattern.
pub struct Recorded<T> {
    /// The signal the capability observed.
    pub observation: Observation<T>,
    draft_ref: DraftRef,
    /// A domain [`Diagnostic`] (ADR-0009) a built-in check supplies, which
    /// [`to_be`](ExpectationBuilder::to_be) attaches on a `Fail`, replacing
    /// `judge`'s generic text. `None` for `run`/`connect_from_vantage`, whose
    /// expectations get the generic diagnostic; `Some` for a domain check like
    /// `exploit_sqli_from_vantage`. `pub(crate)` so an in-crate test can assert a
    /// non-exploit result carries no diagnostic (the `observation.value` gate),
    /// which only surfaces on a `Fail` and so cannot be checked through a judged
    /// Pass.
    pub(crate) diagnostic: Option<Diagnostic>,
}

/// The input [`expect`](TestContext::expect) accepts: a [`Recorded`] result,
/// which links its judgement to evidence, or a bare [`Observation`], which does
/// not. It is the pre-judgement input, not a judged result (that is
/// [`Judgement`]).
///
/// Sealed: the only implementors are these two. A foreign implementor could
/// return an arbitrary [`DraftRef`] from `draft_ref`, which the runner would
/// resolve to some unrelated record, so the seam is closed rather than offered as
/// an extension point. Callers pass `&Recorded` or `&Observation` and never name
/// this trait.
pub trait Expectable<T>: sealed::Sealed {
    /// The observation to judge.
    fn observation(&self) -> &Observation<T>;
    /// The per-test reference to the evidence the observation came from, if any.
    fn draft_ref(&self) -> Option<DraftRef>;
    /// The domain diagnostic a built-in check supplied, attached on a `Fail`
    /// (ADR-0009). Defaults to `None`; a bare `Observation` carries none, and only
    /// a [`Recorded`] from a domain check overrides it.
    fn diagnostic(&self) -> Option<Diagnostic> {
        None
    }
}

impl<T> Expectable<T> for Observation<T> {
    fn observation(&self) -> &Observation<T> {
        self
    }
    fn draft_ref(&self) -> Option<DraftRef> {
        None
    }
}

impl<T> Expectable<T> for Recorded<T> {
    fn observation(&self) -> &Observation<T> {
        &self.observation
    }
    fn draft_ref(&self) -> Option<DraftRef> {
        Some(self.draft_ref)
    }
    fn diagnostic(&self) -> Option<Diagnostic> {
        self.diagnostic.clone()
    }
}

// A private module, so the `Sealed` supertrait cannot be named or implemented
// outside this crate: that is what seals `Expectable`.
mod sealed {
    use crate::observation::Observation;

    pub trait Sealed {}
    impl<T> Sealed for Observation<T> {}
    impl<T> Sealed for super::Recorded<T> {}
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
    draft_ref: Option<DraftRef>,
    diagnostic: Option<Diagnostic>,
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
    ///
    /// A domain check's diagnostic (carried on the [`Recorded`], ADR-0009) is
    /// attached on a `Fail`, replacing `judge`'s generic text; a `Pass` or
    /// `Inconclusive` carries none, and an observation with no domain diagnostic
    /// keeps `judge`'s generic one.
    pub fn to_be(self, expected: T) -> Verdict {
        let Self {
            ctx,
            observation,
            draft_ref,
            diagnostic,
            min_confidence,
        } = self;
        let expectation = Expectation::to_be(expected).min_confidence(min_confidence);
        let mut judgement = judge(observation, &expectation);
        if judgement.verdict == Verdict::Fail
            && let Some(domain) = diagnostic
        {
            judgement.diagnostic = Some(domain);
        }
        let verdict = judgement.verdict;
        ctx.record(judgement, draft_ref);
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intensity::Intensity;
    use crate::observation::Confidence;

    /// A capability that is not `Safe` and panics if executed, so a test can
    /// prove the intensity gate refuses it before it runs.
    struct NonSafe;

    impl crate::capability::sealed::Sealed for NonSafe {}
    impl Capability for NonSafe {
        type Value = ();

        fn name(&self) -> &'static str {
            "non_safe_stub"
        }

        fn intensity(&self) -> Intensity {
            Intensity::Controlled
        }

        async fn execute(
            &self,
            _authorized: IntensityCleared,
        ) -> Result<(Observation<()>, EvidenceDraft)> {
            panic!("a refused capability must not execute");
        }
    }

    /// An Aggressive capability that panics if executed.
    struct Aggressive;

    impl crate::capability::sealed::Sealed for Aggressive {}
    impl Capability for Aggressive {
        type Value = ();

        fn name(&self) -> &'static str {
            "aggressive_stub"
        }

        fn intensity(&self) -> Intensity {
            Intensity::Aggressive
        }

        async fn execute(
            &self,
            _authorized: IntensityCleared,
        ) -> Result<(Observation<()>, EvidenceDraft)> {
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
    impl crate::capability::sealed::Sealed for AlwaysReachable {}
    impl Capability for AlwaysReachable {
        type Value = bool;
        fn name(&self) -> &'static str {
            "always_reachable_stub"
        }
        fn intensity(&self) -> Intensity {
            Intensity::Safe
        }
        async fn execute(
            &self,
            _authorized: IntensityCleared,
        ) -> Result<(Observation<bool>, EvidenceDraft)> {
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
                    source: None,
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
        let recorded = runtime
            .block_on(ctx.run(AlwaysReachable))
            .expect("a Safe capability runs");
        assert!(recorded.observation.value);
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

        let recorded = runtime
            .block_on(ctx.run(AlwaysReachable))
            .expect("a Safe capability runs");
        ctx.expect(&recorded).to_be(true);
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
        // The `Judgement.evidence` field itself is None until the runner resolves
        // it: judge and check both leave it None, and only the runner fills it.
        // Mutation: set `evidence: Some(..)` in judge or check -> fails here.
        assert!(
            pairs
                .iter()
                .all(|(judgement, _)| judgement.evidence.is_none()),
            "the recorded Judgement.evidence is unresolved until the runner fills it"
        );
    }

    /// Guard: a failing `check` records a `Fail` judgement carrying a FAIL
    /// diagnostic whose cause names the assertion, and a passing `check` carries
    /// none (ADR-0009; the built-in check produces it, on failure only).
    /// Mutation: leave `diagnostic` `None` on failure -> the failing assert fails;
    /// fill it unconditionally -> the passing assert fails; drop the message from
    /// the cause -> the content assert fails.
    #[test]
    fn check_failure_carries_a_diagnostic() {
        let ctx = TestContext::new(Scope::default());
        let _ = ctx.check(false, "the boundary must hold");
        ctx.check(true, "a tautology").expect("the check passes");

        let pairs = ctx.take_judgements();
        let (failed, _) = &pairs[0];
        assert_eq!(failed.verdict, Verdict::Fail);
        let diagnostic = failed
            .diagnostic
            .as_ref()
            .expect("a failing check carries a diagnostic");
        assert!(diagnostic.probable_cause.contains("the boundary must hold"));

        let (passed, _) = &pairs[1];
        assert_eq!(passed.verdict, Verdict::Pass);
        assert!(
            passed.diagnostic.is_none(),
            "a passing check carries no diagnostic"
        );
    }

    /// Guard: a domain check's diagnostic, carried on the `Recorded` (as
    /// `exploit_sqli_from_vantage` does), is attached by `to_be` on a `Fail`,
    /// replacing judge's generic text, and dropped on a `Pass`; a `Recorded` with
    /// no domain diagnostic keeps judge's generic one. Mutation: attach it
    /// unconditionally in `to_be` -> the Pass gains it -> the pass assertion fails;
    /// never attach it -> the Fail keeps the generic text -> the domain-text
    /// assertion fails.
    #[test]
    fn to_be_attaches_a_carried_domain_diagnostic_on_fail_only() {
        let domain = Diagnostic {
            probable_cause: "DOMAIN-CAUSE".to_owned(),
            remediation: "DOMAIN-FIX".to_owned(),
        };
        let recorded = |value| Recorded {
            observation: Observation {
                value,
                confidence: Confidence::High,
            },
            draft_ref: DraftRef::new(0),
            diagnostic: Some(domain.clone()),
        };

        let ctx = TestContext::new(Scope::default());
        // Observed true against expected-false -> Fail -> the domain diagnostic.
        assert_eq!(ctx.expect(&recorded(true)).to_be(false), Verdict::Fail);
        // Observed false against expected-false -> Pass -> no diagnostic.
        assert_eq!(ctx.expect(&recorded(false)).to_be(false), Verdict::Pass);

        let pairs = ctx.take_judgements();
        let (failed, _) = &pairs[0];
        let d = failed
            .diagnostic
            .as_ref()
            .expect("a Fail carries a diagnostic");
        assert_eq!(d.probable_cause, "DOMAIN-CAUSE");
        assert_eq!(d.remediation, "DOMAIN-FIX");
        let (passed, _) = &pairs[1];
        assert!(passed.diagnostic.is_none(), "a Pass carries no diagnostic");

        // A Recorded carrying no domain diagnostic keeps judge's generic text.
        let bare = Recorded {
            observation: Observation {
                value: true,
                confidence: Confidence::High,
            },
            draft_ref: DraftRef::new(0),
            diagnostic: None,
        };
        let ctx2 = TestContext::new(Scope::default());
        ctx2.expect(&bare).to_be(false);
        let generic = ctx2.take_judgements();
        let (gen_fail, _) = &generic[0];
        let gd = gen_fail
            .diagnostic
            .as_ref()
            .expect("a Fail carries a diagnostic");
        assert_ne!(
            gd.probable_cause, "DOMAIN-CAUSE",
            "with no domain diagnostic the Fail keeps judge's generic text"
        );
    }

    /// Guard: `connect_from_vantage` on a context with no lab bound (the host path, built by
    /// `new`) fails closed with `LabUnavailable` rather than panicking or acting:
    /// a host run has no vantage to probe from, so it must error before any
    /// Docker call (this needs no daemon). Mutation: unwrap `self.lab` instead of
    /// the `ok_or_else` -> the `None` case panics -> this (expecting an `Err`)
    /// fails.
    #[test]
    fn connect_from_vantage_without_a_lab_fails_closed() {
        let ctx = TestContext::new(Scope::default());
        let scope = Scope::builder()
            .allow("db:5432")
            .expect("valid spec")
            .build();
        let target = scope.resolve("db:5432").expect("in scope");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");
        let result = runtime.block_on(ctx.connect_from_vantage(&target));
        assert!(
            matches!(result, Err(Error::LabUnavailable { .. })),
            "connect_from_vantage without a vantage must fail closed (got Ok: {})",
            result.is_ok()
        );
    }

    /// Guard: `exploit_sqli_from_vantage` on a context with no lab bound fails
    /// closed with `LabUnavailable` rather than panicking or acting, like
    /// `connect_from_vantage`: a host run has no vantage to inject from, so it must
    /// error before any Docker call (this needs no daemon). Mutation: unwrap
    /// `self.lab` instead of the `ok_or_else` -> the `None` case panics -> this
    /// (expecting an `Err`) fails.
    #[test]
    fn exploit_sqli_from_vantage_without_a_lab_fails_closed() {
        let ctx = TestContext::new(Scope::default());
        let scope = Scope::builder()
            .allow("web:8080")
            .expect("valid spec")
            .build();
        let target = scope.resolve("web:8080").expect("in scope");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");
        let result =
            runtime.block_on(ctx.exploit_sqli_from_vantage(&target, "/lookup?name=x", "FLAG"));
        assert!(
            matches!(result, Err(Error::LabUnavailable { .. })),
            "exploit_sqli_from_vantage without a vantage must fail closed (got Ok: {})",
            result.is_ok()
        );
    }

    /// Guard: the SQLi domain diagnostic names the exfiltrated marker and the
    /// injection in its cause, and a parameterized query in its remediation, so a
    /// reader gets the ADR-0009 actionable guidance rather than generic text. Pure,
    /// no Docker (the diagnostic text otherwise has only the Docker-gated demo as a
    /// guard). Mutation: drop the marker from the cause, or change "parameterized"
    /// in the remediation -> the matching assertion fails.
    #[test]
    fn sqli_diagnostic_names_the_marker_and_the_fix() {
        let d = sqli_diagnostic("FLAG123");
        assert!(
            d.probable_cause.contains("FLAG123") && d.probable_cause.contains("injection"),
            "the cause names the marker and the injection: {:?}",
            d.probable_cause
        );
        assert!(
            d.remediation.contains("parameterized"),
            "the remediation names a parameterized query: {:?}",
            d.remediation
        );
    }

    /// Guard: `exploit_path_traversal_from_vantage` on a context with no lab bound
    /// fails closed with `LabUnavailable`, like `exploit_sqli_from_vantage`: a host
    /// run has no vantage to probe from, so it must error before any Docker call
    /// (this needs no daemon). Mutation: unwrap `self.lab` instead of the
    /// `ok_or_else` -> the `None` case panics -> this (expecting an `Err`) fails.
    #[test]
    fn exploit_path_traversal_from_vantage_without_a_lab_fails_closed() {
        let ctx = TestContext::new(Scope::default());
        let scope = Scope::builder()
            .allow("api:8081")
            .expect("valid spec")
            .build();
        let target = scope.resolve("api:8081").expect("in scope");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");
        let result = runtime.block_on(ctx.exploit_path_traversal_from_vantage(
            &target,
            "/file?path=../secret.txt",
            "SENTINEL",
        ));
        assert!(
            matches!(result, Err(Error::LabUnavailable { .. })),
            "exploit_path_traversal_from_vantage without a vantage must fail closed (got Ok: {})",
            result.is_ok()
        );
    }

    /// Guard: the path-traversal domain diagnostic names the sentinel marker read
    /// from outside the intended directory in its cause, and canonicalizing /
    /// rejecting an escaping path in its remediation, so a reader gets ADR-0009
    /// actionable guidance rather than generic text. Pure, no Docker. Mutation: drop
    /// the marker from the cause, or change "canonicalize" in the remediation -> the
    /// matching assertion fails.
    #[test]
    fn path_traversal_diagnostic_names_the_marker_and_the_fix() {
        let d = path_traversal_diagnostic("SENTINEL42");
        assert!(
            d.probable_cause.contains("SENTINEL42")
                && d.probable_cause.contains("intended directory"),
            "the cause names the sentinel marker and the intended directory: {:?}",
            d.probable_cause
        );
        assert!(
            d.remediation.contains("canonicalize"),
            "the remediation names canonicalizing the resolved path: {:?}",
            d.remediation
        );
    }

    /// Guard: `exploit_idor_from_vantage` on a context with no lab bound fails
    /// closed with `LabUnavailable`, like its siblings: a host run has no vantage to
    /// probe from, so it must error before any Docker call (this needs no daemon).
    /// Mutation: unwrap `self.lab` instead of the `ok_or_else` -> the `None` case
    /// panics -> this (expecting an `Err`) fails.
    #[test]
    fn exploit_idor_from_vantage_without_a_lab_fails_closed() {
        let ctx = TestContext::new(Scope::default());
        let scope = Scope::builder()
            .allow("api:8081")
            .expect("valid spec")
            .build();
        let target = scope.resolve("api:8081").expect("in scope");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");
        let result = runtime.block_on(ctx.exploit_idor_from_vantage(
            &target,
            "/object?id=2",
            "REDSTEP_IDOR",
            &[("Authorization".to_owned(), "tok-alice".to_owned())],
        ));
        assert!(
            matches!(result, Err(Error::LabUnavailable { .. })),
            "exploit_idor_from_vantage without a vantage must fail closed (got Ok: {})",
            result.is_ok()
        );
    }

    /// Guard: the IDOR domain diagnostic names the marker (another user's data) in
    /// its cause and the ownership/authorization check in its remediation, so a
    /// reader gets ADR-0009 actionable guidance rather than generic text. Pure, no
    /// Docker. Mutation: drop the marker from the cause, or change "authorization"
    /// in the remediation -> the matching assertion fails.
    #[test]
    fn idor_diagnostic_names_the_marker_and_the_fix() {
        let d = idor_diagnostic("IDOR42");
        assert!(
            d.probable_cause.contains("IDOR42") && d.probable_cause.contains("another user"),
            "the cause names the marker and that it is another user's data: {:?}",
            d.probable_cause
        );
        assert!(
            d.remediation.contains("authorization") && d.remediation.contains("belongs to"),
            "the remediation names the ownership/authorization check: {:?}",
            d.remediation
        );
    }

    /// Guard: `exploit_ssrf_from_vantage` on a context with no lab bound fails
    /// closed with `LabUnavailable`, like its siblings (this needs no daemon).
    /// Mutation: unwrap `self.lab` instead of the `ok_or_else` -> the `None` case
    /// panics -> this (expecting an `Err`) fails.
    #[test]
    fn exploit_ssrf_from_vantage_without_a_lab_fails_closed() {
        let ctx = TestContext::new(Scope::default());
        let scope = Scope::builder()
            .allow("api:8081")
            .expect("valid spec")
            .build();
        let target = scope.resolve("api:8081").expect("in scope");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");
        let result = runtime.block_on(ctx.exploit_ssrf_from_vantage(
            &target,
            "canary",
            8082,
            "ignored-container",
        ));
        assert!(
            matches!(result, Err(Error::LabUnavailable { .. })),
            "exploit_ssrf_from_vantage without a vantage must fail closed (got Ok: {})",
            result.is_ok()
        );
    }

    /// Guard: the SSRF domain diagnostic names the internal host the server was
    /// coerced to reach and the allowlist fix, so a reader gets ADR-0009 actionable
    /// guidance. Pure, no Docker. Mutation: drop the host from the cause, or change
    /// "allowlist" in the remediation -> the matching assertion fails.
    #[test]
    fn ssrf_diagnostic_names_the_host_and_the_fix() {
        let d = ssrf_diagnostic("canary");
        assert!(
            d.probable_cause.contains("canary") && d.probable_cause.contains("SSRF"),
            "the cause names the internal host and the technique: {:?}",
            d.probable_cause
        );
        assert!(
            d.remediation.contains("allowlist"),
            "the remediation names the allowlist fix: {:?}",
            d.remediation
        );
    }
}
