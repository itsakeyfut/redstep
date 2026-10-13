//! The canonical JSON and the terminal renderer over it (ADR-0005, ADR-0009).
//!
//! ADR-0005 makes one canonical JSON the single intermediate representation:
//! every other output is a thin renderer over it, so the formats cannot drift. A
//! `Report` is projected once from a `RunSummary` by `build`; `to_json` and
//! `render_terminal` are the two renderers over that one `Report`, so the file
//! and the terminal agree by construction. SARIF and the HTML attack graph are
//! later renderers over the same `Report` (M2); this unit ships the terminal and
//! the JSON only.
//!
//! A `Report` is a projection, not the internal model. Verdicts serialize as
//! their `Verdict::label` strings rather than through a derived `Serialize`,
//! because `Verdict` is `#[non_exhaustive]` and deriving one would tie the
//! published JSON to the internal variant names; `Confidence` is reused as-is,
//! as it is already a stable leaf. The published types carry `schema_version`
//! and are `#[non_exhaustive]` so the contract can grow without a break.
//! `render_terminal` is a `cargo test`-style summary: one line per test, then the
//! non-PASS reasons indented (a FAIL also carries the H-2 diagnostic), then a
//! count line. The evidence section reuses the `Evidence` records the store
//! already holds (ADR-0004); they are canonical as they are.

use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::evidence::Evidence;
use crate::expectation::{Diagnostic, Judgement};
use crate::observation::Confidence;
use crate::runner::{RunSummary, TestRun};

/// The version of the canonical JSON schema. Bumped when the contract changes in
/// a way a consumer must branch on; present from the first release so a consumer
/// always has a version to read (ADR-0005).
const SCHEMA_VERSION: u32 = 1;

/// The canonical JSON of a run: its per-test results, the evidence they project
/// from, and the exit status a CI gate reads (ADR-0005). `#[non_exhaustive]`,
/// so a later field is not a breaking change for an external Rust consumer; the
/// JSON itself grows compatibly because serde ignores unknown fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Report {
    /// The schema version, so a consumer can branch on the contract.
    pub schema_version: u32,
    /// One result per security test, in run order.
    pub results: Vec<TestResult>,
    /// Every evidence record the run produced (ADR-0004), reused as-is.
    pub evidence: Vec<Evidence>,
    /// `0` only if at least one test ran and all passed; non-zero otherwise. A
    /// field of the canonical JSON, so a gate judges from the JSON (ADR-0005).
    pub exit_code: i32,
}

/// One security test's result: its verdict, the reasons behind it, and the
/// evidence ids they rest on. Named `TestResult`, not `Finding`: a `Finding`
/// (ADR-0007) is a scanner's discovered issue, whereas this is a test outcome
/// that may well be a `PASS`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TestResult {
    /// The fully-qualified test name.
    pub test: String,
    /// The test's verdict, as its label (`"PASS"` / `"FAIL"` / ...).
    pub verdict: String,
    /// The judged expectations behind the verdict, in the order declared.
    pub reasons: Vec<Reason>,
    /// A message for a bare `check` failure, an error, or a panic.
    pub error: Option<String>,
    /// The evidence ids the reasons rest on, aggregated. A list, so a result can
    /// rest on several records even though each reason references one (the #14
    /// cardinality note; ADR-0010).
    pub evidence_ids: Vec<u64>,
}

/// One judged expectation, projected for the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Reason {
    /// This expectation's verdict, as its label.
    pub verdict: String,
    /// The expected value, as the test declared it.
    pub expected: String,
    /// The observed value.
    pub actual: String,
    /// How much the observation was trusted.
    pub confidence: Confidence,
    /// The evidence record this reason rests on, if any.
    pub evidence_id: Option<u64>,
    /// The rustc-style FAIL diagnostic (ADR-0009), present on a `FAIL`.
    pub diagnostic: Option<Diagnostic>,
}

/// Project a run into the canonical report. The one place the projection is
/// built, so the renderers cannot disagree (ADR-0005).
pub fn build(summary: &RunSummary) -> Report {
    Report {
        schema_version: SCHEMA_VERSION,
        results: summary.runs.iter().map(result_of).collect(),
        evidence: summary.evidence.records().to_vec(),
        // Reuse the runner's fail-closed rule rather than re-deriving it, so the
        // empty-run-is-not-a-pass guarantee lives in one place (RunSummary).
        exit_code: summary.exit_code(),
    }
}

/// Serialize the report to the canonical JSON, newline-terminated (so the file
/// follows the usual text convention). The `expect` is unreachable: the report
/// is owned plain data with no non-string map keys, which `serde_json` cannot
/// fail to serialize.
pub fn to_json(report: &Report) -> String {
    let mut json =
        serde_json::to_string_pretty(report).expect("a report of owned, plain data serializes");
    json.push('\n');
    json
}

/// Render the report as a `cargo test`-style terminal summary. A non-PASS reason
/// prints its expected / actual (with the evidence id) indented beneath its test,
/// and a FAIL reason also prints the H-2 probable cause / remediation; a PASS
/// reason is not printed. A final line counts each verdict.
pub fn render_terminal(report: &Report) -> String {
    let mut out = String::new();
    for result in &report.results {
        let _ = writeln!(out, "{:<12} {}", result.verdict, result.test);
        if let Some(error) = &result.error {
            let _ = writeln!(out, "             {error}");
        }
        for reason in &result.reasons {
            // A passing reason is the absence of a problem, not a line to read.
            if reason.verdict == "PASS" {
                continue;
            }
            let evidence = reason
                .evidence_id
                .map(|id| format!("  (Evidence: ev_{id})"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "             {}: expected {}, observed {}{}",
                reason.verdict, reason.expected, reason.actual, evidence
            );
            if let Some(diagnostic) = &reason.diagnostic {
                let _ = writeln!(
                    out,
                    "               probable cause: {}",
                    diagnostic.probable_cause
                );
                let _ = writeln!(
                    out,
                    "               remediation:    {}",
                    diagnostic.remediation
                );
            }
        }
    }
    // The labels here must match `Verdict::label`; a snapshot test pins the whole
    // output so a drifted label or a miscounted bucket is caught.
    let count = |verdict: &str| {
        report
            .results
            .iter()
            .filter(|r| r.verdict == verdict)
            .count()
    };
    let _ = writeln!(
        out,
        "{} passed, {} failed, {} inconclusive, {} errored",
        count("PASS"),
        count("FAIL"),
        count("INCONCLUSIVE"),
        count("ERROR")
    );
    out
}

/// Project one test run into a result, collecting the evidence ids its reasons
/// rest on.
fn result_of(run: &TestRun) -> TestResult {
    let reasons: Vec<Reason> = run.judgements.iter().map(reason_of).collect();
    let evidence_ids = reasons
        .iter()
        .filter_map(|reason| reason.evidence_id)
        .collect();
    TestResult {
        test: run.name.to_owned(),
        verdict: run.verdict.label().to_owned(),
        reasons,
        error: run.error.clone(),
        evidence_ids,
    }
}

/// Project one judgement into a reason.
fn reason_of(judgement: &Judgement) -> Reason {
    Reason {
        verdict: judgement.verdict.label().to_owned(),
        expected: judgement.expected.clone(),
        actual: judgement.actual.clone(),
        confidence: judgement.confidence,
        evidence_id: judgement.evidence.map(|id| id.0),
        diagnostic: judgement.diagnostic.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{EvidenceDraft, EvidenceId, EvidenceStore, Reproduction};
    use crate::intensity::Intensity;
    use crate::verdict::Verdict;

    fn pass_judgement() -> Judgement {
        Judgement {
            verdict: Verdict::Pass,
            expected: "false".to_owned(),
            actual: "false".to_owned(),
            confidence: Confidence::High,
            evidence: Some(EvidenceId(0)),
            diagnostic: None,
        }
    }

    fn fail_judgement() -> Judgement {
        Judgement {
            verdict: Verdict::Fail,
            expected: "false".to_owned(),
            actual: "true".to_owned(),
            confidence: Confidence::High,
            evidence: Some(EvidenceId(1)),
            diagnostic: Some(Diagnostic {
                probable_cause: "the boundary did not hold".to_owned(),
                remediation: "close the path".to_owned(),
            }),
        }
    }

    /// An Inconclusive reason at Low confidence that rests on no evidence: covers
    /// the INCONCLUSIVE label, the Low confidence serialization, and a reason with
    /// no evidence id (which must not be aggregated as id 0).
    fn inconclusive_judgement() -> Judgement {
        Judgement {
            verdict: Verdict::Inconclusive,
            expected: "false".to_owned(),
            actual: "false".to_owned(),
            confidence: Confidence::Low,
            evidence: None,
            diagnostic: None,
        }
    }

    fn run_of(name: &'static str, verdict: Verdict, judgement: Judgement) -> TestRun {
        TestRun {
            name,
            verdict,
            judgements: vec![judgement],
            error: None,
        }
    }

    /// One run of each verdict kind, and two evidence records at a fixed
    /// timestamp, so the JSON and the terminal are deterministic. The ERROR run
    /// has no reasons and an `error` message; the INCONCLUSIVE run rests on no
    /// evidence.
    fn sample_summary() -> RunSummary {
        let mut evidence = EvidenceStore::new();
        for target in ["web:80", "db:5432"] {
            evidence.append(
                EvidenceDraft {
                    capability: "tcp_connect",
                    target: target.to_owned(),
                    intensity: Intensity::Safe,
                    observed: serde_json::Value::Bool(true),
                    confidence: Confidence::High,
                    summary: "reachable".to_owned(),
                    source: None,
                    reproduction: Reproduction {
                        capability: "tcp_connect".to_owned(),
                        target: target.to_owned(),
                        params: serde_json::json!({ "timeout_ms": 5000 }),
                    },
                },
                1_700_000_000_000,
            );
        }
        RunSummary {
            runs: vec![
                run_of("a::boundary_holds", Verdict::Pass, pass_judgement()),
                run_of("b::boundary_breached", Verdict::Fail, fail_judgement()),
                run_of(
                    "c::signal_too_weak",
                    Verdict::Inconclusive,
                    inconclusive_judgement(),
                ),
                TestRun {
                    name: "d::panicked",
                    verdict: Verdict::Error,
                    judgements: vec![],
                    error: Some("boom".to_owned()),
                },
            ],
            evidence,
        }
    }

    /// Guard: the results are the published contract (ADR-0005), pinned exact so
    /// a renamed key, a dropped/mismapped field, a missing verdict kind, or a
    /// mis-serialized `Confidence` is caught (round-trip alone would not; RK-003).
    /// The evidence shape is pinned by #5, so only its ids are checked here.
    /// Mutation: map the verdict or expected/actual wrong in `result_of`/`reason_of`,
    /// or hard-code `confidence`, or drop `error`/`schema_version` -> the literal
    /// no longer matches -> fails.
    #[test]
    fn canonical_json_pins_the_results() {
        let report = build(&sample_summary());
        let value = serde_json::to_value(&report).expect("serialize");

        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["exit_code"], 1);
        assert_eq!(value["evidence"][0]["id"], 0);
        assert_eq!(value["evidence"][1]["id"], 1);
        assert_eq!(
            value["results"],
            serde_json::json!([
                {
                    "test": "a::boundary_holds",
                    "verdict": "PASS",
                    "reasons": [
                        { "verdict": "PASS", "expected": "false", "actual": "false", "confidence": "High", "evidence_id": 0, "diagnostic": null }
                    ],
                    "error": null,
                    "evidence_ids": [0]
                },
                {
                    "test": "b::boundary_breached",
                    "verdict": "FAIL",
                    "reasons": [
                        { "verdict": "FAIL", "expected": "false", "actual": "true", "confidence": "High", "evidence_id": 1,
                          "diagnostic": { "probable_cause": "the boundary did not hold", "remediation": "close the path" } }
                    ],
                    "error": null,
                    "evidence_ids": [1]
                },
                {
                    "test": "c::signal_too_weak",
                    "verdict": "INCONCLUSIVE",
                    "reasons": [
                        { "verdict": "INCONCLUSIVE", "expected": "false", "actual": "false", "confidence": "Low", "evidence_id": null, "diagnostic": null }
                    ],
                    "error": null,
                    "evidence_ids": []
                },
                {
                    "test": "d::panicked",
                    "verdict": "ERROR",
                    "reasons": [],
                    "error": "boom",
                    "evidence_ids": []
                }
            ])
        );
    }

    /// Guard: the terminal output, whole, so the summary count line, the skip-PASS
    /// rule, the evidence suffix, the expected/actual order, the error line, and
    /// every verdict label are all pinned, not merely `contains`-checked. Mutation:
    /// change a count slot (e.g. `count("FAIL")` -> `0`), stop skipping PASS
    /// reasons, swap expected/actual, drop the evidence suffix, or relabel a
    /// verdict -> the snapshot no longer matches -> fails.
    #[test]
    fn terminal_matches_the_snapshot() {
        let report = build(&sample_summary());
        let expected = concat!(
            "PASS         a::boundary_holds\n",
            "FAIL         b::boundary_breached\n",
            "             FAIL: expected false, observed true  (Evidence: ev_1)\n",
            "               probable cause: the boundary did not hold\n",
            "               remediation:    close the path\n",
            "INCONCLUSIVE c::signal_too_weak\n",
            "             INCONCLUSIVE: expected false, observed false\n",
            "ERROR        d::panicked\n",
            "             boom\n",
            "1 passed, 1 failed, 1 inconclusive, 1 errored\n",
        );
        assert_eq!(render_terminal(&report), expected);
    }

    /// Guard: `to_json` is the real serialization, pretty-printed and
    /// newline-terminated, and it round-trips to the same value the report
    /// serializes to. Mutation: return a constant string, drop the trailing
    /// newline, or switch to compact `to_string` -> fails.
    #[test]
    fn to_json_is_pretty_and_round_trips() {
        let report = build(&sample_summary());
        let json = to_json(&report);

        assert!(json.ends_with('\n'), "the JSON file is newline-terminated");
        assert!(json.contains("\n  "), "the JSON is pretty-printed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed, serde_json::to_value(&report).expect("serialize"));
    }

    /// Guard: the exit status is a field of the report and reflects the verdicts,
    /// fail-closed on an empty run, for every verdict kind. Mutation: hard-code
    /// `exit_code: 0` in `build`, or special-case Error/Inconclusive to 0 -> one of
    /// these fails.
    #[test]
    fn report_exit_code_matches_the_verdicts() {
        assert_eq!(
            build(&sample_summary()).exit_code,
            1,
            "a mixed run is non-zero"
        );

        let all_pass = RunSummary {
            runs: vec![run_of("a::ok", Verdict::Pass, pass_judgement())],
            evidence: EvidenceStore::new(),
        };
        assert_eq!(build(&all_pass).exit_code, 0, "an all-pass run is zero");

        for (name, verdict, judgement) in [
            ("a::weak", Verdict::Inconclusive, inconclusive_judgement()),
            ("a::broke", Verdict::Error, inconclusive_judgement()),
        ] {
            let summary = RunSummary {
                runs: vec![run_of(name, verdict, judgement)],
                evidence: EvidenceStore::new(),
            };
            assert_ne!(
                build(&summary).exit_code,
                0,
                "a {verdict:?} run is not a pass"
            );
        }

        let empty = RunSummary {
            runs: vec![],
            evidence: EvidenceStore::new(),
        };
        assert_ne!(build(&empty).exit_code, 0, "an empty run is not a pass");
    }

    /// Guard: a result aggregates the evidence ids of its reasons, and a reason
    /// with no evidence contributes none (not a spurious id 0). Mutation: drop the
    /// aggregation (empty), or replace `filter_map` with `map(unwrap_or(0))` -> the
    /// list is wrong -> fails.
    #[test]
    fn result_collects_only_real_evidence_ids() {
        let mixed = TestRun {
            name: "a::mixed",
            verdict: Verdict::Fail,
            // pass_judgement -> id 0, inconclusive -> no id, fail -> id 1.
            judgements: vec![pass_judgement(), inconclusive_judgement(), fail_judgement()],
            error: None,
        };
        let summary = RunSummary {
            runs: vec![mixed],
            evidence: EvidenceStore::new(),
        };
        let report = build(&summary);
        assert_eq!(report.results[0].evidence_ids, vec![0, 1]);
    }

    /// Guard: every evidence id a result cites resolves to a record in the report's
    /// evidence section, so the projection is internally consistent (ADR-0005).
    /// Mutation: have `build` copy only some of the store's records -> an id no
    /// longer resolves -> fails.
    #[test]
    fn every_cited_evidence_id_resolves() {
        let report = build(&sample_summary());
        let known: Vec<u64> = report.evidence.iter().map(|e| e.id.0).collect();
        for result in &report.results {
            for id in &result.evidence_ids {
                assert!(
                    known.contains(id),
                    "evidence id {id} cited by {} is not in the evidence section",
                    result.test
                );
            }
        }
    }
}
