//! The canonical JSON and the terminal renderer over it (Decision E, H-2).
//!
//! Decision E makes one canonical JSON the single intermediate representation:
//! every other output is a thin renderer over it, so the formats cannot drift. A
//! `Report` is projected once from a `RunSummary` by `build`; `to_json` and
//! `render_terminal` are the two renderers over that one `Report`, so the file
//! and the terminal agree by construction. SARIF and the HTML attack graph are
//! later renderers over the same `Report` (M2); this unit ships the terminal and
//! the JSON only.
//!
//! A `Report` is a projection, not the internal model: verdicts serialize as
//! their `Verdict::label` strings for an explicit published contract, and a
//! finding is one security test with its reasons and the evidence ids they rest
//! on. The evidence section reuses the `Evidence` records the store already holds
//! (Decision D); they are canonical as they are.

use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::evidence::Evidence;
use crate::expectation::{Diagnostic, Judgement};
use crate::observation::Confidence;
use crate::runner::{RunSummary, TestRun};

/// The canonical JSON of a run: its findings, the evidence they project from, and
/// the exit status a CI gate reads (Decision E).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// One finding per security test, in run order.
    pub findings: Vec<Finding>,
    /// Every evidence record the run produced (Decision D), reused as-is.
    pub evidence: Vec<Evidence>,
    /// `0` only if at least one test ran and all passed; non-zero otherwise. A
    /// field of the canonical JSON, so a gate judges from the JSON (Decision E).
    pub exit_code: i32,
}

/// One security test's result: its verdict, the reasons behind it, and the
/// evidence ids they rest on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// The fully-qualified test name.
    pub test: String,
    /// The test's verdict, as its label (`"PASS"` / `"FAIL"` / ...).
    pub verdict: String,
    /// The judged expectations behind the verdict, in the order declared.
    pub reasons: Vec<Reason>,
    /// A message for a bare `check` failure, an error, or a panic.
    pub error: Option<String>,
    /// The evidence ids the reasons rest on, aggregated. A list, so a finding can
    /// rest on several records even though each reason references one (the #14
    /// cardinality note; Decision J).
    pub evidence_ids: Vec<u64>,
}

/// One judged expectation, projected for the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// The rustc-style FAIL diagnostic (Decision H-2), present on a `FAIL`.
    pub diagnostic: Option<Diagnostic>,
}

/// Project a run into the canonical report. The one place the projection is
/// built, so the renderers cannot disagree (Decision E).
pub fn build(summary: &RunSummary) -> Report {
    Report {
        findings: summary.runs.iter().map(finding_of).collect(),
        evidence: summary.evidence.records().to_vec(),
        // Reuse the runner's fail-closed rule rather than re-deriving it, so the
        // empty-run-is-not-a-pass guarantee lives in one place (RunSummary).
        exit_code: summary.exit_code(),
    }
}

/// Serialize the report to the canonical JSON.
pub fn to_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).expect("a report of owned, plain data serializes")
}

/// Render the report as a `cargo test`-style terminal summary. A `FAIL` prints
/// the expected / actual / probable cause / remediation diagnostic indented
/// beneath it (Decision H-2); a `PASS` is one line.
pub fn render_terminal(report: &Report) -> String {
    let mut out = String::new();
    for finding in &report.findings {
        let _ = writeln!(out, "{:<12} {}", finding.verdict, finding.test);
        if let Some(error) = &finding.error {
            let _ = writeln!(out, "             {error}");
        }
        for reason in &finding.reasons {
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
    let count = |verdict: &str| {
        report
            .findings
            .iter()
            .filter(|f| f.verdict == verdict)
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

/// Project one test run into a finding, collecting the evidence ids its reasons
/// rest on.
fn finding_of(run: &TestRun) -> Finding {
    let reasons: Vec<Reason> = run.judgements.iter().map(reason_of).collect();
    let evidence_ids = reasons
        .iter()
        .filter_map(|reason| reason.evidence_id)
        .collect();
    Finding {
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

    fn run_of(name: &'static str, verdict: Verdict, judgement: Judgement) -> TestRun {
        TestRun {
            name,
            verdict,
            judgements: vec![judgement],
            error: None,
        }
    }

    /// Two tests (a PASS and a FAIL) and one evidence record at a fixed
    /// timestamp, so the JSON is deterministic.
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
            ],
            evidence,
        }
    }

    /// Guard: the findings are the published contract (Decision E), pinned exact
    /// so a renamed key or a dropped/mismapped field is caught (round-trip alone
    /// would not; RK-003). The evidence shape is pinned by #5, so only its ids are
    /// checked here. Mutation: map the verdict or expected/actual wrong in
    /// `finding_of`/`reason_of` -> the literal no longer matches -> fails.
    #[test]
    fn canonical_json_pins_the_findings() {
        let report = build(&sample_summary());
        let value = serde_json::to_value(&report).expect("serialize");

        assert_eq!(
            value["findings"],
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
                }
            ])
        );
        assert_eq!(value["exit_code"], 1);
        assert_eq!(value["evidence"][0]["id"], 0);
        assert_eq!(value["evidence"][1]["id"], 1);
    }

    /// Guard: the terminal and the JSON show the same verdicts, because both come
    /// from one `Report`. Mutation: hard-code a verdict label in `render_terminal`
    /// (e.g. always `"PASS"`) -> the terminal line disagrees with the finding's
    /// verdict -> fails.
    #[test]
    fn terminal_and_json_show_the_same_verdicts() {
        let report = build(&sample_summary());
        let terminal = render_terminal(&report);
        for finding in &report.findings {
            assert!(
                terminal.contains(&format!("{:<12} {}", finding.verdict, finding.test)),
                "terminal is missing {} {}, got:\n{terminal}",
                finding.verdict,
                finding.test
            );
        }
    }

    /// Guard: a FAIL carries the H-2 diagnostic in the JSON and prints it.
    /// Mutation: drop `diagnostic` in `reason_of`, or make `render_terminal` skip
    /// the probable-cause/remediation lines -> fails.
    #[test]
    fn fail_finding_carries_the_h2_diagnostic() {
        let report = build(&sample_summary());
        let fail = report
            .findings
            .iter()
            .find(|f| f.verdict == "FAIL")
            .expect("a FAIL finding");
        let diagnostic = fail.reasons[0]
            .diagnostic
            .as_ref()
            .expect("the FAIL reason carries a diagnostic");
        assert!(!diagnostic.probable_cause.is_empty());
        assert!(!diagnostic.remediation.is_empty());

        let terminal = render_terminal(&report);
        assert!(terminal.contains("probable cause: the boundary did not hold"));
        assert!(terminal.contains("remediation:    close the path"));
    }

    /// Guard: the exit status is a field of the report and reflects the verdicts,
    /// fail-closed on an empty run. Mutation: hard-code `exit_code: 0` in `build`
    /// -> the FAIL run and the empty run both read 0 -> fails.
    #[test]
    fn report_exit_code_matches_the_verdicts() {
        assert_eq!(
            build(&sample_summary()).exit_code,
            1,
            "a FAIL run is non-zero"
        );

        let all_pass = RunSummary {
            runs: vec![run_of("a::ok", Verdict::Pass, pass_judgement())],
            evidence: EvidenceStore::new(),
        };
        assert_eq!(build(&all_pass).exit_code, 0, "an all-pass run is zero");

        let empty = RunSummary {
            runs: vec![],
            evidence: EvidenceStore::new(),
        };
        assert_ne!(build(&empty).exit_code, 0, "an empty run is not a pass");
    }

    /// Guard: a finding aggregates the evidence ids of its reasons, so a test with
    /// several runs rests on several records. Mutation: drop the `evidence_ids`
    /// aggregation in `finding_of` (leave it empty) -> fails.
    #[test]
    fn finding_collects_its_evidence_ids() {
        let two_reasons = TestRun {
            name: "a::two_runs",
            verdict: Verdict::Fail,
            judgements: vec![pass_judgement(), fail_judgement()],
            error: None,
        };
        let summary = RunSummary {
            runs: vec![two_reasons],
            evidence: EvidenceStore::new(),
        };
        let report = build(&summary);
        assert_eq!(report.findings[0].evidence_ids, vec![0, 1]);
    }
}
