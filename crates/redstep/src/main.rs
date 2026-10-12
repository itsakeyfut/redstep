//! The thin CLI: run every registered security test, print a `cargo test`-style
//! summary, and optionally write the canonical JSON.
//!
//! The terminal summary and the JSON are two renderers over one canonical
//! [`Report`](redstep::report::Report), so they cannot disagree (ADR-0005). The
//! argument surface is deliberately minimal; it grows with the environment unit
//! (ADR-0003), which later supplies scope from the lab definition rather than
//! from `--allow`.

use redstep::report;
use redstep::{Scope, run};
use std::process::ExitCode;

fn main() -> ExitCode {
    let (scope, json_path) = match parse_args(std::env::args().skip(1)) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!("usage: redstep [--allow host:port]... [--json path]");
            return ExitCode::from(2);
        }
    };

    let summary = match run(scope) {
        Ok(summary) => summary,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let report = report::build(&summary);

    if report.results.is_empty() {
        // Say so rather than exit silently: an empty run is not a pass, and a
        // bare non-zero exit with no output looks like a crash (the exit code is
        // still non-zero, see Report::exit_code, CLAUDE.md row 6).
        eprintln!("no security tests were discovered");
    }

    print!("{}", report::render_terminal(&report));

    if let Some(path) = &json_path
        && let Err(err) = std::fs::write(path, report::to_json(&report))
    {
        eprintln!("error: could not write {path}: {err}");
        return ExitCode::FAILURE;
    }

    // The status is a field of the canonical JSON (ADR-0005). Map it to a
    // process code explicitly rather than casting: `build` only ever produces 0
    // or 1, but `report.exit_code` is a public `i32`, and `as u8` would wrap a
    // stray value (256 -> 0) into a false success (CLAUDE.md row 6).
    if report.exit_code == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Parse `--allow host:port` (repeatable) and an optional `--json path` into a
/// scope and a JSON destination. Default-deny: no `--allow` yields an empty
/// scope that allows nothing.
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<(Scope, Option<String>), String> {
    let mut builder = Scope::builder();
    let mut json_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--allow" => {
                let spec = args.next().ok_or("--allow needs a host:port")?;
                builder = builder.allow(&spec).map_err(|e| e.to_string())?;
            }
            "--json" => {
                json_path = Some(args.next().ok_or("--json needs a path")?);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok((builder.build(), json_path))
}
