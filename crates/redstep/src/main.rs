//! The thin CLI: run every registered security test and report one line each.
//!
//! The argument surface is deliberately minimal; it grows with the runner in a
//! later unit (see Decision A's MVP note in docs/specs/design-decisions.md).
//! `--allow host:port` (repeatable) is the interim scope source; the
//! environment unit (Decision C) later supplies scope from the lab definition.

use redstep::{Scope, run};
use std::process::ExitCode;

fn main() -> ExitCode {
    let scope = match parse_scope(std::env::args().skip(1)) {
        Ok(scope) => scope,
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!("usage: redstep [--allow host:port]...");
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

    if summary.runs.is_empty() {
        // Say so rather than exit silently: an empty run is not a pass, and a
        // bare non-zero exit with no output looks like a crash (see
        // RunSummary::exit_code, CLAUDE.md row 6).
        eprintln!("no security tests were discovered");
    }

    for test in &summary.runs {
        match test.outcome.reason() {
            Some(reason) => println!("{:<5} {} ({reason})", test.outcome.label(), test.name),
            None => println!("{:<5} {}", test.outcome.label(), test.name),
        }
    }

    // 0 only if at least one test ran and all passed; non-zero otherwise.
    // exit_code is 0 or 1.
    ExitCode::from(summary.exit_code() as u8)
}

/// Parse `--allow host:port` flags into a scope. Default-deny: no flags yields
/// an empty scope that allows nothing.
fn parse_scope(mut args: impl Iterator<Item = String>) -> Result<Scope, String> {
    let mut builder = Scope::builder();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--allow" => {
                let spec = args.next().ok_or("--allow needs a host:port")?;
                builder = builder.allow(&spec).map_err(|e| e.to_string())?;
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(builder.build())
}
