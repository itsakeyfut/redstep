//! A deliberately vulnerable "diagnostics" tier for the redstep command-injection
//! playground (#85). This is a security test fixture, NOT product code:
//! `GET /exec?cmd=` builds a shell command by string concatenation on purpose, so
//! an injected `;`/`$()`/backtick runs in this fixture's shell (inside its own
//! container, confined to the egress-less lab, never the Docker host). It exists
//! only to be attacked inside the lab and must never be deployed.
//!
//! The `fixed` cargo feature builds the patched variant (`redstep/cmdi:fixed`):
//! `/exec` then runs the base command with an argument vector and no shell, so the
//! injection is an inert literal argument, and the attack-to-defense loop shows
//! the same probe failing against it. The two `run_exec` bodies sit side by side
//! under `#[cfg(feature = "fixed")]` so the fix is a one-function diff.
//!
//! Unlike the other playground fixtures, whose runtime is distroless (no shell),
//! this one needs a shell at runtime to demonstrate OS command injection, so its
//! Dockerfile runs on a shell-bearing base (`debian:bookworm-slim`). It is
//! excluded from the cargo workspace with the rest of `playground/`.

use std::process::{Command, Output};

// The injected command reads a sentinel file the Dockerfile bakes in at
// `/srv/cmdi_secret.txt`, whose body is the witness; the attacker (the
// orchestrator probe) supplies that path, so the fixture itself does not name it.

/// A constant banner prefixed to every `/exec` response, so a benign request has
/// a stable marker that is not derived from the input: the fix-replay positive
/// control looks for this to prove the endpoint still answers (a broken fix that
/// returned nothing would not).
const BANNER: &str = "exec result:";

fn main() {
    // `/app healthcheck` backs the image HEALTHCHECK. A bare TCP connect confirms
    // the listener is bound, so the readiness gate (bring_up) waits on a real
    // check without the runtime needing anything beyond the binary.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(match std::net::TcpStream::connect(("127.0.0.1", 8083)) {
            Ok(_) => 0,
            Err(_) => 1,
        });
    }

    let server = tiny_http::Server::http("0.0.0.0:8083").expect("bind :8083");
    for request in server.incoming_requests() {
        let (status, body) = handle(request.url());
        let response = tiny_http::Response::from_string(body).with_status_code(status);
        let _ = request.respond(response);
    }
}

fn handle(url: &str) -> (u16, String) {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    match path {
        // Healthy once the listener is up; the readiness gate reaches this.
        "/health" => (200, "ok".to_owned()),
        // THE ENDPOINT UNDER TEST: run a diagnostic command built from `cmd`.
        "/exec" => {
            let cmd = percent_decode(&query_param(query, "cmd").unwrap_or_default());
            (200, format!("{BANNER} {}", run_exec(&cmd)))
        }
        _ => (404, "not found".to_owned()),
    }
}

/// THE VULNERABILITY (`redstep/cmdi:mvp`): the caller's input is concatenated after
/// a fixed base command and run through a shell, so a `;`/`$()`/backtick executes.
/// An injected `;cat /srv/cmdi_secret.txt` reads the sentinel, whose body is the
/// witness. Returns the command's combined stdout+stderr.
#[cfg(not(feature = "fixed"))]
fn run_exec(input: &str) -> String {
    let line = format!("echo {input}");
    render(Command::new("sh").arg("-c").arg(line).output())
}

/// THE FIX (`redstep/cmdi:fixed`): the base command runs with an argument vector
/// and no shell, so the input is a single literal argument and its metacharacters
/// are inert. A benign input still returns the base command's output (the input
/// echoed), so the endpoint stays live for the fix-replay positive control.
#[cfg(feature = "fixed")]
fn run_exec(input: &str) -> String {
    render(Command::new("echo").arg(input).output())
}

/// Combined stdout then stderr of a finished command, or a readable error. The
/// mvp relies on this returning the command's output so an injected command's
/// result reaches the response body.
fn render(out: std::io::Result<Output>) -> String {
    match out {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            s
        }
        Err(e) => format!("exec error: {e}"),
    }
}

/// The first value for `key` in an `&`-separated query string. Copied from the
/// api fixture (the playground crates do not share a library).
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_owned())
    })
}

/// Decode `%XX` escapes and `+` in a query value, operating on bytes. Copied from
/// the api fixture.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(high), Some(low)) => {
                    out.push(high << 4 | low);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A single hex digit's value, or `None`. Copied from the api fixture.
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
