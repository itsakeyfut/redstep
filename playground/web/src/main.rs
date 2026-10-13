//! The attacker-facing web tier of the redstep SQLi playground (#47): a thin
//! forwarder, and the entry the attacker vantage reaches (nothing is published
//! outside the egress-less lab). It relays `GET /lookup?<query>` to the api verbatim,
//! so the injectable parameter is preserved, and its `/health` reaches the api so
//! the readiness gate (bring_up, #47) waits for the whole `web -> api -> db`
//! chain. A security test fixture, not product code; excluded from the cargo
//! workspace with the rest of `playground/`.

use std::io::{Read, Write};

fn main() {
    // `/app healthcheck` backs the image HEALTHCHECK (no shell in the distroless
    // runtime); it reaches this process's own `/health`, which reaches the api.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(match http_get("127.0.0.1", 8080, "/health") {
            Ok((200, _)) => 0,
            _ => 1,
        });
    }

    let server = tiny_http::Server::http("0.0.0.0:8080").expect("bind :8080");
    for request in server.incoming_requests() {
        let (status, body) = handle(request.url());
        let response = tiny_http::Response::from_string(body).with_status_code(status);
        let _ = request.respond(response);
    }
}

fn handle(url: &str) -> (u16, String) {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    match path {
        // Healthy only when the api (and, through it, the seeded db) answers.
        "/health" => match http_get("api", 8081, "/health") {
            Ok((200, _)) => (200, "ok".to_owned()),
            _ => (503, "api unavailable".to_owned()),
        },
        // Relay the raw query verbatim so the injection reaches the api unchanged.
        "/lookup" => match http_get("api", 8081, &format!("/lookup?{query}")) {
            Ok((code, body)) => (code, body),
            Err(e) => (502, format!("upstream error: {e}")),
        },
        _ => (404, "not found".to_owned()),
    }
}

/// A minimal blocking HTTP/1.0 GET for the forward hop and the healthcheck.
/// Connection: close, so the upstream ends the body and `read_to_string` sees EOF.
/// Duplicated in the api fixture on purpose: the two are separate,
/// workspace-excluded crates with no shared crate to hold it.
fn http_get(host: &str, port: u16, path: &str) -> std::io::Result<(u16, String)> {
    let mut stream = std::net::TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}
