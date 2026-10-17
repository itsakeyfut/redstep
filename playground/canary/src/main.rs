//! The SSRF canary for the redstep playground (#65): the out-of-band witness
//! point. It records each request it receives by logging the request path to
//! stdout (one line per request) and returns 200. The redstep orchestrator reads
//! THIS container's logs to witness that a coerced server (the SSRF target)
//! reached the canary over the egress-less lab network, which is a request that
//! never appears in the target's own response. It has no query or state endpoint:
//! there is nothing for an attacker to read back, and the witness lives only in
//! the container logs the orchestrator reads.
//!
//! A security test fixture, not product code; excluded from the cargo workspace
//! with the rest of `playground/`.

use std::net::TcpStream;

fn main() {
    // `/app healthcheck` backs the image HEALTHCHECK (no shell in the distroless
    // runtime). A bare TCP connect confirms the listener is bound WITHOUT sending a
    // request, so the readiness gate never logs a healthcheck line that a probe's
    // token search could trip over.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(match TcpStream::connect(("127.0.0.1", 8082)) {
            Ok(_) => 0,
            Err(_) => 1,
        });
    }

    let server = tiny_http::Server::http("0.0.0.0:8082").expect("bind :8082");
    for request in server.incoming_requests() {
        // One line per request. The orchestrator greps these logs for its per-probe
        // token to witness that the coerced target reached the canary.
        println!("canary received: {}", request.url());
        let response = tiny_http::Response::from_string("ok").with_status_code(200);
        let _ = request.respond(response);
    }
}
