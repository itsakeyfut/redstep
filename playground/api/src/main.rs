//! A deliberately vulnerable internal API tier for the redstep SQLi playground
//! (#47). This is a security test fixture, NOT product code: `GET /lookup?name=`
//! builds its SQL by string concatenation on purpose, so a UNION injection reads
//! a DB-only flag. It exists only to be attacked inside the egress-less lab and
//! must never be deployed. The fix (a parameterized query) is the check slice,
//! issue #50.
//!
//! It is excluded from the cargo workspace (`exclude = ["playground"]`): the
//! raw-concat query is the vulnerability, so it must not sit in the framework's
//! own clippy surface, and its behaviour is checked by the orchestrator's
//! Docker-gated `sqli_playground_is_exploitable` test, not by the main gate.

use std::io::{Read, Write};

/// The db is reachable in the lab by its workload alias `db` on the shared
/// network; the credential matches `playground/db`'s baked dev constant.
const DB_CONN: &str = "host=db port=5432 user=redstep password=redstep dbname=redstep";

fn main() {
    // `/app healthcheck` backs the image HEALTHCHECK (the distroless runtime has
    // no shell), so the readiness gate (bring_up, #47) waits on a real end-to-end
    // check: the HTTP listener is up and `/health` can reach the seeded db.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(match http_get("127.0.0.1", 8081, "/health") {
            Ok((200, _)) => 0,
            _ => 1,
        });
    }

    let server = tiny_http::Server::http("0.0.0.0:8081").expect("bind :8081");
    for request in server.incoming_requests() {
        let (status, body) = handle(request.url());
        let response = tiny_http::Response::from_string(body).with_status_code(status);
        let _ = request.respond(response);
    }
}

fn handle(url: &str) -> (u16, String) {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    match path {
        // Healthy only when the seeded db answers, so web's health (which reaches
        // this) and the readiness gate reflect the whole chain being up.
        "/health" => match db_rows("SELECT 1 FROM secrets LIMIT 1") {
            Ok(_) => (200, "ok".to_owned()),
            Err(e) => (503, format!("db unavailable: {e}")),
        },
        "/lookup" => {
            let name = percent_decode(&query_param(query, "name").unwrap_or_default());
            // THE VULNERABILITY: the caller's input is concatenated straight into
            // the SQL, so `' UNION SELECT flag, 'x' FROM secrets-- ` reads the
            // DB-only flag. The fix is a parameterized query (#50).
            let sql = format!("SELECT label, body FROM notes WHERE label = '{name}'");
            match db_rows(&sql) {
                Ok(rows) => (200, rows),
                Err(e) => (500, format!("query error: {e}")),
            }
        }
        _ => (404, "not found".to_owned()),
    }
}

/// Run a simple (unprepared) query and return its rows as `|`-joined columns,
/// one row per line. A fresh connection per request keeps the fixture simple and
/// tolerant of the db starting after the api. `simple_query` runs the raw SQL
/// string with no parameters, which is exactly the injectable path. The column
/// count is read from each row (not assumed), so a one-column query like
/// `/health`'s `SELECT 1` and a two-column `/lookup` both format without panic. A
/// UNION whose column count does not match is a Postgres error, surfaced to the
/// caller as an HTTP 500, not a panic (and not a successful read).
fn db_rows(sql: &str) -> Result<String, postgres::Error> {
    let mut client = postgres::Client::connect(DB_CONN, postgres::NoTls)?;
    let mut out = String::new();
    for message in client.simple_query(sql)? {
        if let postgres::SimpleQueryMessage::Row(row) = message {
            let cols: Vec<&str> = (0..row.len()).map(|i| row.get(i).unwrap_or("")).collect();
            out.push_str(&cols.join("|"));
            out.push('\n');
        }
    }
    Ok(out)
}

/// The first value for `key` in a `a=1&b=2` query string, still percent-encoded.
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_owned())
    })
}

/// Decode `%XX` escapes and `+` in a query value, operating on bytes. Decoding on
/// bytes (not slicing the `&str`) is deliberate: `%` followed by a multibyte
/// character would otherwise slice on a non-char boundary and panic, and a panic
/// here kills the single-threaded request loop. `hex` also rejects a leading
/// `+`/`-`, which `u8::from_str_radix` would have accepted (so `%+f` stays
/// literal). Lossy for invalid UTF-8, which a fixture need not preserve.
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
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A single hex digit's value, or `None` for any non-hex byte (so `%zz`, a
/// trailing `%`, and a leading `+`/`-` are all left literal).
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A minimal blocking HTTP/1.0 GET, used by the `healthcheck` subcommand to reach
/// this process's own `/health`. Connection: close, so the server ends the body
/// and `read_to_string` sees EOF. Duplicated in the web fixture on purpose: the
/// two are separate, workspace-excluded crates with no shared crate to hold it.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard: percent_decode never panics on a `%` followed by a multibyte
    /// character (it decodes on bytes, not by slicing the str), and decodes the
    /// payloads the playground actually uses. Mutation: restore the str-slice form
    /// (`&s[i + 1..i + 3]`) -> percent_decode("%a\u{e9}") panics on a non-char
    /// boundary -> this test fails.
    #[test]
    fn percent_decode_handles_escapes_and_never_panics() {
        assert_eq!(percent_decode("a+b%20c"), "a b c");
        assert_eq!(percent_decode("%27%20%2C"), "' ,");
        assert!(percent_decode("%27%20UNION").starts_with("' UNION"));
        // A `%` before a multibyte character: left literal, and crucially no panic.
        assert_eq!(percent_decode("%a\u{e9}"), "%a\u{e9}");
        // Malformed or truncated escapes stay literal.
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("a%"), "a%");
        assert_eq!(percent_decode("a%4"), "a%4");
        // A leading sign is not read as hex (u8::from_str_radix would have).
        assert_ne!(percent_decode("%+f"), "\u{f}");
    }

    /// Guard: hex rejects every non-hex byte, including the `+`/`-` that
    /// `u8::from_str_radix` accepts. Mutation: implement `hex` via
    /// `u8::from_str_radix` on a one-byte str -> `hex(b'+')` becomes `Some` -> the
    /// sign asserts fail.
    #[test]
    fn hex_rejects_non_hex_including_signs() {
        assert_eq!(hex(b'0'), Some(0));
        assert_eq!(hex(b'9'), Some(9));
        assert_eq!(hex(b'a'), Some(10));
        assert_eq!(hex(b'F'), Some(15));
        assert_eq!(hex(b'+'), None);
        assert_eq!(hex(b'-'), None);
        assert_eq!(hex(b'g'), None);
        assert_eq!(hex(b' '), None);
    }
}
