//! The scope allowlist and the only way to produce a target a capability may
//! act on.
//!
//! Pure model layer (docs/rules/design.md). A [`ScopedTarget`] has no public
//! constructor: the only way to obtain one is `Scope::resolve`, so a later
//! capability can accept a target that nothing but the gate produced
//! (docs/rules/security.md section 2). The default [`Scope`] is empty, which
//! denies everything.

use crate::error::{Error, Result};

/// A target that has passed the scope gate. Constructible only by
/// `Scope::resolve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedTarget {
    host: String,
    port: u16,
}

impl ScopedTarget {
    /// The resolved host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The resolved port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// An allowlist of `host:port` targets. Default-deny: an empty scope allows
/// nothing.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    allow: Vec<(String, u16)>,
}

impl Scope {
    /// Start building a scope.
    pub fn builder() -> ScopeBuilder {
        ScopeBuilder::default()
    }

    /// Resolve a `host:port` specification against the allowlist.
    ///
    /// A malformed spec is [`Error::InvalidTarget`] (never a panic); a
    /// well-formed spec that is not allowed is [`Error::OutOfScope`]. Both
    /// happen before any action, so an out-of-scope target cannot be acted on.
    ///
    /// `pub(crate)` on purpose: a test reaches it through
    /// [`TestContext::resolve`](crate::TestContext::resolve), and nothing
    /// outside the crate resolves a target by any other route.
    pub(crate) fn resolve(&self, spec: &str) -> Result<ScopedTarget> {
        let (host, port) = parse_host_port(spec)?;
        if self.allow.iter().any(|(h, p)| h == &host && *p == port) {
            Ok(ScopedTarget { host, port })
        } else {
            Err(Error::OutOfScope {
                spec: spec.to_owned(),
            })
        }
    }
}

/// Builder for a [`Scope`].
#[derive(Debug, Default)]
pub struct ScopeBuilder {
    allow: Vec<(String, u16)>,
}

impl ScopeBuilder {
    /// Add a `host:port` target to the allowlist. A malformed spec is rejected
    /// here rather than at resolve time.
    pub fn allow(mut self, spec: &str) -> Result<Self> {
        let (host, port) = parse_host_port(spec)?;
        self.allow.push((host, port));
        Ok(self)
    }

    /// Finish building. The scope is valid by construction.
    pub fn build(self) -> Scope {
        Scope { allow: self.allow }
    }
}

/// Parse a `host:port` specification. MVP matches a literal host and port; a
/// named target (`web`) comes with the environment unit (Decision C).
fn parse_host_port(spec: &str) -> Result<(String, u16)> {
    let invalid = |reason: &str| Error::InvalidTarget {
        spec: spec.to_owned(),
        reason: reason.to_owned(),
    };

    let (host, port_str) = spec
        .rsplit_once(':')
        .ok_or_else(|| invalid("expected host:port"))?;
    if host.is_empty() {
        return Err(invalid("empty host"));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| invalid(&format!("invalid port {port_str:?}")))?;
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_allowing(spec: &str) -> Scope {
        Scope::builder()
            .allow(spec)
            .expect("fixture spec is valid")
            .build()
    }

    /// Guard: resolving a target that is not in the allowlist is a hard error,
    /// returned before any action. Mutation: make `resolve` return the target
    /// regardless of membership -> this returns `Ok` -> fails.
    #[test]
    fn out_of_scope_target_should_error_before_acting() {
        let scope = scope_allowing("web:80");
        let err = scope.resolve("db:5432").expect_err("db is not allowed");
        assert!(matches!(err, Error::OutOfScope { .. }));
    }

    /// Guard: an allowed host:port resolves to a target carrying that exact host
    /// and port. Mutation: make `ScopedTarget` carry a fixed host or port -> an
    /// accessor assertion fails. (Membership itself is guarded by the two tests
    /// below.)
    #[test]
    fn in_scope_host_port_resolves() {
        let scope = scope_allowing("web:80");
        let target = scope.resolve("web:80").expect("web:80 is allowed");
        assert_eq!(target.host(), "web");
        assert_eq!(target.port(), 80);
    }

    /// Guard: membership compares the port, not only the host. Mutation: match
    /// on the host alone -> `web:81` resolves against an allowlist of `web:80`
    /// -> fails. Without this a capability could reach a port never allowed.
    #[test]
    fn resolve_rejects_allowed_host_wrong_port() {
        let scope = scope_allowing("web:80");
        let err = scope
            .resolve("web:81")
            .expect_err("wrong port is out of scope");
        assert!(matches!(err, Error::OutOfScope { .. }));
    }

    /// Guard: membership compares the host, not only the port. Mutation: match
    /// on the port alone -> `api:80` resolves against an allowlist of `web:80`
    /// -> fails. Without this a capability could reach a host never allowed.
    #[test]
    fn resolve_rejects_wrong_host_allowed_port() {
        let scope = scope_allowing("web:80");
        let err = scope
            .resolve("api:80")
            .expect_err("wrong host is out of scope");
        assert!(matches!(err, Error::OutOfScope { .. }));
    }

    /// Guard: the empty (default) scope allows nothing. Mutation: default the
    /// allowlist to permit -> this resolves -> fails.
    #[test]
    fn empty_scope_should_allow_nothing() {
        let scope = Scope::default();
        let err = scope.resolve("web:80").expect_err("empty scope denies all");
        assert!(matches!(err, Error::OutOfScope { .. }));
    }

    /// Guard: a malformed spec is an error, not a panic. Mutation: `unwrap` the
    /// port parse -> this panics instead of returning `Err` -> fails.
    #[test]
    fn invalid_target_spec_is_error_not_panic() {
        let scope = Scope::default();
        for bad in ["not-a-target", "web:", ":80", "web:http", "web:99999"] {
            let err = scope.resolve(bad).expect_err("malformed spec");
            assert!(matches!(err, Error::InvalidTarget { .. }), "spec {bad:?}");
        }
    }

    proptest::proptest! {
        /// Guard: `resolve` never panics on arbitrary input
        /// (docs/rules/security.md section 5). Mutation: any `unwrap`/`expect`
        /// on parsed input -> a crafted input panics -> proptest shrinks to it.
        #[test]
        fn resolve_never_panics_on_arbitrary_input(spec in ".*") {
            let scope = Scope::default();
            let _ = scope.resolve(&spec);
        }
    }
}
