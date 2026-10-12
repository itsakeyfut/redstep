//! The isolated lab's topology: the segments, the workloads in them, the
//! boundaries between them, and the attacker's vantage (Decision C).
//!
//! Pure model layer (docs/rules/design.md section 2): an `Environment` is a
//! validated value with no Docker and no IO. Standing it up with bollard, the
//! boundary self-check, and resolving scope from it are later units; this is the
//! definition they read. The network boundary is framework-owned because it is
//! the thing under test (Decision C); the workload *content* is the user's,
//! referenced by image.
//!
//! The definition is built in code through [`Environment::builder`], valid by
//! construction like [`Scope`](crate::Scope); the YAML/DSL definition format is
//! Decision C's open question, deferred to M2.

use crate::error::{Error, Result};

/// A named network segment (one Docker network at bring-up), e.g. the MVP's
/// `internet` and `internal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    name: String,
}

impl Segment {
    /// The segment's name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A workload placed in a segment. The framework owns the boundary; the user
/// supplies the content, referenced by `image` (Decision C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    name: String,
    image: String,
    segment: String,
}

impl Workload {
    /// The workload's name, e.g. `"db"`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The image reference the user supplies, e.g. `"postgres:16"`.
    pub fn image(&self) -> &str {
        &self.image
    }

    /// The segment the workload sits in.
    pub fn segment(&self) -> &str {
        &self.segment
    }
}

/// A declared boundary from one segment to another. `allow` is the list of
/// permitted `workload:port` specs (Decision C's shape); an empty `allow` means
/// the path is blocked, which is the MVP's `internet -> internal`.
///
/// Nothing enforces a port-level `allow` yet: the MVP's boundaries are
/// membership-only (Decision N), so [`EnvironmentBuilder::build`] refuses a
/// non-empty one rather than hold a permission the lab cannot keep. The field
/// stays for the firewall gateway (Decision N, M3) that will enforce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Boundary {
    from: String,
    to: String,
    allow: Vec<String>,
}

impl Boundary {
    /// The segment the boundary leads from.
    pub fn from(&self) -> &str {
        &self.from
    }

    /// The segment the boundary leads to.
    pub fn to(&self) -> &str {
        &self.to
    }

    /// The permitted `workload:port` specs; empty means the path is blocked.
    pub fn allow(&self) -> &[String] {
        &self.allow
    }
}

/// The lab topology, valid by construction: its builder checked that every
/// reference resolves (Decision C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    segments: Vec<Segment>,
    workloads: Vec<Workload>,
    boundaries: Vec<Boundary>,
    vantage: String,
}

impl Environment {
    /// Start building an environment.
    pub fn builder() -> EnvironmentBuilder {
        EnvironmentBuilder::default()
    }

    /// The declared segments.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// The declared workloads.
    pub fn workloads(&self) -> &[Workload] {
        &self.workloads
    }

    /// The declared boundaries.
    pub fn boundaries(&self) -> &[Boundary] {
        &self.boundaries
    }

    /// The segment the attacker's vantage sits in. The vantage is the minimal
    /// part of Decision L/P modelled here: a starting segment, not the
    /// AttackerState graph.
    pub fn vantage_segment(&self) -> &str {
        &self.vantage
    }

    /// The workload with this name, if any. A lookup the later units (bring-up,
    /// scope resolution) use to turn a named target into its segment.
    pub fn workload(&self, name: &str) -> Option<&Workload> {
        self.workloads.iter().find(|w| w.name == name)
    }
}

/// Builder for an [`Environment`]. [`build`](Self::build) validates the topology
/// and is the only way to obtain an `Environment`, so one that exists is one
/// whose references all resolve.
#[derive(Debug, Default)]
pub struct EnvironmentBuilder {
    segments: Vec<String>,
    workloads: Vec<(String, String, String)>,
    boundaries: Vec<(String, String, Vec<String>)>,
    vantage: Option<String>,
}

impl EnvironmentBuilder {
    /// Declare a segment.
    pub fn segment(mut self, name: &str) -> Self {
        self.segments.push(name.to_owned());
        self
    }

    /// Declare a workload (`name`) from `image`, placed in `segment`.
    pub fn workload(mut self, name: &str, image: &str, segment: &str) -> Self {
        self.workloads
            .push((name.to_owned(), image.to_owned(), segment.to_owned()));
        self
    }

    /// Declare a boundary from `from` to `to` permitting `allow` (empty blocks
    /// the path; a non-empty `allow` is refused until the firewall gateway, see
    /// [`build`](Self::build)).
    pub fn boundary(mut self, from: &str, to: &str, allow: &[&str]) -> Self {
        let allow = allow.iter().map(|spec| (*spec).to_owned()).collect();
        self.boundaries
            .push((from.to_owned(), to.to_owned(), allow));
        self
    }

    /// Place the attacker's vantage segment.
    pub fn vantage(mut self, segment: &str) -> Self {
        self.vantage = Some(segment.to_owned());
        self
    }

    /// Validate the topology and build the environment. Every reference must
    /// name a declared segment, names must be unique, the vantage segment must
    /// be set and declared, every segment and workload name must be a valid lab
    /// name (see `is_valid_lab_name`), and every boundary's `allow`
    /// must be empty (the membership-only MVP cannot enforce a port-level allow,
    /// so the model refuses one fail-closed); otherwise
    /// [`Error::InvalidEnvironment`].
    pub fn build(self) -> Result<Environment> {
        let invalid = |reason: String| Error::InvalidEnvironment { reason };

        let mut segments: Vec<String> = Vec::new();
        for name in self.segments {
            if !is_valid_lab_name(&name) {
                return Err(invalid(format!(
                    "segment name {name:?} is not a valid lab name \
                     (a lowercase letter, then lowercase letters, digits, interior hyphens)"
                )));
            }
            if segments.contains(&name) {
                return Err(invalid(format!("duplicate segment {name:?}")));
            }
            segments.push(name);
        }
        let declared = |name: &str| segments.iter().any(|s| s == name);

        let vantage = self
            .vantage
            .ok_or_else(|| invalid("no vantage segment was set".to_owned()))?;
        if !declared(&vantage) {
            return Err(invalid(format!(
                "vantage segment {vantage:?} is not a declared segment"
            )));
        }

        let mut workloads: Vec<Workload> = Vec::new();
        for (name, image, segment) in self.workloads {
            if !is_valid_lab_name(&name) {
                return Err(invalid(format!(
                    "workload name {name:?} is not a valid lab name \
                     (a lowercase letter, then lowercase letters, digits, interior hyphens)"
                )));
            }
            if workloads.iter().any(|w| w.name == name) {
                return Err(invalid(format!("duplicate workload {name:?}")));
            }
            if !declared(&segment) {
                return Err(invalid(format!(
                    "workload {name:?} is in undeclared segment {segment:?}"
                )));
            }
            workloads.push(Workload {
                name,
                image,
                segment,
            });
        }

        let mut boundaries: Vec<Boundary> = Vec::new();
        for (from, to, allow) in self.boundaries {
            if !declared(&from) {
                return Err(invalid(format!(
                    "boundary leads from undeclared segment {from:?}"
                )));
            }
            if !declared(&to) {
                return Err(invalid(format!(
                    "boundary leads to undeclared segment {to:?}"
                )));
            }
            if !allow.is_empty() {
                return Err(invalid(format!(
                    "boundary {from:?} -> {to:?} carries a port-level allow {allow:?}, \
                     but the membership-only MVP cannot enforce one; allow must be empty \
                     until the firewall gateway (Decision N, M3)"
                )));
            }
            boundaries.push(Boundary { from, to, allow });
        }

        let segments = segments.into_iter().map(|name| Segment { name }).collect();
        Ok(Environment {
            segments,
            workloads,
            boundaries,
            vantage,
        })
    }
}

/// Whether `name` is a valid lab name: a DNS-label-like identifier of at most 63
/// bytes (the DNS label limit), starting with a lowercase ASCII letter, then
/// lowercase ASCII letters, digits, and interior hyphens, with no trailing
/// hyphen.
///
/// This subset is both a valid `host:port` host and a valid Docker network alias
/// and name. The leading-letter rule is what keeps a numeric or hex address
/// literal (`16909060`, which `inet_aton` reads as `1.2.3.4`) from being a
/// declared workload, so a routable address cannot enter the scope gate's
/// allowlist on membership alone through
/// [`Scope::from_environment`](crate::Scope::from_environment). The
/// bring-up unit uses the name as a network alias (the container itself is named
/// with a run prefix), so a workload `db` is reachable in the lab as `db`.
///
/// The guard is `name_with_an_invalid_lab_name_is_rejected`.
fn is_valid_lab_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The MVP topology: internet/internal, the 3-tier app in internal, the
    /// attacker's vantage external, and the internet -> internal path blocked.
    /// `internal` is declared first so the vantage (`internet`) is not the first
    /// segment, which lets the happy-path test below pin `vantage_segment`.
    fn mvp() -> EnvironmentBuilder {
        Environment::builder()
            .segment("internal")
            .segment("internet")
            .workload("web", "redstep/web:mvp", "internal")
            .workload("api", "redstep/api:mvp", "internal")
            .workload("db", "postgres:16", "internal")
            .vantage("internet")
            .boundary("internet", "internal", &[])
    }

    /// Guard: the MVP environment validates and carries its topology back field
    /// for field. The happy-path fixture the rejection tests start from.
    /// Mutation: have `vantage_segment` return `segments[0].name()` -> this
    /// fails, because the fixture's vantage is not its first segment; swap
    /// `Workload::image` and `segment` bodies -> the db assertions fail.
    #[test]
    fn mvp_environment_builds() {
        let env = mvp().build().expect("the MVP topology is valid");

        let segment_names: Vec<&str> = env.segments().iter().map(Segment::name).collect();
        assert_eq!(segment_names, ["internal", "internet"]);

        let workload_names: Vec<&str> = env.workloads().iter().map(Workload::name).collect();
        assert_eq!(workload_names, ["web", "api", "db"]);

        let db = env.workload("db").expect("db is declared");
        assert_eq!(db.name(), "db");
        assert_eq!(db.image(), "postgres:16");
        assert_eq!(db.segment(), "internal");
        assert!(env.workload("absent").is_none());

        assert_eq!(env.vantage_segment(), "internet");

        assert_eq!(env.boundaries().len(), 1);
        let boundary = &env.boundaries()[0];
        assert_eq!(boundary.from(), "internet");
        assert_eq!(boundary.to(), "internal");
        assert!(
            boundary.allow().is_empty(),
            "the internet -> internal path is blocked"
        );
    }

    /// Guard: a boundary carrying a non-empty `allow` is refused, because the
    /// membership-only MVP cannot enforce a port-level permission and a lab must
    /// not hold one it cannot keep (CLAUDE.md's off-scale rule). Mutation: drop
    /// the `!allow.is_empty()` check in `build` -> the boundary with an allow
    /// builds -> this fails.
    #[test]
    fn a_boundary_with_a_nonempty_allow_is_refused() {
        let result = mvp().boundary("internet", "internal", &["web:443"]).build();
        assert!(
            matches!(&result, Err(Error::InvalidEnvironment { reason }) if reason.contains("allow")),
            "got {result:?}"
        );
    }

    /// Guard: a boundary that leads to or from an undeclared segment is rejected
    /// before anything is stood up, and the reason names the offending side.
    /// Mutation: drop the `to` check in `build` -> the bad-`to` environment
    /// builds -> fails; drop the `from` check -> the bad-`from` one builds ->
    /// fails.
    #[test]
    fn boundary_to_unknown_segment_is_rejected() {
        let bad_to = mvp().boundary("internet", "dmz", &[]).build();
        assert!(
            matches!(&bad_to, Err(Error::InvalidEnvironment { reason }) if reason.contains("to undeclared") && reason.contains("dmz")),
            "got {bad_to:?}"
        );

        let bad_from = mvp().boundary("dmz", "internal", &[]).build();
        assert!(
            matches!(&bad_from, Err(Error::InvalidEnvironment { reason }) if reason.contains("from undeclared") && reason.contains("dmz")),
            "got {bad_from:?}"
        );
    }

    /// Guard: a workload in an undeclared segment is rejected, and the reason
    /// names the workload and the segment. Mutation: drop the workload-segment
    /// check in `build` -> the environment builds -> fails.
    #[test]
    fn workload_in_unknown_segment_is_rejected() {
        let result = mvp().workload("cache", "redis:7", "nowhere").build();
        assert!(
            matches!(&result, Err(Error::InvalidEnvironment { reason }) if reason.contains("cache") && reason.contains("nowhere")),
            "got {result:?}"
        );
    }

    /// Guard: the vantage segment must be set and declared, and the reason says
    /// which. Mutation: drop the `ok_or_else` (no-vantage) check, or the
    /// `declared(&vantage)` check in `build` -> one of these builds -> fails.
    #[test]
    fn vantage_segment_must_be_set_and_declared() {
        let unset = Environment::builder().segment("internet").build();
        assert!(
            matches!(&unset, Err(Error::InvalidEnvironment { reason }) if reason.contains("vantage")),
            "no vantage set: {unset:?}"
        );

        let undeclared = Environment::builder()
            .segment("internet")
            .vantage("ghost")
            .build();
        assert!(
            matches!(&undeclared, Err(Error::InvalidEnvironment { reason }) if reason.contains("ghost")),
            "vantage in an undeclared segment: {undeclared:?}"
        );
    }

    /// Guard: duplicate segment or workload names are rejected by name, even when
    /// the rest differs. Mutation: drop the `segments.contains` check, or the
    /// `workloads.iter().any` check, in `build` -> the duplicate builds -> fails.
    #[test]
    fn duplicate_names_are_rejected() {
        let dup_segment = Environment::builder()
            .segment("internet")
            .segment("internet")
            .vantage("internet")
            .build();
        assert!(
            matches!(&dup_segment, Err(Error::InvalidEnvironment { reason }) if reason.contains("segment") && reason.contains("internet")),
            "duplicate segment: {dup_segment:?}"
        );

        // Same name, different image and segment: still a duplicate by name.
        let dup_workload = mvp().workload("db", "mysql:8", "internet").build();
        assert!(
            matches!(&dup_workload, Err(Error::InvalidEnvironment { reason }) if reason.contains("workload") && reason.contains("db")),
            "duplicate workload: {dup_workload:?}"
        );
    }

    /// Guard: a segment or workload name that is not a valid lab name is
    /// rejected, so a routable or Docker-illegal name cannot become an allowlist
    /// host or a network alias. Mutation: drop the leading-letter check -> the
    /// all-digit `16909060` (which `inet_aton` reads as `1.2.3.4`) builds;
    /// change `len() > 63` to `> 64` -> the 64-byte name builds; drop the
    /// trailing-hyphen check -> `web-` builds; drop digits or hyphens from the
    /// allowed set -> a valid name below fails to build. Each makes this fail.
    #[test]
    fn name_with_an_invalid_lab_name_is_rejected() {
        let sixty_four = "a".repeat(64);
        // uppercase, dot, space, dotted IP, decimal IP literal, leading digit,
        // leading hyphen, trailing hyphen, empty, over 63 bytes.
        let bad = [
            "Web",
            "web.evil",
            "my web",
            "169.254.169.254",
            "16909060",
            "0web",
            "-web",
            "web-",
            "",
            sixty_four.as_str(),
        ];
        for name in bad {
            let as_segment = Environment::builder().segment(name).vantage(name).build();
            assert!(
                matches!(&as_segment, Err(Error::InvalidEnvironment { reason }) if reason.contains("lab name")),
                "segment name {name:?}: {as_segment:?}"
            );

            let as_workload = Environment::builder()
                .segment("internet")
                .vantage("internet")
                .workload(name, "busybox:1", "internet")
                .build();
            assert!(
                matches!(&as_workload, Err(Error::InvalidEnvironment { reason }) if reason.contains("lab name")),
                "workload name {name:?}: {as_workload:?}"
            );
        }
    }

    /// Guard: a valid lab name builds, so the rejection above is not so strict it
    /// refuses legitimate names (digits, interior hyphens, and a 63-byte name are
    /// allowed). Mutation: drop digits from the allowed set -> `db2` fails to
    /// build; drop hyphens -> `web-1` fails; change `len() > 63` to `> 62` -> the
    /// 63-byte name fails. Each makes this fail.
    #[test]
    fn a_valid_lab_name_builds() {
        let sixty_three = "a".repeat(63);
        for name in ["web", "db2", "web-1", "a1", sixty_three.as_str()] {
            let built = Environment::builder()
                .segment("internet")
                .vantage("internet")
                .workload(name, "busybox:1", "internet")
                .build();
            assert!(
                built.is_ok(),
                "workload name {name:?} should build: {built:?}"
            );
        }
    }
}
