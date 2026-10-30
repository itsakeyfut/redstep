//! The isolated lab's topology: the segments, the workloads in them, the
//! boundaries between them, and the attacker's vantage (ADR-0003).
//!
//! Pure model layer (docs/rules/design.md section 2): an `Environment` is a
//! validated value with no Docker and no IO. Standing it up with bollard, the
//! boundary self-check, and resolving scope from it are later units; this is the
//! definition they read. The network boundary is framework-owned because it is
//! the thing under test (ADR-0003); the workload *content* is the user's,
//! referenced by image.
//!
//! The definition is built in code through [`Environment::builder`], valid by
//! construction like [`Scope`](crate::Scope); the YAML/DSL definition format is
//! ADR-0003's open question, deferred to M2.

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

/// What a workload runs in the lab (#46). This is a lab-topology distinction
/// (what command the container runs), not the scanner sense of a "service"
/// discovered at a `host:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadKind {
    /// A placeholder kept alive by `sleep` so the topology is inspectable; it
    /// runs no service. The boundary demo's stand-ins are this (#18/#28): a
    /// busybox image whose default command would exit at once. Assumes the image
    /// declares no `ENTRYPOINT`: Docker appends `Cmd` to an entrypoint, so with
    /// one the `sleep` would become its argument rather than the command.
    Standin,
    /// A real service. `command: None` runs the image's own default command (a
    /// real app image: postgres, the vulnerable web tier of #47); `Some` runs an
    /// explicit command (a listener in a test, or an app needing start args). An
    /// empty `Some` command is refused by [`EnvironmentBuilder::build`].
    Service { command: Option<Vec<String>> },
}

/// A workload placed in a segment. The framework owns the boundary; the user
/// supplies the content, referenced by `image` (ADR-0003). It is either a
/// `Standin` (kept alive, no service) or a real `Service` (#46).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    name: String,
    image: String,
    segment: String,
    kind: WorkloadKind,
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

    /// Whether this is a stand-in or a real service, and what it runs (#46).
    pub fn kind(&self) -> &WorkloadKind {
        &self.kind
    }
}

/// A declared boundary from one segment to another. `allow` is the list of
/// permitted `workload:port` specs (ADR-0003's shape); an empty `allow` means
/// the path is blocked, which is the MVP's `internet -> internal`.
///
/// A plain boundary ([`EnvironmentBuilder::boundary`]) is membership-only
/// (ADR-0011): there is no mechanism to enforce a port-level `allow`, so
/// [`EnvironmentBuilder::build`] refuses a non-empty one rather than hold a
/// permission the lab cannot keep (RK-005). A gateway-mediated boundary
/// ([`EnvironmentBuilder::gateway_boundary`]) declares a firewall gateway to
/// enforce it, so it may carry a validated `allow`; at v0.3.0 the gateway is a
/// structural mediator (#113) and the port rules that act on `allow`, with the
/// self-check that verifies them, are #114.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Boundary {
    from: String,
    to: String,
    allow: Vec<String>,
    gateway: bool,
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

    /// Whether a firewall gateway mediates this boundary (ADR-0011). A plain
    /// boundary is membership-only and carries an empty `allow`; a
    /// gateway-mediated one may carry a validated `allow` the gateway enforces.
    pub fn is_gateway_mediated(&self) -> bool {
        self.gateway
    }
}

/// The lab topology, valid by construction: its builder checked that every
/// reference resolves (ADR-0003).
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
    /// part of ADR-0012/ADR-0017 modelled here: a starting segment, not the
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
    workloads: Vec<(String, String, String, WorkloadKind)>,
    boundaries: Vec<(String, String, Vec<String>, bool)>,
    vantage: Option<String>,
}

impl EnvironmentBuilder {
    /// Declare a segment.
    pub fn segment(mut self, name: &str) -> Self {
        self.segments.push(name.to_owned());
        self
    }

    /// Declare a stand-in workload (`name`) from `image`, placed in `segment`:
    /// a placeholder kept alive by `sleep`, running no service (#46). Use
    /// [`service`](Self::service) for a workload that runs its image's own
    /// service: a stand-in's `image` is never started, so a real app image
    /// declared here would silently run `sleep` instead of its service.
    pub fn standin(mut self, name: &str, image: &str, segment: &str) -> Self {
        self.workloads.push((
            name.to_owned(),
            image.to_owned(),
            segment.to_owned(),
            WorkloadKind::Standin,
        ));
        self
    }

    /// Declare a real-service workload that runs its image's own default command
    /// (a real app image, e.g. a database or the vulnerable web tier, #46/#47).
    /// An image that declares no `CMD` (and no `ENTRYPOINT`) fails to start at
    /// bring-up, surfaced as [`Error::LabUnavailable`].
    pub fn service(mut self, name: &str, image: &str, segment: &str) -> Self {
        self.workloads.push((
            name.to_owned(),
            image.to_owned(),
            segment.to_owned(),
            WorkloadKind::Service { command: None },
        ));
        self
    }

    /// Declare a real-service workload that runs an explicit `command` (a
    /// listener in a test, or an app needing start args, #46).
    pub fn service_cmd(mut self, name: &str, image: &str, segment: &str, command: &[&str]) -> Self {
        let command = command.iter().map(|c| (*c).to_owned()).collect();
        self.workloads.push((
            name.to_owned(),
            image.to_owned(),
            segment.to_owned(),
            WorkloadKind::Service {
                command: Some(command),
            },
        ));
        self
    }

    /// Declare a membership-only boundary from `from` to `to` permitting `allow`
    /// (empty blocks the path). A non-empty `allow` is refused at
    /// [`build`](Self::build), because nothing enforces a port-level permission on
    /// a membership-only boundary (RK-005); use
    /// [`gateway_boundary`](Self::gateway_boundary) for a gateway-enforced allow.
    pub fn boundary(mut self, from: &str, to: &str, allow: &[&str]) -> Self {
        let allow = allow.iter().map(|spec| (*spec).to_owned()).collect();
        self.boundaries
            .push((from.to_owned(), to.to_owned(), allow, false));
        self
    }

    /// Declare a boundary from `from` to `to` enforced by a firewall gateway,
    /// permitting `allow` (`workload:port` specs; an empty `allow` opens nothing).
    /// Unlike [`boundary`](Self::boundary) this may carry a non-empty `allow`: a
    /// gateway is declared to enforce it (ADR-0011). At v0.3.0 the gateway is a
    /// structural mediator, a container dual-homed on both segment networks
    /// (#113); the port rules that act on `allow` and the self-check that verifies
    /// them are #114. [`build`](Self::build) refuses an `allow` the gateway cannot
    /// enforce (a self-loop, a malformed spec, or a workload that is not declared
    /// or not in the `to` segment).
    pub fn gateway_boundary(mut self, from: &str, to: &str, allow: &[&str]) -> Self {
        let allow = allow.iter().map(|spec| (*spec).to_owned()).collect();
        self.boundaries
            .push((from.to_owned(), to.to_owned(), allow, true));
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
    /// name (see `is_valid_lab_name`), a plain boundary's `allow` must be empty
    /// (nothing enforces a port-level allow without a gateway, so the model
    /// refuses one fail-closed, RK-005), and a gateway boundary's `allow` must be
    /// one the gateway can enforce (distinct segments, each spec a `workload:port`
    /// naming a declared workload in the `to` segment); otherwise
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
        for (name, image, segment, kind) in self.workloads {
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
            // A `Service` with an explicit but empty command is refused: an empty
            // argv serializes as `"Cmd": []`, which the daemon treats like no
            // command at all, so it silently behaves as `.service(..)` while the
            // type says a command was given. `.service(..)` is the way to ask for
            // the image default (#46 review).
            if let WorkloadKind::Service {
                command: Some(argv),
            } = &kind
                && (argv.is_empty() || argv[0].trim().is_empty())
            {
                return Err(invalid(format!(
                    "workload {name:?} has an empty service command; use .service(..) \
                     for the image's own command, or give a non-empty one"
                )));
            }
            workloads.push(Workload {
                name,
                image,
                segment,
                kind,
            });
        }

        let mut boundaries: Vec<Boundary> = Vec::new();
        for (from, to, allow, gateway) in self.boundaries {
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
            if gateway {
                // A gateway boundary may carry an `allow`, but only one the gateway
                // can actually enforce: it bridges two distinct segments, and each
                // spec must name a declared workload in the `to` segment on a valid
                // port. An opening the gateway cannot hold is refused, not built
                // (RK-005): a topology that reads as allowed while nothing holds the
                // line is this project's off-scale failure turned into a value.
                if from == to {
                    return Err(invalid(format!(
                        "gateway boundary {from:?} -> {to:?} bridges a segment to itself; \
                         a gateway mediates a path between two distinct segments"
                    )));
                }
                for spec in &allow {
                    let Some((workload, _port)) = parse_allow_spec(spec) else {
                        return Err(invalid(format!(
                            "gateway boundary {from:?} -> {to:?} allow spec {spec:?} is not a \
                             valid workload:port (a workload name, a colon, a port 1-65535)"
                        )));
                    };
                    match workloads.iter().find(|w| w.name == workload) {
                        None => {
                            return Err(invalid(format!(
                                "gateway boundary {from:?} -> {to:?} allow spec {spec:?} names \
                                 workload {workload:?}, which is not declared"
                            )));
                        }
                        Some(w) if w.segment != to => {
                            return Err(invalid(format!(
                                "gateway boundary {from:?} -> {to:?} allow spec {spec:?} names \
                                 workload {workload:?} in segment {seg:?}, not the boundary's \
                                 {to:?} segment",
                                seg = w.segment
                            )));
                        }
                        Some(_) => {}
                    }
                }
            } else if !allow.is_empty() {
                // A membership-only boundary cannot enforce a port-level allow, so
                // the model refuses one fail-closed rather than hold a permission
                // the lab cannot keep (RK-005). Use `.gateway_boundary` for a
                // gateway-enforced allow.
                return Err(invalid(format!(
                    "boundary {from:?} -> {to:?} carries a port-level allow {allow:?}, \
                     but a membership-only boundary cannot enforce one; use a gateway \
                     boundary, or leave allow empty (ADR-0011, RK-005)"
                )));
            }
            boundaries.push(Boundary {
                from,
                to,
                allow,
                gateway,
            });
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

/// Split a gateway boundary's `allow` spec `"workload:port"` into its workload
/// name and port, or `None` if it is not that shape: it must have a `:`, a
/// non-empty workload name, and a port that parses as a non-zero `u16`
/// (1-65535). Whether the workload is declared and sits in the boundary's `to`
/// segment is checked by [`EnvironmentBuilder::build`], which has the workload
/// list; this is the pure syntactic half, unit-tested without it. A workload
/// name is a valid lab name and so carries no `:`, so the last `:` separates the
/// port.
///
/// The guard is `parse_allow_spec_reads_workload_and_port`.
fn parse_allow_spec(spec: &str) -> Option<(&str, u16)> {
    let (workload, port) = spec.rsplit_once(':')?;
    if workload.is_empty() {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some((workload, port))
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

    /// Guard: the builder tags each workload with its kind (#46). `.standin`
    /// is a stand-in; `.service` is a real service running the image's own
    /// command (`None`); `.service_cmd` is a real service with an explicit
    /// command. Mutation: make `.service` build a `Standin` (or `.standin` a
    /// `Service`) -> the kind assertion fails.
    #[test]
    fn builder_tags_each_workload_with_its_kind() {
        let env = Environment::builder()
            .segment("s")
            .vantage("s")
            .standin("standin", "busybox:1", "s")
            .service("app", "postgres:16", "s")
            .service_cmd("listener", "busybox:1", "s", &["nc", "-l"])
            .build()
            .expect("valid environment");

        let kind = |name: &str| env.workload(name).expect("declared").kind().clone();
        assert_eq!(kind("standin"), WorkloadKind::Standin);
        assert_eq!(kind("app"), WorkloadKind::Service { command: None });
        assert_eq!(
            kind("listener"),
            WorkloadKind::Service {
                command: Some(vec!["nc".to_owned(), "-l".to_owned()]),
            }
        );
    }

    /// Guard: a service workload with an explicit but empty command is refused,
    /// because an empty argv serializes as `"Cmd": []` and the daemon then runs
    /// the image default, silently behaving as `.service(..)` while the type says
    /// a command was given (#46 review). An empty first argument (the program) is
    /// refused the same way. Mutation: drop the empty-command check in `build`
    /// -> `service_cmd(.., &[])` builds -> this fails.
    #[test]
    fn a_service_with_an_empty_command_is_refused() {
        let empty = Environment::builder()
            .segment("s")
            .vantage("s")
            .service_cmd("svc", "busybox:1", "s", &[])
            .build();
        assert!(
            matches!(&empty, Err(Error::InvalidEnvironment { reason }) if reason.contains("empty service command")),
            "an empty command: {empty:?}"
        );

        let blank_program = Environment::builder()
            .segment("s")
            .vantage("s")
            .service_cmd("svc", "busybox:1", "s", &["   "])
            .build();
        assert!(
            matches!(&blank_program, Err(Error::InvalidEnvironment { reason }) if reason.contains("empty service command")),
            "a blank program argument: {blank_program:?}"
        );
    }

    /// The MVP topology: internet/internal, the 3-tier app in internal, the
    /// attacker's vantage external, and the internet -> internal path blocked.
    /// `internal` is declared first so the vantage (`internet`) is not the first
    /// segment, which lets the happy-path test below pin `vantage_segment`.
    fn mvp() -> EnvironmentBuilder {
        Environment::builder()
            .segment("internal")
            .segment("internet")
            .standin("web", "redstep/web:mvp", "internal")
            .standin("api", "redstep/api:mvp", "internal")
            .standin("db", "postgres:16", "internal")
            .vantage("internet")
            .boundary("internet", "internal", &[])
    }

    /// Guard: the MVP environment validates and carries its topology back field
    /// for field, and its `.boundary` reads as not gateway-mediated (the false
    /// direction of `is_gateway_mediated`, which `bring_up`'s gateway filter
    /// depends on: a plain boundary reading `true` would spawn a spurious
    /// gateway). Mutation: have `vantage_segment` return `segments[0].name()` ->
    /// this fails, because the fixture's vantage is not its first segment; swap
    /// `Workload::image` and `segment` bodies -> the db assertions fail; make
    /// `is_gateway_mediated` return `true` -> the `!is_gateway_mediated` assertion
    /// fails.
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
        assert!(
            !boundary.is_gateway_mediated(),
            "a plain boundary is not gateway-mediated"
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

    /// A gateway-boundary fixture: a `dmz` foothold segment, an `internal`
    /// segment with a `web` service, and the attacker on `dmz`. The gateway
    /// tests declare a `dmz -> internal` boundary on top of this.
    fn gateway_base() -> EnvironmentBuilder {
        Environment::builder()
            .segment("dmz")
            .segment("internal")
            .vantage("dmz")
            .standin("foot", "busybox:1", "dmz")
            .service("web", "busybox:1", "internal")
    }

    /// Guard: a gateway-mediated boundary accepts a non-empty `allow` that the
    /// gateway can enforce (a declared workload in the `to` segment on a valid
    /// port), and the boundary reports itself gateway-mediated. This is #113's
    /// acceptance criterion 1 at the model level, and the companion to the
    /// still-refused plain boundary above (criterion 2). Mutation: make `build`
    /// treat a gateway boundary like a plain one (refuse its allow) -> the
    /// `expect` panics; make `gateway_boundary` push `false` (or
    /// `is_gateway_mediated` return `false`) -> the `is_gateway_mediated`
    /// assertion fails.
    #[test]
    fn a_gateway_boundary_accepts_a_validated_allow() {
        let env = gateway_base()
            .gateway_boundary("dmz", "internal", &["web:443"])
            .build()
            .expect("a gateway boundary with a valid allow builds");
        let boundary = &env.boundaries()[0];
        assert!(
            boundary.is_gateway_mediated(),
            "the boundary must report itself gateway-mediated"
        );
        assert_eq!(boundary.allow(), ["web:443"]);
    }

    /// Guard: a gateway boundary whose `allow` the gateway cannot enforce is
    /// refused, not built (#113 acceptance criterion 3, RK-005): a workload not
    /// in the `to` segment, an undeclared workload, a malformed spec, a port of
    /// 0, and a gateway bridging a segment to itself. Mutation: drop the
    /// allow-spec validation loop in `build` -> the wrong-segment, unknown,
    /// malformed, and port-0 cases build; drop the `from == to` check -> the
    /// self-loop builds. Each makes this fail.
    #[test]
    fn a_gateway_that_cannot_enforce_is_refused() {
        // `foot` is in `dmz`, not the boundary's `to` segment `internal`.
        let wrong_segment = gateway_base()
            .gateway_boundary("dmz", "internal", &["foot:80"])
            .build();
        assert!(
            matches!(&wrong_segment, Err(Error::InvalidEnvironment { reason }) if reason.contains("foot") && reason.contains("segment")),
            "workload not in the to segment: {wrong_segment:?}"
        );

        let unknown = gateway_base()
            .gateway_boundary("dmz", "internal", &["ghost:80"])
            .build();
        assert!(
            matches!(&unknown, Err(Error::InvalidEnvironment { reason }) if reason.contains("ghost") && reason.contains("not declared")),
            "undeclared workload: {unknown:?}"
        );

        let malformed = gateway_base()
            .gateway_boundary("dmz", "internal", &["web"])
            .build();
        assert!(
            matches!(&malformed, Err(Error::InvalidEnvironment { reason }) if reason.contains("workload:port")),
            "a spec with no port: {malformed:?}"
        );

        let port_zero = gateway_base()
            .gateway_boundary("dmz", "internal", &["web:0"])
            .build();
        assert!(
            matches!(&port_zero, Err(Error::InvalidEnvironment { reason }) if reason.contains("workload:port")),
            "port 0 is not a usable port: {port_zero:?}"
        );

        let self_loop = gateway_base()
            .gateway_boundary("dmz", "dmz", &["foot:80"])
            .build();
        assert!(
            matches!(&self_loop, Err(Error::InvalidEnvironment { reason }) if reason.contains("itself")),
            "a gateway bridging a segment to itself: {self_loop:?}"
        );
    }

    /// Guard: `parse_allow_spec` reads `workload:port`, and rejects a spec with
    /// no port, a port of 0, a port past the `u16` range, and an empty workload.
    /// Mutation: drop the `port == 0` rejection -> `"web:0"` parses -> this
    /// fails; drop the empty-workload check -> `":443"` parses -> this fails.
    #[test]
    fn parse_allow_spec_reads_workload_and_port() {
        assert_eq!(parse_allow_spec("web:443"), Some(("web", 443)));
        assert_eq!(parse_allow_spec("web"), None, "no port");
        assert_eq!(parse_allow_spec("web:0"), None, "port 0 is not usable");
        assert_eq!(parse_allow_spec("web:99999"), None, "port past u16");
        assert_eq!(parse_allow_spec(":443"), None, "empty workload");
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
        let result = mvp().standin("cache", "redis:7", "nowhere").build();
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
        let dup_workload = mvp().standin("db", "mysql:8", "internet").build();
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
                .standin(name, "busybox:1", "internet")
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
                .standin(name, "busybox:1", "internet")
                .build();
            assert!(
                built.is_ok(),
                "workload name {name:?} should build: {built:?}"
            );
        }
    }
}
