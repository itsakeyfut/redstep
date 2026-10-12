//! The isolated lab's topology: the segments, the workloads in them, the
//! boundaries between them, and where the attacker starts (Decision C).
//!
//! Pure model layer (docs/rules/design.md section 2): a `Lab` is a validated
//! value with no Docker and no IO. Standing it up with bollard, the boundary
//! self-check, and resolving scope from it are later units; this is the
//! definition they read. The network boundary is framework-owned because it is
//! the thing under test (Decision C); the workload *content* is the user's,
//! referenced by image.
//!
//! The definition is built in code through [`Lab::builder`], valid by
//! construction like [`Scope`](crate::Scope); the YAML/DSL definition format is
//! Decision C's open question, deferred to M2.

use crate::error::{Error, Result};

/// A named network segment (one Docker network at bring-up). For the MVP:
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
/// the path is blocked, which is the MVP's `internet -> internal`. The specs are
/// held as given; parsing and enforcing them is a later unit, where the MVP's
/// membership-only capability (Decision N) decides what a non-empty `allow` can
/// mean yet.
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

/// The lab topology, valid by construction (its builder checked every reference).
/// The segments, the workloads in them, the boundaries, and the attacker's
/// starting segment (Decision C; the vantage is the minimal part of Decision L/P
/// modelled here, not the AttackerState graph).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lab {
    segments: Vec<Segment>,
    workloads: Vec<Workload>,
    boundaries: Vec<Boundary>,
    attacker: String,
}

impl Lab {
    /// Start building a lab.
    pub fn builder() -> LabBuilder {
        LabBuilder::default()
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

    /// The segment the attacker starts in (the vantage).
    pub fn attacker_segment(&self) -> &str {
        &self.attacker
    }

    /// The workload with this name, if any. A lookup the later units (bring-up,
    /// scope resolution) use to turn a named target into its segment.
    pub fn workload(&self, name: &str) -> Option<&Workload> {
        self.workloads.iter().find(|w| w.name == name)
    }
}

/// Builder for a [`Lab`]. [`build`](Self::build) validates the topology and is
/// the only way to obtain a `Lab`, so a `Lab` that exists is one whose references
/// all resolve.
#[derive(Debug, Default)]
pub struct LabBuilder {
    segments: Vec<String>,
    workloads: Vec<(String, String, String)>,
    boundaries: Vec<(String, String, Vec<String>)>,
    attacker: Option<String>,
}

impl LabBuilder {
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
    /// the path).
    pub fn boundary(mut self, from: &str, to: &str, allow: &[&str]) -> Self {
        let allow = allow.iter().map(|spec| (*spec).to_owned()).collect();
        self.boundaries
            .push((from.to_owned(), to.to_owned(), allow));
        self
    }

    /// Place the attacker's starting segment (the vantage).
    pub fn attacker(mut self, segment: &str) -> Self {
        self.attacker = Some(segment.to_owned());
        self
    }

    /// Validate the topology and build the lab. Every reference must name a
    /// declared segment, names must be unique, and the attacker's segment must be
    /// set and declared; otherwise [`Error::InvalidLab`]. The `allow` specs'
    /// contents are not checked here (that is scope resolution's parsing).
    pub fn build(self) -> Result<Lab> {
        let invalid = |reason: String| Error::InvalidLab { reason };

        let mut segments: Vec<String> = Vec::new();
        for name in self.segments {
            if segments.contains(&name) {
                return Err(invalid(format!("duplicate segment {name:?}")));
            }
            segments.push(name);
        }
        let declared = |name: &str| segments.iter().any(|s| s == name);

        let attacker = self
            .attacker
            .ok_or_else(|| invalid("no attacker segment was set".to_owned()))?;
        if !declared(&attacker) {
            return Err(invalid(format!(
                "attacker segment {attacker:?} is not a declared segment"
            )));
        }

        let mut workloads: Vec<Workload> = Vec::new();
        for (name, image, segment) in self.workloads {
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
            boundaries.push(Boundary { from, to, allow });
        }

        let segments = segments.into_iter().map(|name| Segment { name }).collect();
        Ok(Lab {
            segments,
            workloads,
            boundaries,
            attacker,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The MVP topology: internet/internal, the 3-tier app in internal, the
    /// attacker external, and the internet -> internal path blocked.
    fn mvp() -> LabBuilder {
        Lab::builder()
            .segment("internet")
            .segment("internal")
            .workload("web", "redstep/web:mvp", "internal")
            .workload("api", "redstep/api:mvp", "internal")
            .workload("db", "postgres:16", "internal")
            .attacker("internet")
            .boundary("internet", "internal", &[])
    }

    /// Guard: the MVP lab validates and carries its topology. The happy-path
    /// fixture the rejection tests start from. Mutation: not applicable; the
    /// rejection guards below cover the validation.
    #[test]
    fn mvp_lab_builds() {
        let lab = mvp().build().expect("the MVP topology is valid");
        assert_eq!(lab.segments().len(), 2);
        assert_eq!(lab.workloads().len(), 3);
        assert_eq!(lab.attacker_segment(), "internet");
        assert_eq!(
            lab.workload("db").expect("db is declared").segment(),
            "internal"
        );
        assert!(
            lab.boundaries()[0].allow().is_empty(),
            "the internet -> internal path is blocked"
        );
    }

    /// Guard: a boundary that leads to or from an undeclared segment is rejected
    /// before anything is stood up. Mutation: drop the `to` check in `build` ->
    /// the bad-`to` lab builds -> fails; drop the `from` check -> the bad-`from`
    /// lab builds -> fails.
    #[test]
    fn boundary_to_unknown_segment_is_rejected() {
        let bad_to = mvp().boundary("internet", "dmz", &[]).build();
        assert!(matches!(bad_to, Err(Error::InvalidLab { .. })));

        let bad_from = mvp().boundary("dmz", "internal", &[]).build();
        assert!(matches!(bad_from, Err(Error::InvalidLab { .. })));
    }

    /// Guard: a workload in an undeclared segment is rejected. Mutation: drop the
    /// workload-segment check in `build` -> the lab builds -> fails.
    #[test]
    fn workload_in_unknown_segment_is_rejected() {
        let result = mvp().workload("cache", "redis:7", "nowhere").build();
        assert!(matches!(result, Err(Error::InvalidLab { .. })));
    }

    /// Guard: the attacker's segment must be set and declared. Mutation: drop the
    /// `ok_or_else` (no-attacker) check, or the `declared(&attacker)` check in
    /// `build` -> one of these builds -> fails.
    #[test]
    fn attacker_segment_must_be_declared() {
        let unset = Lab::builder().segment("internet").build();
        assert!(
            matches!(unset, Err(Error::InvalidLab { .. })),
            "no attacker set"
        );

        let undeclared = Lab::builder().segment("internet").attacker("ghost").build();
        assert!(
            matches!(undeclared, Err(Error::InvalidLab { .. })),
            "attacker in an undeclared segment"
        );
    }

    /// Guard: duplicate segment or workload names are rejected. Mutation: drop the
    /// `segments.contains` check, or the `workloads.iter().any` check, in `build`
    /// -> the duplicate builds -> fails.
    #[test]
    fn duplicate_names_are_rejected() {
        let dup_segment = Lab::builder()
            .segment("internet")
            .segment("internet")
            .attacker("internet")
            .build();
        assert!(
            matches!(dup_segment, Err(Error::InvalidLab { .. })),
            "duplicate segment"
        );

        let dup_workload = mvp().workload("db", "postgres:16", "internal").build();
        assert!(
            matches!(dup_workload, Err(Error::InvalidLab { .. })),
            "duplicate workload"
        );
    }
}
