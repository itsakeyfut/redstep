//! A record of what a capability did (Decision D).
//!
//! Pure model type, and deliberately minimal: the evidence unit (#5) supersedes
//! it with the append-only store that the reports, the attack graph and the
//! success witness all project from, adding an id, a timestamp, artifacts and
//! reproduction. There is no timestamp here on purpose, so a record stays a
//! pure, comparable, testable value until that store lands.

use crate::intensity::Intensity;
use crate::observation::Confidence;

/// What one capability execution did: enough to say what happened, not yet the
/// full artifact-carrying record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// The capability that produced it, e.g. `"tcp_connect"`.
    pub capability: &'static str,
    /// The target it acted on, as `host:port`.
    pub target: String,
    /// The force it applied.
    pub intensity: Intensity,
    /// Whether the target was reachable.
    pub reachable: bool,
    /// How much to trust that.
    pub confidence: Confidence,
}
