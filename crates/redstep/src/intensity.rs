//! How much force a capability applies (ADR-0002, ADR-0006).
//!
//! Pure model type. The intensity ladder is how the safety model gates force:
//! a capability reports its intensity, and the run path refuses anything but
//! `Safe` until the authorization and isolation proof a later unit adds unlock
//! the higher rungs (See ADR-0006).

/// The force a capability applies. `Safe` is the only rung exercisable in the
/// current build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Intensity {
    /// Fast, deterministic, non-destructive: reachability, segmentation, a
    /// spec check. Runs without any opt-in.
    Safe,
    /// Active but measured. Requires an explicit opt-in (not yet unlocked).
    Controlled,
    /// Full-force offensive tooling. Requires an opt-in and proof the target is
    /// a framework-created isolated environment (not yet unlocked).
    Aggressive,
}
