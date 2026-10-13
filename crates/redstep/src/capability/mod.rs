//! The capability layer: an active action against a scope-resolved target.
//!
//! A capability is where force lives (See ADR-0002). The shipped [`TcpConnect`]
//! takes a [`ScopedTarget`](crate::ScopedTarget), which nothing but the scope
//! resolver produces, so it cannot reach a target that did not pass the gate
//! (docs/rules/security.md section 2). That is still a property of *that*
//! capability, not of the trait: the trait does not require holding a
//! `ScopedTarget`, so the scope gate stays per-capability. Forcing scope through
//! the type trait-wide waits for the second capability to shape the requirement
//! (#9); sealing (below) makes that safe to defer, because no external,
//! unreviewed capability can hold a raw address.
//!
//! The intensity gate is compiler-held *outside* the crate: the trait is sealed,
//! so an external crate cannot implement [`Capability`] at all, and
//! [`execute`](Capability::execute) takes an [`IntensityCleared`] token whose only
//! constructor (`IntensityCleared::issue`) is crate-private, so external code can
//! neither add a capability nor mint a token to run one.
//!
//! *Inside* the crate it is enforced but not fully compiler-held: the token is
//! not bound to the capability's own intensity. `issue` always refuses a
//! non-`Safe` intensity, and [`run`](crate::TestContext::run) is the disciplined
//! caller that mints the token from `capability.intensity()` (guarded by the
//! refusal tests), but a different in-crate caller could mint a `Safe` token and
//! hand it to a non-`Safe` capability's `execute`. That is `run`'s convention,
//! not a compiler fact. It is not reachable in a shipped run, because only `run`
//! executes a capability on this path and no non-`Safe` capability ships, so
//! binding the token to the capability (and gating the vantage path the same way)
//! is deferred to the first non-`Safe` / in-container capability (ADR-0006 layer
//! 3, #9). This unit builds only the native, `Safe` side; tool adapters and
//! higher intensities are later units.

pub mod tcp_connect;

pub use tcp_connect::TcpConnect;

use crate::error::{Error, Result};
use crate::evidence::EvidenceDraft;
use crate::intensity::Intensity;
use crate::observation::Observation;

/// Seals [`Capability`]: only this crate's modules can name `Sealed`, so only
/// this crate can implement the trait. External/dynamic capability authoring is
/// deferred (ADR-0002, ADR-0007), and sealing closes the off-scale case of an
/// unreviewed external capability escaping scope (#9), which is what lets the
/// trait-wide scope-by-type gate be deferred.
///
/// A consequence worth stating plainly: "in-workspace" tool adapters (ADR-0002,
/// ADR-0007) must live *in this crate*, not in a sibling workspace crate, because
/// Rust has no "workspace-visible" visibility and a sibling crate cannot name
/// `Sealed`. When ADR-0007's adapter trait is designed, decide whether adapters
/// are `Capability` impls (in-crate) or a separate normalized-to-evidence trait.
pub(crate) mod sealed {
    pub trait Sealed {}
}

mod intensity_gate {
    use super::{Error, Intensity, Result};

    /// Proof that `issue` ran and cleared a `Safe` intensity. Its field is
    /// private and its only constructor is `issue`, which enforces the check, so
    /// no code outside this crate can mint one. It proves "a `Safe` intensity was
    /// cleared", not "this capability was checked": the token is not bound to the
    /// capability `execute` runs, so inside the crate `run` is what ties the two
    /// together (it mints from `capability.intensity()`). See the module docs.
    pub struct IntensityCleared(());

    impl IntensityCleared {
        /// The intensity gate: the only constructor of an [`IntensityCleared`],
        /// and it mints one only for a `Safe` capability.
        /// [`run`](crate::TestContext::run) calls this before
        /// [`execute`](super::Capability::execute); it is crate-private, so
        /// nothing outside the crate can mint a token.
        pub(crate) fn issue(intensity: Intensity) -> Result<Self> {
            if intensity != Intensity::Safe {
                return Err(Error::IntensityRefused { got: intensity });
            }
            Ok(IntensityCleared(()))
        }
    }
}

pub use intensity_gate::IntensityCleared;

/// An active action: executed against the target it holds, returning a
/// normalized observation and the evidence of what happened, and reporting its
/// intensity so the gate can refuse it.
///
/// `async fn` in a trait is allowed here deliberately: the trait is used
/// through a generic caller ([`TestContext::run`](crate::TestContext::run)), not
/// a `dyn` object, and the runner is single-threaded, so the absent `Send`
/// bound the lint warns about is not needed. A `dyn`-safe registry of
/// capabilities is a later unit's concern (ADR-0002).
///
/// The trait is sealed: only this crate can implement it (see the crate-private
/// `sealed` module). An external crate cannot implement it, which is what makes
/// the intensity gate compiler-held outside the crate (mutation: remove the
/// `: sealed::Sealed` bound and this compiles):
///
/// ```compile_fail
/// struct Evil;
/// impl redstep::Capability for Evil {
///     type Value = ();
///     fn name(&self) -> &'static str { "evil" }
///     fn intensity(&self) -> redstep::Intensity { redstep::Intensity::Aggressive }
///     async fn execute(&self, _c: redstep::IntensityCleared)
///         -> redstep::Result<(redstep::Observation<()>, redstep::EvidenceDraft)> {
///         unreachable!()
///     }
/// }
/// ```
///
/// Nor can external code mint the [`IntensityCleared`] token `execute` requires,
/// so it cannot run a capability even if it had one. The token's field is
/// private (mutation: make it `pub` and this compiles):
///
/// ```compile_fail
/// let _ = redstep::IntensityCleared(());
/// ```
///
/// and its constructor is crate-private (mutation: make `issue` `pub` and this
/// compiles):
///
/// ```compile_fail
/// let _ = redstep::IntensityCleared::issue(redstep::Intensity::Safe);
/// ```
#[allow(async_fn_in_trait)]
pub trait Capability: sealed::Sealed {
    /// What the observation carries. For a reachability capability it is `bool`.
    type Value;

    /// A stable identifier for the evidence record, e.g. `"tcp_connect"`.
    fn name(&self) -> &'static str;

    /// The force this capability applies. The gate refuses anything but `Safe`
    /// in the current build.
    fn intensity(&self) -> Intensity;

    /// Act against the held target, returning the observation and a draft of the
    /// evidence of what happened. Takes an [`IntensityCleared`], which only
    /// `IntensityCleared::issue` can mint and only for a `Safe` capability, so an
    /// external caller cannot execute a capability at all and `run` is the
    /// in-crate caller that mints it from this capability's own intensity (see the
    /// module docs). A capability holds its
    /// [`ScopedTarget`](crate::ScopedTarget), so this takes no raw target. It
    /// returns an [`EvidenceDraft`], not an [`Evidence`](crate::Evidence): a
    /// capability cannot know the id or timestamp of its own record, which the
    /// store assigns on append (ADR-0004).
    async fn execute(
        &self,
        cleared: IntensityCleared,
    ) -> Result<(Observation<Self::Value>, EvidenceDraft)>;
}
