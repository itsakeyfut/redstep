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
//! *Inside* the crate the gate is compiler-held too (#44). [`IntensityCleared`]
//! is generic over the capability it clears, minted only by
//! `IntensityCleared::issue(&capability)` from that capability's own intensity,
//! and [`execute`](Capability::execute) takes an `IntensityCleared<Self>`: a
//! token minted for one capability cannot drive another's `execute` (`E0308`),
//! and a non-`Safe` capability cannot obtain a token at all. The in-container
//! vantage path (`connect_from_vantage` and the `exploit_*_from_vantage` family,
//! `context.rs`) is gated the same way by a separate `VantageCleared` proof,
//! which clears `Safe` and `Controlled` (confined by lab isolation, ADR-0006
//! layers 1-2) and refuses `Aggressive`, whose layer-3 isolation proof is not
//! built. This unit builds the native side; the tool adapters and the
//! `Aggressive` rung are later units.

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
    use super::{Capability, Error, Intensity, Result};
    use core::marker::PhantomData;

    /// Proof that the intensity gate cleared capability `C` to run on the host
    /// path. Generic over `C` so a token minted for one capability cannot drive
    /// another's [`execute`](super::Capability::execute) (`E0308`); its field is
    /// private and its only constructor is `issue`, which mints one only for a
    /// `Safe` capability, so no in-crate caller can hand a non-`Safe` capability a
    /// token and no external code can mint one at all (#44). `PhantomData<fn() ->
    /// C>` so the token is `Send`/`Sync` whatever `C` is.
    pub struct IntensityCleared<C: Capability>(PhantomData<fn() -> C>);

    impl<C: Capability> IntensityCleared<C> {
        /// The intensity gate for the host path: the only constructor of an
        /// [`IntensityCleared`], minting one only for a `Safe` capability from
        /// that capability's own intensity. [`run`](crate::TestContext::run) calls
        /// it before [`execute`](super::Capability::execute); it is crate-private,
        /// so nothing outside the crate can mint a token.
        pub(crate) fn issue(capability: &C) -> Result<Self> {
            let got = capability.intensity();
            if got != Intensity::Safe {
                return Err(Error::IntensityRefused { got });
            }
            Ok(IntensityCleared(PhantomData))
        }
    }

    /// Proof that the intensity gate cleared an in-container action to run on the
    /// attacker's vantage (#44). A separate proof from [`IntensityCleared`]
    /// because the vantage path is not a [`Capability`] (a host-runnable
    /// reachability check would be a vacuous PASS, RK-008) and its
    /// intensity ceiling differs: lab isolation (ADR-0006 layers 1-2) confines
    /// `Controlled`, so `issue` clears `Safe` and `Controlled` and refuses only
    /// `Aggressive`, whose layer-3 isolation proof is not built. Its field is
    /// private and `issue` is crate-private, so only this crate mints one. It
    /// stays crate-internal: the external `compile_fail` guard for "the
    /// in-container seam cannot run ungated" arrives when that seam is made public
    /// (the v0.4.0 adapters).
    pub(crate) struct VantageCleared(());

    impl VantageCleared {
        /// The intensity gate for the in-container vantage path. Clears `Safe` and
        /// `Controlled` (lab-confined, ADR-0006 layers 1-2); refuses `Aggressive`.
        pub(crate) fn issue(intensity: Intensity) -> Result<Self> {
            if intensity == Intensity::Aggressive {
                return Err(Error::IntensityRefused { got: intensity });
            }
            Ok(VantageCleared(()))
        }
    }
}

pub use intensity_gate::IntensityCleared;
pub(crate) use intensity_gate::VantageCleared;

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
///     async fn execute(&self, _c: redstep::IntensityCleared<Self>)
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
/// let _ = redstep::IntensityCleared::<redstep::TcpConnect>(core::marker::PhantomData);
/// ```
///
/// and its constructor is crate-private (mutation: make `issue` `pub` and this
/// compiles):
///
/// ```compile_fail
/// let _ = redstep::IntensityCleared::<redstep::TcpConnect>::issue;
/// ```
// `Sized`: the gate token `IntensityCleared<Self>` is sized (it carries
// `PhantomData<fn() -> Self>`), and a capability is always used through the
// generic `run`/`execute` path, never as a `dyn` object (see the `async fn`
// note above), so requiring `Sized` costs nothing and lets `execute` name
// `IntensityCleared<Self>`.
#[allow(async_fn_in_trait)]
pub trait Capability: sealed::Sealed + Sized {
    /// What the observation carries. For a reachability capability it is `bool`.
    type Value;

    /// A stable identifier for the evidence record, e.g. `"tcp_connect"`.
    fn name(&self) -> &'static str;

    /// The force this capability applies. The gate refuses anything but `Safe`
    /// in the current build.
    fn intensity(&self) -> Intensity;

    /// Act against the held target, returning the observation and a draft of the
    /// evidence of what happened. Takes an `IntensityCleared<Self>`, a token bound
    /// to this very capability: only `IntensityCleared::issue(&self)` mints one and
    /// only for a `Safe` capability, so a token minted for another capability does
    /// not type-check here (`E0308`), a non-`Safe` capability cannot obtain one,
    /// and external code cannot mint one at all (see the module docs). A capability
    /// holds its
    /// [`ScopedTarget`](crate::ScopedTarget), so this takes no raw target. It
    /// returns an [`EvidenceDraft`], not an [`Evidence`](crate::Evidence): a
    /// capability cannot know the id or timestamp of its own record, which the
    /// store assigns on append (ADR-0004).
    async fn execute(
        &self,
        cleared: IntensityCleared<Self>,
    ) -> Result<(Observation<Self::Value>, EvidenceDraft)>;
}
