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
//! The intensity gate *is* trait-wide and compiler-held. Two things hold it:
//! the trait is sealed, so an external crate cannot implement [`Capability`] at
//! all; and [`execute`](Capability::execute) takes an [`Authorized`] token whose
//! only constructor is the intensity gate itself. [`run`](crate::TestContext::run)
//! is the one place that mints a token, and only for a `Safe` capability, so no
//! caller (in the crate or outside it) can execute a capability without passing
//! the gate (ADR-0006 layer 3, #9). This unit builds only the native, `Safe`
//! side; tool adapters and higher intensities are later units.

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
pub(crate) mod sealed {
    pub trait Sealed {}
}

mod gate {
    use super::{Error, Intensity, Result};

    /// Proof that the intensity gate ran. Its field is private and its only
    /// constructor is `Authorized::issue`, which enforces the check, so no
    /// caller can mint one without passing the gate. Since
    /// [`execute`](super::Capability::execute) requires one, a capability cannot
    /// run ungated, in the crate or outside it (ADR-0006 layer 3, #9).
    pub struct Authorized(());

    impl Authorized {
        /// The intensity gate: the one place an [`Authorized`] is minted, and
        /// only for a `Safe` capability. [`run`](crate::TestContext::run) calls
        /// this before [`execute`](super::Capability::execute).
        pub(crate) fn issue(intensity: Intensity) -> Result<Self> {
            if intensity != Intensity::Safe {
                return Err(Error::IntensityRefused { got: intensity });
            }
            Ok(Authorized(()))
        }
    }
}

pub use gate::Authorized;

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
/// `sealed` module).
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
    /// evidence of what happened. Takes an [`Authorized`], which only
    /// [`run`](crate::TestContext::run) can mint (after the intensity gate), so
    /// a capability cannot be executed without passing the gate. A capability
    /// holds its [`ScopedTarget`](crate::ScopedTarget), so this takes no raw
    /// target. It returns an [`EvidenceDraft`], not an [`Evidence`](crate::Evidence):
    /// a capability cannot know the id or timestamp of its own record, which the
    /// store assigns on append (ADR-0004).
    async fn execute(
        &self,
        authorized: Authorized,
    ) -> Result<(Observation<Self::Value>, EvidenceDraft)>;
}
