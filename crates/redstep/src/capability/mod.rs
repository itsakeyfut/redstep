//! The capability layer: an active action against a scope-resolved target.
//!
//! A capability is where force lives (See Decision B). The shipped
//! [`TcpConnect`] takes a [`ScopedTarget`](crate::ScopedTarget), which nothing
//! but the scope resolver produces, so it cannot reach a target that did not
//! pass the gate (docs/rules/security.md section 2). That is a property of that
//! capability, not of the trait: the trait below does not require holding a
//! `ScopedTarget`, so a hand-written capability could hold a raw address.
//! Forcing scope and intensity through the type, rather than by each
//! capability's discipline, is scheduled before the first tool adapter or
//! external capability lands. A capability reports its [`Intensity`], which the
//! run path checks before executing. This unit builds only the native, `Safe`
//! side; tool adapters and higher intensities are later units.

pub mod tcp_connect;

pub use tcp_connect::TcpConnect;

use crate::evidence::EvidenceDraft;
use crate::intensity::Intensity;
use crate::observation::Observation;

/// An active action: executed against the target it holds, returning a
/// normalized observation and the evidence of what happened, and reporting its
/// intensity so the run path can gate it.
///
/// `async fn` in a trait is allowed here deliberately: the trait is used
/// through a generic caller ([`TestContext::run`](crate::TestContext::run)), not
/// a `dyn` object, and the runner is single-threaded, so the absent `Send`
/// bound the lint warns about is not needed. A `dyn`-safe registry of
/// capabilities is a later unit's concern (Decision B).
#[allow(async_fn_in_trait)]
pub trait Capability {
    /// What the observation carries. For a reachability capability it is `bool`.
    type Value;

    /// A stable identifier for the evidence record, e.g. `"tcp_connect"`.
    fn name(&self) -> &'static str;

    /// The force this capability applies. The run path refuses anything but
    /// `Safe` in the current build.
    fn intensity(&self) -> Intensity;

    /// Act against the held target, returning the observation and a draft of the
    /// evidence of what happened. A capability holds its
    /// [`ScopedTarget`](crate::ScopedTarget), so this takes no raw target. It
    /// returns an [`EvidenceDraft`], not an [`Evidence`](crate::Evidence):
    /// a capability cannot know the id or timestamp of its own record, which the
    /// store assigns on append (Decision D).
    async fn execute(&self) -> crate::Result<(Observation<Self::Value>, EvidenceDraft)>;
}
