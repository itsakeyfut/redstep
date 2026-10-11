//! The registry the `#[security_test]` macro submits into and the runner reads.
//!
//! Pure of I/O. The macro expansion references the items here by path
//! (`::redstep::registry::...`), including the re-exported `inventory`, so a
//! crate that writes tests needs only `redstep` as a dependency.

use crate::context::TestContext;
use crate::error::Result;
use std::future::Future;
use std::pin::Pin;

/// Re-exported so the macro can call `inventory::submit!` by path without the
/// test's crate depending on `inventory` directly.
#[doc(hidden)]
pub use inventory;

/// The future a registered test returns, erased so the registry can hold one
/// type while the future still borrows the [`TestContext`] for its lifetime.
pub type TestFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + 'a>>;

/// The function pointer a registered test is erased to. A named `fn` with
/// elided lifetimes has exactly this higher-ranked type.
pub type TestFn = for<'a> fn(&'a TestContext) -> TestFuture<'a>;

/// One discovered security test: its fully-qualified name and a way to run it.
pub struct RegisteredTest {
    /// `module_path!()::fn_name`, assigned by the macro.
    pub name: &'static str,
    /// Runs the test against a context, returning its future.
    pub run: TestFn,
}

inventory::collect!(RegisteredTest);

/// Every registered test, in submission order (the runner sorts them).
pub fn all() -> impl Iterator<Item = &'static RegisteredTest> {
    inventory::iter::<RegisteredTest>.into_iter()
}
