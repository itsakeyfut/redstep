//! The `#[security_test]` attribute macro.
//!
//! It keeps the annotated async function as written and registers it with the
//! runner, so `redstep`'s runner can discover and execute it. See
//! `docs/specs/design-decisions.md` Decision A.

use proc_macro::TokenStream;
use quote::quote;
use syn::{FnArg, ItemFn, parse_macro_input};

/// Register an async function as a security test.
///
/// The function must be `async fn NAME(ctx: &TestContext) -> redstep::Result<()>`.
/// A wrong shape is a compile error, named here where it can be, and caught by
/// the generated wrapper's type otherwise.
#[proc_macro_attribute]
pub fn security_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);

    if let Some(err) = check_signature(&func) {
        // Emit the original item as well, so the user still sees type errors in
        // the body rather than only the signature complaint.
        return quote! { #func #err }.into();
    }

    let name = &func.sig.ident;
    let name_str = name.to_string();

    // A named wrapper (not a closure) so lifetime elision gives it the
    // higher-ranked `fn` type the registry stores. The `const _` block keeps
    // the wrapper and the submission out of the surrounding namespace.
    let expanded = quote! {
        #func

        const _: () = {
            fn __redstep_run(
                ctx: &::redstep::TestContext,
            ) -> ::redstep::registry::TestFuture<'_> {
                ::std::boxed::Box::pin(#name(ctx))
            }

            ::redstep::registry::inventory::submit! {
                ::redstep::registry::RegisteredTest {
                    name: ::core::concat!(::core::module_path!(), "::", #name_str),
                    run: __redstep_run,
                }
            }
        };
    };

    expanded.into()
}

/// Return a `compile_error!` token stream when the shape is wrong in a way this
/// macro can name precisely: not `async`, or not exactly one argument. The
/// return type is left to the generated wrapper, where a mismatch is a type
/// error at a precise span.
fn check_signature(func: &ItemFn) -> Option<proc_macro2::TokenStream> {
    let sig = &func.sig;

    if sig.asyncness.is_none() {
        return Some(error_at(
            &sig.ident,
            "a #[security_test] must be `async fn`",
        ));
    }

    let non_receiver = sig
        .inputs
        .iter()
        .filter(|arg| matches!(arg, FnArg::Typed(_)))
        .count();
    let has_receiver = sig
        .inputs
        .iter()
        .any(|arg| matches!(arg, FnArg::Receiver(_)));

    if has_receiver || non_receiver != 1 {
        return Some(error_at(
            &sig.ident,
            "a #[security_test] must take exactly one argument: `ctx: &TestContext`",
        ));
    }

    None
}

fn error_at(ident: &syn::Ident, msg: &str) -> proc_macro2::TokenStream {
    syn::Error::new(ident.span(), msg).to_compile_error()
}
