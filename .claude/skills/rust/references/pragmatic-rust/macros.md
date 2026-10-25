<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT license (see LICENSE.md). -->
<!-- From the Pragmatic Rust Guidelines, https://microsoft.github.io/rust-guidelines/agents/all.txt -->

# Macros Guidelines



## Prefer 'macros by example' over proc macros (M-EXAMPLE-OVER-PROC) { #M-EXAMPLE-OVER-PROC }

<why>easy macro inspection and fast compilation.</why>

When a 'macro by example' can do the job, it should be preferred over proc macros.

Proc macros are more powerful, but their expansion can't easily be inspected. Where this versatility isn't needed, a simple 'macro by example' is the better option.

```rust,ignore
// Bad, attribute macro requires proc macro machinery, can be hard to 
// inspect in some IDEs, and isn't needed here.
#[make_new_id]
struct MyId;

// Good, easier to write, maintain and inspect, faster compilation speed.
make_new_id!(MyId);
```



## Third party items come from hidden `_private` module (M-MACRO-HELPERS) { #M-MACRO-HELPERS }

<why>predictable compilation.</why>

When a macro expansion needs to refer to third-party items, the host crate should re-export those from a hidden module, and the macro should emit fully-qualified paths through that module rather than expecting the user's crate to depend on the third-party crate directly.

For example, a crate `foo` requiring `bar` traits would do:

```rust,ignore
#[doc(hidden)]
pub mod _private {
    pub use ::bar::Bar;
}

pub use foo_proc::my_macro;
```

The `my_macro!` implementation would then rely on its presence in its emitted code:

```rust,ignore
impl ::foo::_private::Bar for MyType { ... }
```



## Macros are a last resort (M-MACRO-LAST-RESORT) { #M-MACRO-LAST-RESORT }

<why>minimal complexity.</why>

Macros should only be used if no other viable solution exists, compare this adage:

> As @littlecalculist always told me, “macros are for when you run out of language”. If you still have language left — and Rust gives you a lot of language — use the language first.
>
> @pcwalton

Macros are powerful, but come with several downsides. They

- are magic, and it can be impossible to predict what they do, or how they do it,
- disproportionally increase compilation time in projects that otherwise don't rely on them,
- can cause subtle breakage at edition boundaries where Rust syntax and semantics can change.

Counterintuitively, the more structurally complex the result of a macro expansion is, the worse an idea it is to use macros for that in the first place. The ideal macro makes your users go "_I know exactly what this will generate, but I don't want to write all of that by hand_".



## Macros assume main crate (M-MACRO-MAIN-CRATE) { #M-MACRO-MAIN-CRATE }

<why>simple macro logic.</why>

Procedural macros can (and should) assume they are used through their main crate and emit paths for that.

For crates including proc macros it is common to ship them split in 3 for technical reasons:

- `foo` - the main crate that re-exports macros from `foo_proc`, along with extra traits or types,
- `foo_proc` - facade re-exporting macros from `foo_proc_impl` with `proc-macro = true`,
- `foo_proc_impl` - the actual macro implementation and unit tests.

In some cases there can be additional crates involved. Authors might be tempted to make `foo`, `foo_proc`, and siblings all work, resulting in complex re-export hierarchies or the use of 3rd party helpers. In reality, the minimal UX gain is usually not worth the added complexity (or compile time overhead), given the ecosystem precedent of mostly not supporting these usage modes in the first place.

This also implies you should not attempt to support use cases where your crate is imported under a different name.



## Pin supporting proc macro crates (M-MACRO-VERSION-PIN) { #M-MACRO-VERSION-PIN }

<why>keep generated code compatible with its library</why>

A crate that re-exports macros from companion proc macro crates must pin them to its own exact
version via `=x.y.z`, and each macro crate must pin its own companion crates the same way. When
publishing, those crates are counted as one crate and must be published together with the same
exact version.

Without exact pins, a newer macro may generate code incompatible with an older version of the
crate, causing unexpected and hard-to-diagnose compilation failures in the generated code.

M-MACRO-VERSION-PIN does not apply to independently consumed macro libraries.

Example:

```toml
# foo/Cargo.toml
[dependencies]
foo_macros = "=1.2.3"
```



## Macros don't lie about signatures (M-MACROS-DONT-LIE) { #M-MACROS-DONT-LIE }

<why>clarity for users and LLMs.</why>

Macros must not (make users) misrepresent signatures or the shape of items.

Macros have the ability to arbitrarily rewrite token streams. They could convert structs to enums, traits to functions, or perform any other transformation imaginable. They should, however, do none of that, as the resulting code will be highly confusing and virtually impossible to predict or reason about.

Among others, macros must not

- visibly convert the nature of data types (e.g., structs to enums, ...),
- alter function signatures,
- convert the `async`-ness of items,
- do anything else that materially detaches _what's written_ from _what's happening_.

```rust,ignore
// Bad: Adds extra parameter and marks function `async`. Impossible to 
// predict from reading code. 
#[magic_transform]
fn foo() { }

foo(token).await
```



## Proc macros should have separate impl crate incl. tests (M-PROC-IMPL) { #M-PROC-IMPL }

<why>thoroughly testable proc macros.</why>

Proc macros should be thin shims inside some `foo_proc` crate that delegate to a separate, regular library crate, usually called `foo_proc_impl`, which contains the actual token-stream transformation logic and its tests.

As proc macro crates are special, testing them from `foo_proc` usually requires workarounds for unit and snapshot tests. Instead, consider having a `foo_proc_impl` crate:

```rust,ignore
use proc_macro2::TokenStream;

pub fn my_macro(attr: TokenStream, item: TokenStream) -> TokenStream { ... }
```

These can come with regular [insta](https://insta.rs/) or similar snapshot tests, and are then exported as genuine proc macros via a `foo_proc` crate like so:

```rust,ignore
#[proc_macro_attribute]
pub fn my_macro(attr: TokenStream, item: TokenStream) -> TokenStream {
    foo_proc_impl::my_macro(attr.into(), item.into()).into()
}
```

The macros are then re-exported from the core crate:

```rust,ignore
pub use foo_proc::my_macro;
```

Inside the core crate, we also recommend adding [trybuild](https://docs.rs/trybuild/latest/trybuild/) UI tests with negative examples to ensure consistent error messages.



## Proc macros don't produce implied or hidden items (M-PROC-IMPLIED-ITEMS) { #M-PROC-IMPLIED-ITEMS }

<why>clear errors and correct hygiene and visibility.</why>

Macros should not define magic types on their own, in particular not public ones, or ones that don't rely on namespace tricks.

Some macros want to define types, for example

```rust,ignore
#[my_macro]
struct UserType;

// would expand to

struct UserType;
struct ExtraType; 
impl UserType {
    fn foo() -> ExtraType { ... };
}
```

This is almost always a bad idea for several reasons:

- they can conflict with existing user-defined types inside the same module,
- if done naively, they can conflict with other expansions of the same macro,
- they can clash with the user's naming conventions,
- they are invisible at source code level and easily forgotten to be re-exported where needed.

While it is possible for users to work around these limitations somewhat, these are paper cuts your users will have to deal with, possibly months after the fact when refactoring otherwise unrelated code.

Note that there is one exception to this rule that has generally acceptable UX, the overloaded use of [namespaces](https://doc.rust-lang.org/reference/names/namespaces.html) made prominent by crates like Rocket:

```rust,ignore
#[my_macro]
fn foo() { ... }

// would expand to

fn foo() { ... }

struct foo;
impl SomeTrait for foo { ... }
```

Here a new type `foo` is introduced with the same name as the function `foo`. Due to Rust's namespace rules they can co-exist and are automatically re-exported with their parent, and due to [Rust's casing rules (C-CASE)](https://rust-lang.github.io/api-guidelines/naming.html#casing-conforms-to-rfc-430-c-case) these are highly unlikely to clash with user-defined types. However, they would still not make for a pretty _public_ type, and are therefore mainly used inside root crates to define request handlers or FFI functions.

> ### <tip></tip> Namespaces != Modules
>
> Namespaces in Rust have nothing to do with namespaces in other languages. A namespace in C# is approximately a module in Rust. A namespace in Rust
is an esoteric property of names (e.g., `fn foo`, `struct Bar {}`, `moo!`) that decides which 'naming bucket' it lives in inside a module.
