<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT license (see LICENSE.md). -->
<!-- From the Pragmatic Rust Guidelines, https://microsoft.github.io/rust-guidelines/agents/all.txt -->

# Correctness Guidelines



## Panic continuation is last resort (M-PANIC-CONTINUATION) { #M-PANIC-CONTINUATION }

<why>state integrity and freedom from subtle bugs.</why>

Panic recovery via `catch_unwind()` is a matter of last resort and must generally be followed by a controlled application restart.

Panics indicate the program has reached an unrecoverable state (compare [M-PANIC-IS-STOP](./#M-PANIC-IS-STOP) and [M-PANIC-ON-BUG](./#M-PANIC-ON-BUG)). Library code in particular should not attempt to catch a panic and continue execution, as there is a risk of observing otherwise impossible state:

```rust,ignore
thread_local! {
    static ALWAYS_EQUAL: RefCell<(i32, i32)> = RefCell::new((0, 0));
}

fn main() {
    let _ = panic::catch_unwind(|| {
        ALWAYS_EQUAL.with_borrow_mut(|p| {
            p.0 += 1;        
            panic!("Assume some user-provided closure failed here");  
            p.1 += 1;
        });
    });

    ALWAYS_EQUAL.with_borrow(|p| {
        assert_eq!(p.0, p.1);  // Broken!
    });
}
```

Although the example above is slightly contrived, the side effects and interactions of a caught panic can be harder to identify, can have wide blast radius, and be subtle.

Systems where many unrelated tasks are in flight (e.g., server request handlers) can use `catch_unwind` on a per-request basis, but should still promote an application restart after a request handler caused a panic. The purpose of `catch_unwind` here is not to continue execution indefinitely, but to allow all other requests to gracefully finish.



## Panic means 'stop the program' (M-PANIC-IS-STOP) { #M-PANIC-IS-STOP }

<why>soundness and predictability.</why>

Panics are not exceptions. Instead, they suggest immediate program termination.

Although your code must be [_minimally_ panic-safe](https://doc.rust-lang.org/nomicon/exception-safety.html) (i.e., a survived panic may not lead to
undefined state), invoking a panic means _this program should stop now_. It is not valid to:

- use panics to communicate (errors) upstream,
- use panics to handle self-inflicted error conditions,
- assume panics will be caught, even by your own code.

For example, if the application calling you is compiled with a `Cargo.toml` containing

```toml
[profile.release]
panic = "abort"
```

then any invocation of panic will cause an otherwise functioning program to needlessly abort. Valid reasons to panic are:

- when encountering a programming error, e.g., `x.expect("must never happen")`,
- anything invoked from const contexts, e.g., `const { foo.unwrap() }`,
- when user requested, e.g., providing an `unwrap()` method yourself,
- when encountering a poison, e.g., by calling `unwrap()` on a lock result (a poisoned lock signals another thread has panicked already).

Any of those are directly or indirectly linked to programming errors.



## Custom panics have a helpful message (M-PANIC-MESSAGE) { #M-PANIC-MESSAGE }

<why>faster bug diagnosis.</why>

When code panics intentionally (via `panic!`, `assert!`, `unreachable!`, `todo!`, or similar), a message must be present to clearly state what went wrong and, where applicable, include relevant values.

```rust,ignore
// Bad, the panic gives the developer little to act on.
assert!(buffer.len() >= HEADER_SIZE);

// Good, message contains reason and actual values.
assert!(buffer.len() >= HEADER_SIZE, "buffer too small for header: got {} bytes, need {HEADER_SIZE}", buffer.len());
```

Messages related to API misuse should be useful to the end user. Messages indicating bugs should be helpful to you-as-the-author, or whoever maintains the project after you, to quickly identify the underlying cause.

Panic messages in tests are not generally needed.



## Detected programming bugs are panics, not errors (M-PANIC-ON-BUG) { #M-PANIC-ON-BUG }

<why>tractable error handling and runtime consistency.</why>

As an extension of [M-PANIC-IS-STOP] above, when an unrecoverable programming error has been
detected, libraries and applications must panic, i.e., request program termination.

In these cases, no `Error` type should be introduced or returned, as any such error could not be acted upon at runtime.

Contract violations, i.e., the breaking of invariants either within a library or by a caller, are programming errors and must therefore panic.

However, what constitutes a violation is situational. APIs are not expected to go out of their way to detect them, as such
checks can be impossible or expensive. Encountering `must_be_even == 3` during an already existing check clearly warrants
a panic, while a function `parse(&str)` clearly must return a `Result`. If in doubt, we recommend you take inspiration from the standard library.

```rust, ignore
// Generally, a function with bad parameters must either
// - Ignore a parameter and/or return the wrong result
// - Signal an issue via Result or similar
// - Panic
// If in this `divide_by` we see that y == 0, panicking is
// the correct approach.
fn divide_by(x: u32, y: u32) -> u32 { ... }

// However, it can also be permissible to omit such checks
// and return an unspecified (but not an undefined) result.
fn divide_by_fast(x: u32, y: u32) -> u32 { ... }

// Here, passing an invalid URI is not a contract violation.
// Since parsing is inherently fallible, a Result must be returned.
fn parse_uri(s: &str) -> Result<Uri, ParseError> { };

```

> ### <tip></tip> Make it 'Correct by Construction'
>
> While panicking on a detected programming error is the 'least bad option', your panic might still ruin someone's day.
> For any user input or calling sequence that would otherwise panic, you should also explore if you can use the type
> system to avoid panicking code paths altogether.

[M-PANIC-IS-STOP]: ./#M-PANIC-IS-STOP



## Unsafe implies undefined behavior (M-UNSAFE-IMPLIES-UB) { #M-UNSAFE-IMPLIES-UB }

<why>semantic consistency without warning fatigue.</why>

The marker `unsafe` may only be applied to functions and traits if misuse implies the risk of undefined behavior (UB).
It must not be used to mark functions that are dangerous to call for other reasons.

```rust
// Valid use of unsafe
unsafe fn print_string(x: *const String) { }

// Invalid use of unsafe
unsafe fn delete_database() { }
```



## Unsafe needs reason, should be avoided (M-UNSAFE) { #M-UNSAFE }

<why>memory safety and a minimal attack surface.</why>

You must have a valid reason to use `unsafe`. The only valid reasons are

1) novel abstractions, e.g., a new smart pointer or allocator,
1) performance, e.g., attempting to call `.get_unchecked()`,
1) FFI and platform calls, e.g., calling into C or the kernel, ...

Unsafe code lowers the guardrails used by the compiler, transferring some of the compiler's responsibilities
to the programmer. Correctness of the resulting code relies primarily on catching all mistakes in code review,
which is error-prone. Mistakes in unsafe code may introduce high-severity security vulnerabilities.

You must not use ad-hoc `unsafe` to

- shorten a performant and safe Rust program, e.g., 'simplify' enum casts via `transmute`,
- bypass `Send` and similar bounds, e.g., by doing `unsafe impl Send ...`,
- bypass lifetime requirements via `transmute` and similar.

Ad-hoc here means `unsafe` embedded in otherwise unrelated code. It is of course permissible to create properly designed, sound abstractions doing these things.

In any case, `unsafe` must follow the guidelines outlined below.

### Novel Abstractions

- [ ] Verify there is no established alternative. If there is, prefer that.
- [ ] Your abstraction must be minimal and testable.
- [ ] It must be hardened and tested against ["adversarial code"](https://cheats.rs/#adversarial-code), esp.
  - If they accept closures they must become invalid (e.g., poisoned) if the closure panics
  - They must assume any safe trait is misbehaving, esp. `Deref`, `Clone` and `Drop`.
- [ ] Any use of `unsafe` must be accompanied by plain-text reasoning outlining its safety
- [ ] It must pass [Miri](https://github.com/rust-lang/miri), including adversarial test cases
- [ ] It must follow all other [unsafe code guidelines](https://rust-lang.github.io/unsafe-code-guidelines/)

### Performance

- [ ] Using `unsafe` for performance reasons should only be done after benchmarking
- [ ] Any use of `unsafe` must be accompanied by plain-text reasoning outlining its safety. This applies to both
  calling `unsafe` methods, as well as providing `_unchecked` ones.
- [ ] The code in question must pass [Miri](https://github.com/rust-lang/miri)
- [ ] You must follow the [unsafe code guidelines](https://rust-lang.github.io/unsafe-code-guidelines/)

### FFI

- [ ] We recommend you use an established interop library to avoid `unsafe` constructs
- [ ] You must follow the [unsafe code guidelines](https://rust-lang.github.io/unsafe-code-guidelines/)
- [ ] You must document your generated bindings to make it clear which call patterns are permissible

### Further Reading

- [Nomicon](https://doc.rust-lang.org/nightly/nomicon/)
- [Unsafe Code Guidelines](https://rust-lang.github.io/unsafe-code-guidelines/)
- [Miri](https://github.com/rust-lang/miri)
- ["Adversarial code"](https://cheats.rs/#adversarial-code)



## All code must be sound (M-UNSOUND) { #M-UNSOUND }

<why>predictable runtime behavior free of bugs and incompatibilities.</why>

Unsound code is seemingly _safe_ code that may produce undefined behavior when called from other safe code, or on its own accord.

> ### <tip></tip> Meaning of 'Safe'
>
> The terms _safe_ and `unsafe` are technical terms in Rust.
>
> A function is _safe_, if its signature does not mark it `unsafe`. That said, _safe_ functions can still be dangerous
> (e.g., `delete_database()`), and `unsafe` ones are, when properly used, usually quite benign (e.g.,`vec.get_unchecked()`).
>
> A function is therefore _unsound_ if it appears _safe_ (i.e., it is not marked `unsafe`), but if _any_ of its calling
> modes would cause undefined behavior. This is to be interpreted in the strictest sense. Even if causing undefined
> behavior is only a 'remote, theoretical possibility' requiring 'weird code', the function is unsound.
>
> Also see [Unsafe, Unsound, Undefined](https://cheats.rs/#unsafe-unsound-undefined).

```rust
// "Safely" converts types
fn unsound_ref<T>(x: &T) -> &u128 {
    unsafe { std::mem::transmute(x) }
}

// "Clever trick" to work around missing `Send` bounds.
struct AlwaysSend<T>(T);
unsafe impl<T> Send for AlwaysSend<T> {}
unsafe impl<T> Sync for AlwaysSend<T> {}
```

Unsound abstractions are never permissible. If you cannot safely encapsulate something, you must expose `unsafe` functions instead, and document proper behavior.

<div class="warning">

No Exceptions

While you may break most guidelines if you have a good enough reason, there are no exceptions in this case: unsound code is never acceptable.

</div>

> ### <tip></tip> It's the Module Boundaries
>
> Note that soundness boundaries equal module boundaries! It is perfectly fine, in an otherwise safe abstraction,
> to have safe functions that rely on behavior guaranteed elsewhere **in the same module**.
>
> ```rust
> struct MyDevice(*const u8);
>
> impl MyDevice {
>     fn new() -> Self {
>        // Properly initializes instance ...
>        # todo!()
>     }
>
>     fn get(&self) -> u8 {
>         // It is perfectly fine to rely on `self.0` being valid, despite this
>         // function in-and-by itself being unable to validate that.
>         unsafe { *self.0 }
>     }
> }
>
> ```
