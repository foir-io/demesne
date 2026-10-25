<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT license (see LICENSE.md). -->
<!-- From the Pragmatic Rust Guidelines, https://microsoft.github.io/rust-guidelines/agents/all.txt -->

# AI Guidelines



## Design with AI use in mind (M-DESIGN-FOR-AI) { #M-DESIGN-FOR-AI }

<why>maximum utility from agents working in your codebase.</why>

As a general rule, making APIs easier to use for humans also makes them easier to use by AI.
If you follow the guidelines in this book, you should be in good shape.

Rust's strong type system is a boon for agents, as their lack of genuine understanding can often be
counterbalanced by comprehensive compiler checks, which Rust provides in abundance.

With that said, there are a few guidelines which are particularly important to help make AI coding in Rust more effective:

* **Create Idiomatic Rust API Patterns**. The more your APIs, whether public or internal, look and feel like the majority of
Rust code in the world, the better it is for AI. Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html)
along with the guidelines from [Library / UX](../libs/ux).

* **Provide Thorough Docs**. Agents love good detailed docs. Include docs for all of your modules and public items in your crate.
Assume the reader has a solid, but not expert, level of understanding of Rust, and that the reader understands the standard library.
Follow
[C-CRATE-DOC](https://rust-lang.github.io/api-guidelines/checklist.html#c-crate-doc),
[C-FAILURE](https://rust-lang.github.io/api-guidelines/checklist.html#c-failure),
[C-LINK](https://rust-lang.github.io/api-guidelines/checklist.html#c-link), and
[M-MODULE-DOCS](../docs/#M-MODULE-DOCS)
[M-CANONICAL-DOCS](../docs/#M-CANONICAL-DOCS).

* **Provide Thorough Examples**. Your documentation should have directly usable examples, the repository should include more elaborate ones.
Follow
[C-EXAMPLE](https://rust-lang.github.io/api-guidelines/checklist.html#c-example)
[C-QUESTION-MARK](https://rust-lang.github.io/api-guidelines/checklist.html#c-question-mark).

* **Use Strong Types**. Avoid [primitive obsession](https://refactoring.guru/smells/primitive-obsession) by using strong types with strict well-documented semantics.
Follow
[C-NEWTYPE](https://rust-lang.github.io/api-guidelines/checklist.html#c-newtype).

* **Make Your APIs Testable**. Design APIs which allow your customers to test their use of your API in unit tests. This might involve introducing some mocks, fakes,
or cargo features. AI agents need to be able to iterate quickly to prove that the code they are writing that calls your API is working
correctly.

* **Ensure Test Coverage**. Your own code should have good test coverage over observable behavior.
This enables agents to work in a mostly hands-off mode when refactoring.



## Avoid meta design documentation (M-NO-META-DESIGN-DOCUMENTATION) { #M-NO-META-DESIGN-DOCUMENTATION }

<why>docs focused on what is relevant to users.</why>

Crate and module documentation must be free of meta design narratives that were only relevant during the creation of a crate. In other words, it is the end-state that is to be documented, not the design journey.

Agents frequently produce sections that describe how a change was designed, "why we picked X over Y" essays, and design journals inside user-facing documentation. These artifacts might be interesting diagnostics while working on the project, but they are mostly meaningless to end users.

For example, an agent might append a self-report like this, summarizing which guidelines it claims to have followed:

```text
| Rule | Applied | Where |
| --- | :---: | --- |
| M-SHORT-NAMES | ✅ | Shortened method names across the data-access and HTTP handler layers. |
| M-WEASEL-WORDS | ✅ | Removed weasel words from type and field names throughout the public API. |
| M-PUBLIC-DISPLAY | ✅ | Added `Display` impls for all user-facing identifier and error types. |
| M-ASYNC-FN | ✅ | Migrated I/O-facing APIs from `impl Future` returns to `async fn`. |
```

This kind of content describes process, not behaviour, and goes stale over time. That said, it is of course perfectly reasonable to have a _Design Principles_ or similar section in the project's README, that on a high level describes the enduring architectural goals that are relevant to end users (e.g., a crate being allocation free, having an OSI architecture, or being designed with `#[no_std]` in mind).



## Rust code solves Rust problems (M-RUST-SHAPED) { #M-RUST-SHAPED }

<why>idiomatic code.</why>

When (automatically) porting C#, Java, C++, or similar code to Rust, technical constructs must not be copied 1-on-1.

It is prudent to separate domain aspects from language aspects. Domain aspects address business problems. An algorithm to compute prime numbers or logic for processing a customer table can (and should) work the same when translating between languages.

However, many patterns exist to solve problems particular to the ecosystem they stem from. The Rust ecosystem has its own problems, and these need to be addressed by idioms that work for Rust. These include

- error handling,
- management of tasks and threads,
- component abstractions and their lifetimes,
- ownership of parameters,
- the absence of 'object-oriented' programming,
- structural differences between interfaces and traits,
- and many others.

While some language constructs simply don't translate at all (e.g., compared to C#, Rust does not have any meaningful reflection), others are deceptively similar and might only bite months down the line (e.g., statics, compare [M-AVOID-STATICS](../libs/resilience/#M-AVOID-STATICS)).

As a rule of thumb, structs and their methods can have vaguely similar names, flows, inputs and outputs, as far as their business functionality is concerned. However, any striking technical similarity between Rust and { C#, Java, Python, ... } implementations is indicative of deeper architectural problems; a `throw_if_null()` never makes sense.



## Items are only visible through one path (M-SINGLE-ITEM-PATH) { #M-SINGLE-ITEM-PATH }

<why>a single, clutter-free path to each type.</why>

Public items within a crate should be reachable only through one path. For example some `crate::db::Connection` should not also be visible as `crate::Connection`:

```rust,ignore
// Not OK
pub mod db {
    pub struct Connection;
}

pub use db::Connection;
```

This rule is often violated by agents creating or refactoring large code bases over several iterations. In an attempt to _simplify_ their task, they re-export items under multiple paths, often previous ones from before some change, instead of cleanly redesigning structures where it makes sense.

Note this only targets the duplication of user-facing items. Within a crate it is acceptable (and often unavoidable) to see the same item multiple times as export trees are constructed:

```rust,ignore
// OK
pub(crate) mod db {
    pub struct Connection;
}

pub use db::Connection;
```

Similarly, re-exports of foreign items are not covered by this rule, although they should follow [M-FOREIGN-REEXPORTS](../libs/interop/#M-FOREIGN-REEXPORTS).

Likewise, this rule also does not apply to public-but-hidden `_private` modules needed by macros, compare [M-MACRO-HELPERS](../macros/#M-MACRO-HELPERS).



## Tests do not assert ground truth (M-TAUTOLOGICAL-TESTS) { #M-TAUTOLOGICAL-TESTS }

<why>tests that add value, not noise.</why>

Unit tests should verify meaningful behavior instead of repeating foundational definitions.

Agents frequently produce tests that re-state the expected value from the same logic the code under test uses, or that simply mirror the implementation's branches. Such tests pass by construction, provide virtually no value, but increase the noise floor of subsequent changes:

```rust
const CHECKPOINTS: [u32; 4] = [0, 90, 180, 270];

#[test]
fn checkpoints_are_correct() {
    assert_eq!(CHECKPOINTS, [0, 90, 180, 270]);
}
```

Where these are used to satisfy mutation tests, the mutation test should be skipped instead.

Instead, a meaningful test would check a property the constants are supposed to satisfy, for example that they are evenly spaced, monotonically increasing, or impose some direction in related logic.
