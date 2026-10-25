<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT license (see LICENSE.md). -->
<!-- From the Pragmatic Rust Guidelines, https://microsoft.github.io/rust-guidelines/agents/all.txt -->

# Performance Guidelines



## Hot `async` functions reduce stack size (M-ASYNC-STACK-SIZE) { #M-ASYNC-STACK-SIZE }

<why>small async stack sizes and low memcpy overhead.</why>

Functions marked `async` in the hot path should track their future sizes, and take one or more of the following steps to reduce their impact:

- reduction of parameter and rval type size,
- reduction of type size of items held across `.await` points,
- returning `impl Future` and extracting setup logic from `async {}` capture.

> ### <tip></tip> Future 'Stack' Sizes
>
> In Futures, what would naively be considered _their stack_, is actually part of a significantly more complicated machinery under their  hood.
>
> Regular locals, that only live momentarily between two `.await` points, still remain part of the runtime thread's regular stack. However, any locals that live across `.await` points, or parameters passed during construction, become part of that Future's state machine type, and the layout of this type is currently not as optimized as it could be.
>
> This not only can cause stack-to-heap memcpy operations when creating or boxing Futures, it can also force large upfront stack sizes of the hypothetical most deeply nested cross-async call stack of the involved async function (which, on a side note, is why they can't simply recurse).
>
> ```rust,ignore
> async fn foo(_large: Large) {
>     let within_future = [0_u8; 1024]; // Crosses .await below, embedded in `foo` type
>     let on_stack = [0_u8; 1024]; // Does not cross .await points, lives on stack
>     let sneaky = Droppable::with_size(1024); // Secretly crosses .await point!
>     dbg!(&on_stack, &sneaky);
>     bar(&within_future).await;
>     dbg!(&within_future);
>     // <- `sneaky` dropped here, despite otherwise not being used!
> }
> 
> let future = foo(Large::new()); // `Large` becomes embedded in `foo` type, 
>                                 // blowing up its size, despite it not even
>                                 // being used.
> 
> // Here, despite `foo` not running yet, we might consume up to `Large` + 
> // 2kb of this thread's stack memory. Once we spawn this is memcpy'ed 
> // to runtime Task structure:
> rt.spawn(future);
>```

For many async functions this isn't an issue, as their associated `Future`-cost is negligible. However, functions used along the hot path, that are either called or instantiated frequently (e.g., 1000's of calls per second or concurrent tasks) might benefit from monitoring and optimizations.

Hot futures should be tracked via `size_of_val`:

```rust,ignore
async fn hot() { ... }

#[test]
fn has_reasonable_size() {
    let f = hot();
    assert!(size_of_val(&f) < ...); // Determine value / limit at first run.
}
```

Then consider a combination of the following:

```rust,ignore
// 1) Return an `impl Future` instead, this prevents large arguments 
//    from infecting the future size, among others.
fn hot(args: Args) -> impl Future<Output = Result<T>> { 
    // 2) Process arguments outside async context if processing does
    //    not require async functionality.
    let args = args.do_something(); 

    if args.invalid() {
        // 3) Use `Either` to return a single `impl Future` type, as
        //    otherwise you'd have to invent a new type. 
        async { Err(InvalidArgs) }.left_future() 
    } else {
        // 4) Chain future invocations via future helpers, which again 
        //    prevents heavy locals from being passed through the state 
        //    machine.
        read(args).then(|x| foo(x)).right_future() 
    }
}
```



## Nested type hierarchies should avoid needless indirection (M-AVOID-INDIRECTION) { #M-AVOID-INDIRECTION }

<why>fast, cache-friendly memory access.</why>

Hot types should avoid nested heap indirection and consider lifting hot, cacheable deep fields to improve cache utilization.  

While the gold standard is to benchmark, a pattern that emerges repeatedly when porting C# code to Rust is to reflexively `Arc` nested types, often multiple layers deep. Although this can make sense on very wide or heavyweight types that genuinely need to be shared by multiple owners, this pattern can ruin access latency when multiple rounds of DRAM lookup have to be performed sequentially.

Where nested, shared ownership isn't strictly needed, it is usually better to start with local, embedded data, and lift cacheable fields.

```rust,ignore
// Bad, `print` (assuming it is reasonably hot) needs 2 indirections 
// to query whether it is enabled. 
struct Item {
    config: Arc<Config>,
    payload: Payload,
}

struct Config {
    feature: Arc<Feature>
}

impl Item {
    fn print(&self) {
        if self.config.feature.is_enabled() { ... }
    }
}

// Better: `enabled` resides nearby and is likely immediately available 
// once `print` is called.
struct Item {
    config: Arc<Config>,
    payload: Payload,
    enabled: bool,
}

impl Item {
    fn print(&self) {
        if self.enabled { ... }
    }
}

```



## Use boxed slices and strings for immutable owned sequences (M-BOX-DST) { #M-BOX-DST }

<why>low memory consumption and good cache utilization.</why>

Frequently used, internal, immutable sequences that will not be resized after construction should be stored as `Box<[T]>`, `Arc<str>` or similar, rather than their original  `Vec<T>` or `String` counterparts.

Regular growable collections consist of a `(ptr, len, capacity)` triple. Converting them to boxed slices makes them immutable, executes a [shrink-to-fit](./#M-SHRINK-TO-FIT), and drops the `capacity` bit, reducing their handle size by 1/3.  For this pattern to be useful, the following preconditions should apply:

- the sequence should be frequently instantiated (e.g., >1000's of instances),
- it must be immutable,
- it should not be user-visible, i.e., regular users would just deal with `&str` or similar.

Some collections provide dedicated methods for this, e.g., `String::into_boxed_str`.

```rust,ignore
// Bad, with many entries this wastes space and makes
// traversal ultimately slower. 
struct Data {
    ids: Vec<String>
}

// Good, reduces memory consumption and fits more elements 
// into cache.
struct Data {
    ids: Vec<Box<str>>
}
```



## Use a fast hasher where possible (M-FAST-HASHER) { #M-FAST-HASHER }

<why>hashing performance.</why>

When hashing trusted, internal keys, prefer a fast non-cryptographic hasher (e.g., `foldhash`, `FxHash`) over the standard library default.

Rust's default hasher is reasonably DoS safe on untrusted user input, but this comes at a performance penalty. If you can trust that keys are not maliciously crafted to overflow individual buckets, a custom fast hasher can yield significant performance gains.

```rust,ignore
// Bad, uses default hasher for keys we control.
let lookup = HashMap::<UserID, Data>::with_capacity(1024);

// Good, uses faster foldhash for internal keys.
let lookup = foldhash::HashMap<UserID, Data>::with_capacity(1024);
```



## Identify, profile, optimize the hot path early (M-HOTPATH) { #M-HOTPATH }

<why>high-performance code.</why>

You should, early in the development process, identify if your crate is performance or COGS relevant. If it is:

- identify hot paths and create benchmarks around them,
- regularly run a profiler collecting CPU and allocation insights,
- document or communicate the most performance sensitive areas.

For benchmarks we recommend [criterion](https://crates.io/crates/criterion) or [divan](https://crates.io/crates/divan).
If possible, benchmarks should not only measure elapsed wall time, but also used CPU time over all threads (this unfortunately
requires manual work and is not supported out of the box by the common benchmark utils).

Profiling Rust on Windows works out of the box with [Intel VTune](https://www.intel.com/content/www/us/en/developer/tools/oneapi/vtune-profiler.html)
and [Superluminal](https://superluminal.eu/). However, to gain meaningful CPU insights you should enable debug symbols for benchmarks in your `Cargo.toml`:

```toml
[profile.bench]
debug = 1
```

Documenting the most performance sensitive areas helps other contributors take better decision. This can be as simple as
sharing screenshots of your latest profiling hot spots.

### Further Reading

- [Performance Tips](https://cheats.rs/#performance-tips)

> ### <tip></tip> How much faster?
>
> Some of the most common 'language related' issues we have seen include:
>
> - frequent re-allocations, esp. cloned, growing or `format!` assembled strings,
> - short lived allocations over bump allocations or similar,
> - memory copy overhead that comes from cloning Strings and collections,
> - repeated re-hashing of equal data structures
> - the use of Rust's default hasher where collision resistance wasn't an issue
>
> Anecdotally, we have seen ~15% benchmark gains on hot paths where only some of these `String`  problems were
> addressed, and it appears that up to 50% could be achieved in highly optimized versions.



## Collections are created with sufficient initial capacity (M-INITIAL-CAPACITY) { #M-INITIAL-CAPACITY }

<why>efficient collection creation.</why>

Where the final or approximate size of a collection (`Vec`, `String`, `HashMap`, `HashSet`, etc.) is known at construction time, it should be created via   `with_capacity` rather than `new` or `default`.

Collections created without capacity may be re-allocated multiple times during their initialization, which also includes copying their content. Creating them with sufficient capacity can entirely avoid this needless overhead.

```rust,ignore
// Bad, probably re-allocates and copies content over multiple times.
let mut rval = Vec::new();
for x in &other {
    rval.push(convert(x));
}

// Better, creates collection with sufficient capacity upfront.
let mut rval = Vec::with_capacity(other.len());
for x in &other {
    rval.push(convert(x));
}
```

Iterator-driven construction (`collect`) inherits this behavior via `size_hint` and should be preferred over manual `push` loops when possible:

```rust,ignore
// Ideal, looks nicer and is performant
let rval: Vec<_> = other.iter().map(convert).collect();
```



## Library telemetry does not tank performance (M-LOG-OVERHEAD) { #M-LOG-OVERHEAD }

<why>low-overhead telemetry during diagnosis.</why>

Library code that emits telemetry should ensure that doing so does not meaningfully impact throughput or latency on the hot path.

Crates offered to 3rd parties emitting logs or metrics should assume telemetry will be permanently enabled, or under load. Care should therefore be taken that the volume and overhead of emitted events is reasonable, and will not cause excessive performance degradation.

Hot, inner loops should preferably stay free of telemetry emission entirely. If it can't be avoided, the events emitted should be lightweight and avoid allocations (e.g., `format!` string concatenation).

```rust,ignore
// Bad, logs each message and invokes allocation-based formatting.
for m in messages {
    log(format!("Emitting message {}", m.id()))
}

// Better, avoids per-message allocations.
for m in messages {
    log(("Emitting message", m.id()))
}

// Best: If possible, let telemetry users reconstruct what happened offline 
log(("Processing message batch", messages.batch_id()))
for m in messages { ... }
```



## Reuse allocations where possible (M-MEM-REUSE) { #M-MEM-REUSE }

<why>low allocation overhead and fast hot paths.</why>

When designing APIs you should allow users to hold onto reusable resources. Inside your code you should make use of them where available.

The cost of repeated allocations inside hot loops can be significant, and from a user's perspective they can be invisible unless profiled:

```rust,ignore
// Bad, API design forces new allocation per element.
for id in ids {
    let value = db.get(id);
}
```

While this style of API may exist for convenience, it should be auxiliary. Instead, the core APIs should allow users to own the underlying object and re-use it:

```rust,ignore
// Good, allows users to decide whether a new allocation is needed.
let mut value = Value::new();
for id in ids {
    db.get_in(id, &mut value);
}
```

The canonical method on reusable types to reuse them is `.clear()`, as can be found on many `std` items. Multiple flavors of this pattern exist. In simple cases user-owned types can hold a preexisting, reusable collection directly:

```rust
struct Value {
    data: Vec<u8>
}
```

In heavyweight, deeply nested libraries it can be worthwhile to either pass a bump-style `Arena`, or to encapsulate one inside the user types, so it can be used throughout the call stack:

```rust,ignore
struct Query {
    arena: Arena,
    request: Request,
    data: Vec<u8>    
}

fn client_do_work(query: &mut Query) {
    let request = rewrite_request(&query.request, &query.arena);
    get_in(request, &mut query.data);
}
```



## Shrink collections to fit after building (M-SHRINK-TO-FIT) { #M-SHRINK-TO-FIT }

<why>a minimal memory footprint.</why>

Where large, long-lived, growable collections such as `Vec` or `String` were built without an exact size reservation (compare [M-INITIAL-CAPACITY](./#M-INITIAL-CAPACITY)), the resulting collection should be shrunk via `shrink_to_fit` before storing it.

Many Rust collections grow by powers of two when iteratively adding elements. In the worst case a collection might therefore use ~2x of its needed memory.

```rust,ignore
// Bad, long lived object might end up using 2x needed memory.
let mut long_lived = Vec::new();
for x in large_iter {
    long_lived.push(x);
}

// Good, frees up extra memory.
long_lived.shrink_to_fit();
```

Note that this does not apply to conversions done via `into_boxed_*` and friends (compare [M-BOX-DST](./#M-BOX-DST)), as these generally shrink before converting already.



## Optimize for throughput, avoid empty cycles (M-THROUGHPUT) { #M-THROUGHPUT }

<why>COGS savings at scale.</why>

You should optimize your library for throughput, and one of your key metrics should be _items per CPU cycle_.

This does not mean to neglect latency&mdash;after all you can scale for throughput, but not for latency. However,
in most cases you should not pay for latency with _empty cycles_ that come with single-item processing, contended locks and frequent task switching.

Ideally, you should

- partition reasonable chunks of work ahead of time,
- let individual threads and tasks deal with their slice of work independently,
- sleep or yield when no work is present,
- design your own APIs for batched operations,
- perform work via batched APIs where available,
- yield within long individual items, or between chunks of batches (see [M-YIELD-POINTS]),
- exploit CPU caches, temporal and spatial locality.

You should not:

- hot spin to receive individual items faster,
- perform work on individual items if batching is possible,
- do work stealing or similar to balance individual items.

Shared state should only be used if the cost of sharing is less than the cost of re-computation.

[M-YIELD-POINTS]: ./#M-YIELD-POINTS



## Long-running tasks should have yield points (M-YIELD-POINTS) { #M-YIELD-POINTS }

<why>fair CPU time for all tasks.</why>

If you perform long running computations, they should contain `yield_now().await` points.

Your future might be executed in a runtime that cannot work around blocking or long-running tasks. Even then, such tasks are
considered bad design and cause runtime overhead. If your complex task performs I/O regularly it will simply utilize these await points to preempt itself:

```rust, ignore
async fn process_items(items: &[items]) {
    // Keep processing items, the runtime will preempt you automatically.
    for i in items {
        read_item(i).await;
    }
}
```

If your task performs long-running CPU operations without intermixed I/O, it should instead cooperatively yield at regular intervals, to not starve concurrent operations:

```rust, ignore
async fn process_items(zip_file: File) {
    let items = zip_file.read().async;
    for i in items {
        decompress(i);
        yield_now().await;
    }
}
```

If the number and duration of your individual operations are unpredictable you should use APIs such as `has_budget_remaining()` and
related APIs to query your hosting runtime.

> ### <tip></tip> Yield how often?
>
> In a thread-per-core model the overhead of task switching must be balanced against the systemic effects of starving unrelated tasks.
>
> Under the assumption that runtime task switching takes 100's of ns, in addition to the overhead of lost CPU caches,
> continuous execution in between should be long enough that the switching cost becomes negligible (<1%).
>
> Thus, performing 10 - 100μs of CPU-bound work between yield points would be a good starting point.
