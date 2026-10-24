# demesne-emit-rust

Compiles a demesne spec into Rust tables at build time. Your crate names the surfaces it uses in `build.rs`; only those are emitted, as `static` items of `demesne-runtime` types built from borrowed data. Nothing is parsed or allocated at runtime, and a spec that fails to parse or validate fails the build.

```toml
[dependencies]
demesne-runtime = "0.94"

[build-dependencies]
demesne-emit-rust = "0.94"
```

```rust
// build.rs
fn main() {
    demesne_emit_rust::Builder::new("authz.demesne")
        .session()
        .claims_contract()
        .holds_resolver("")
        .resource_access("note")
        .check("note", "edit")
        .compile();
}
```

```rust
// src/authz.rs
include!(concat!(env!("OUT_DIR"), "/demesne.rs"));
```

```rust
let claims = demesne_runtime::mint_claims_values(authz::claims::CONTRACT, &values)?;
let setup: Vec<String> = authz::claims::SESSION.session_setup_sql(true);
let can_edit_sql: &str = authz::objects::note::checks::EDIT;
```

`compile()` panics with the spec's error, which is how a build script fails; `generate()` returns it instead, and `render()` returns the code without writing a file.

| Builder method | Item |
| -- | -- |
| `vocabulary(name)` | `vocabularies::NAME: Vocabulary` |
| `holds_resolver(store)` | `rolestores::store::HOLDS_RESOLVER: HoldsResolver` |
| `role_assignment(store)` | `rolestores::store::ROLE_ASSIGNMENT: RoleAssignmentSurface` |
| `expanded_presets(store)` | `rolestores::store::EXPANDED_PRESETS: &[(&str, &[&str])]` |
| `grant(name)` | `grants::NAME: GrantSurface` |
| `resource_access(object)` | `objects::object::RESOURCE_ACCESS: ResourceAccessSurface` |
| `conditional_resource_access(object)` | `objects::object::CONDITIONAL_RESOURCE_ACCESS: ResourceAccessSurface` |
| `point_check(object)` | `objects::object::POINT_CHECK_SQL: &str` |
| `app_surface(object)` | `objects::object::APP_SURFACE: AppObjectSurface` |
| `check(object, verb)` | `objects::object::checks::VERB: &str` |
| `pdp(site)` | `pdp::SITE: Pdp` |
| `session()` | `claims::SESSION: Session` |
| `claims_contract()` | `claims::CONTRACT: &[&str]` |
| `claims_contract_entries()` | `claims::CONTRACT_ENTRIES: &[ClaimEntry]` |

An empty rolestore name means the spec's first rolestore, as in the Go library; the item takes that store's name. `resource_access` refuses an object whose readers its enumeration cannot all name, as Go's `ResourceAccessSurface` does; `conditional_resource_access` emits it with the `conditional` flag set. `check` refuses a capability (`@pdp`) verb and a verb without a `@check` layer.
