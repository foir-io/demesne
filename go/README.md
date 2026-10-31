# github.com/foir-io/demesne/go

demesne's runtime for Go. The module embeds the Rust runtime compiled to WebAssembly and runs it on [wazero](https://wazero.io), so it needs no cgo and builds wherever Go does. Its answers are the Rust runtime's own: the oracle that checks `@foir/demesne` replays every case through this module too.

```
go get github.com/foir-io/demesne/go@v1.2.0
```

The module's major and minor version are those of the demesne release whose runtime it embeds, and a patch release can fix the Go layer alone. Generate code with the CLI of the same minor version.

## The typed surface

Generate a package from your spec, and commit it:

```
demesne emit authz.demesne --target go framework authz > internal/authz/authz.go
```

The package holds a `Surface` with a field per object, each with a `Can<Verb>` check, `ListResources` and `CheckMany`; `Holds` and `HoldsRoles`, which read a principal's role assignments and resolve them; `Caps` and `RoleTiers` over what they return; `Check`, which dispatches by object and verb; and `CheckHandler`, an `http.Handler` that answers with the JSON decision. Build the runtime once at startup and the surface from it:

```go
r, err := demesne.New(ctx)
if err != nil {
	return err
}
defer r.Close(ctx)
s := authz.New(r)
```

A check runs under the caller's claims, inside a transaction that has set them up, and the database decides: it delegates to the same compiled predicate the RLS policy enforces.

```go
tx, err := db.BeginTx(ctx, nil)
if err != nil {
	return err
}
defer tx.Rollback()
claims, err := s.Mint(ctx, authz.Claims{MemberID: member, TenantID: tenant, WorkspaceID: workspace})
if err != nil {
	return err
}
setup := authz.SessionSetupSQL(true)
if _, err := tx.ExecContext(ctx, setup[0]); err != nil {
	return err
}
if _, err := tx.ExecContext(ctx, setup[1], claims); err != nil {
	return err
}
decision, err := s.Doc.CanView(ctx, demesne.FromSQL(tx), docID)
```

## Connections

Generated checks run their SQL through `demesne.Querier`, which `demesne.FromSQL` makes from a `*sql.DB`, `*sql.Tx` or `*sql.Conn`. `CheckMany` passes its ids as a `[]string`, so the driver has to send one as a Postgres `text[]`, as pgx's `database/sql` driver (`github.com/jackc/pgx/v5/stdlib`) does. For another driver, implement `Querier` yourself.

## Concurrency

A `Runtime` is safe for concurrent use. It compiles the module once and keeps a pool of instances, so calls from many goroutines run side by side. When a call fails, the runtime closes the instance it ran on instead of reusing it.

## Projections

`demesne emit authz.demesne --target go projections <pkg>` writes the spec's projections as Go values: `Claims`, `AppSurface`, `PDP`, `HoldsResolver`, `RoleAssignment`, `Grants` and `ResourceAccess`. Each type has the runtime's operations as methods, among them the write builders for role assignments, reach grants and record sharing, which return a `Statement` whose arguments are the values you passed in. `--target go claims` and `--target go pdp` write the claims contract and each emit site's policy map on their own.

## Coming from v0.93

The Go engine is frozen at v0.93.1 on the `release/v0.93` branch, where `Spec.EmitFramework(pkg)` still generates its Go package. This module replaces it. The generated package keeps the shape of v0.93's: the claims struct, the session SQL, a check per object and verb, `Holds`, `Caps`, `RoleTiers`, `Check` and `CheckHandler`. The differences: the checks hang off a `Surface` built from a `Runtime`, each method takes a `context.Context`, and `Mint` is a method of the surface.
