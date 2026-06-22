package demesne

import (
	"fmt"
)

// App-level read surface (Layer 2, EID-341 / EID-340 WS0) — the ergonomic
// authorization API an application calls at runtime: "can this subject do X to this
// row?" (Check), "which of these rows can it see?" (CheckMany), "list the rows it can
// see" (ListResources). RLS already ENFORCES on every data query; what RLS cannot
// answer is the standalone authorization QUESTION — a pre-action affordance, a
// realtime join gate, a paginated "my visible rows" list. This surface is that
// question API, and it is the foundation the reverse-enumeration (WS1) and verifier
// (WS2) build on.
//
// EQUAL BY DELEGATION — the moat. These builders return SQL the caller runs UNDER the
// subject's minted claims (ClaimsSetSQL) and the RLS connection role; the live RLS
// predicate decides. They re-evaluate NO policy in app code:
//
//   - Check = PointCheckSQL run under the subject's claims (→ pointAllow), composed
//     with the verb PDP via ComposeCan. So Check(read) IS "visible under RLS" by
//     construction — there is no parallel evaluator to drift (the Zanzibar Check
//     service the moat rejects).
//   - ListResources = the real RLS-filtered SELECT run AS the subject, keyset
//     paginated; LIMIT/keyset push down natively (the grant-dominant-LIST fast path
//     that does not need a materialized cache).
//   - CheckMany = the batched point-check: pass a set of ids, get back the subset RLS
//     lets the subject see.
//
// SCOPE. These answer the READ / visibility decision — the object's SELECT policy,
// which is what RLS filters when the subject queries. "Who can access X" (reverse) and
// non-read verbs over the full permission tree are WS1, not here.
//
// TARGET-NEUTRAL. AppCheckSurface is plain exported data and the builders return SQL
// strings (row identity binds to $1), so a TypeScript emitter (EID-338 / WS6)
// reproduces them from the same projection. Nothing here names a tenant / project /
// customer; the table and PK are spec-declared.

// AppCheckSurface projects a spec's governed objects into the app-level read layout:
// one AppObjectSurface per object, each carrying the table + PK its check/list
// statements are built from. The claims/session setup (Spec.ClaimsSetSQL,
// Spec.SessionSetupSQL) and the verb gate (Spec.EmitPDP / PDP.Authorize / ComposeCan)
// are the existing runtime glue this composes with.
type AppCheckSurface struct {
	Objects []AppObjectSurface
}

// AppObjectSurface is one object's app-level read surface: the table and primary-key
// column its point-check, batch-check and list statements reference. The same identity
// (Table, PK) the RLS point-check uses, so the app-level answer cannot diverge from the
// enforced predicate.
type AppObjectSurface struct {
	Object string // the spec object name
	Table  string // its governed table
	PK     string // its primary-key column (the row identity)
	// FlatListFn is the qualified reverse fast-path fn (auth.<flat>_resources) when this
	// object's SELECT permission is EXACTLY one materialized via-group term (single-term,
	// exclusion-free) — then ListResources can drive from that small reachable set and the
	// LIMIT pushes down. "" otherwise: the caller uses the RLS-filtered SELECT (the default
	// grant-dominant path). The fast-path STILL runs under RLS, so it is a candidate-narrowing
	// hint, never a second evaluator.
	FlatListFn string
	// AsyncCheckSQL is the MinimizeLatency affordance read for this object's `async` via-grant
	// relation: SELECT allowed, as_of FROM <index>_affordance($1, '<kind>', <subject claim>),
	// where $1 is the row id and the principal is the subject's own claim (IDOR-safe, like the
	// flat). It reads the async INDEX, NEVER the floor — the caller wraps the (allowed, as_of)
	// it returns in ComposeAffordance to get an Affordance (a hint), never a Decision. "" when
	// the object has no async relation (so a non-async spec's surface is byte-identical).
	AsyncCheckSQL string
	// EditCheckSQL is the WRITE point-check (EID-350): SELECT EXISTS over the object's
	// `update`-mapped permission predicate, inlined (a bare SELECT never triggers the UPDATE
	// policy). Run under the subject's claims it reports "visible AND editable" — the gate a
	// co-edit / write join needs. "" when the object has no @rls update permission.
	EditCheckSQL string
}

// EmitAppSurface projects every governed object into the app-level read surface — the
// parallel Emit* entry point for Layer 2, alongside EmitDefiners / EmitRLS / EmitPDP.
// Errors when the spec declares no objects.
func (s *Spec) EmitAppSurface() (*AppCheckSurface, error) {
	if len(s.Objects) == 0 {
		return nil, fmt.Errorf("EmitAppSurface: the spec declares no objects")
	}
	out := &AppCheckSurface{Objects: make([]AppObjectSurface, 0, len(s.Objects))}
	for _, o := range s.Objects {
		// A composite-PK object has no single-column row identity to bind `WHERE <id> =
		// $1`, so it carries no point-check surface (EID-371 §4.1). Skip it rather than
		// emit a `WHERE id = $1` that errors at runtime (the framework banners it).
		if !o.pointCheckable() {
			continue
		}
		editSQL, err := s.editPointCheckSQL(o)
		if err != nil {
			return nil, fmt.Errorf("EmitAppSurface: %s edit point-check: %w", o.Name, err)
		}
		out.Objects = append(out.Objects, AppObjectSurface{
			Object:        o.Name,
			Table:         o.Table,
			PK:            o.pk(),
			FlatListFn:    s.flatListFn(o),
			AsyncCheckSQL: s.asyncCheckSQL(o),
			EditCheckSQL:  editSQL,
		})
	}
	return out, nil
}

// flatListFn returns the reverse ListResources fast-path fn (auth.<flat>_resources) for an
// object whose SELECT permission is EXACTLY one materialized via-group term — single-term
// and exclusion-free, so driving the LIST from that one flat returns the WHOLE visible set
// (a union would miss the other terms' rows; an exclusion would over-include). "" otherwise,
// so the caller falls back to the RLS-filtered SELECT. Needs an owner-plane claim (the
// two-level reverse reads the asking subject from the GUC).
func (s *Spec) flatListFn(o *Object) string {
	var sel *Perm
	for _, pm := range o.Perms {
		if pm.Maps == "select" {
			sel = pm
			break
		}
	}
	// Single positive leaf only: a union / `and` / `and not` adds Expr leaves, so len != 1
	// rules them out; the tree-op guard is belt-and-suspenders.
	if sel == nil || len(sel.Expr) != 1 || sel.Expr[0] == nil || accessorTreeOp(sel.Tree) != "" {
		return ""
	}
	var rel *Relation
	for _, r := range o.Relations {
		if r.Name == sel.Expr[0].Ident {
			rel = r
			break
		}
	}
	if rel == nil {
		return ""
	}
	g, ok := rel.Repr.(ViaGroup)
	if !ok || !g.Materialized {
		return ""
	}
	if len(o.Scoped) == 0 || s.ownerSubject(o.Scoped[len(o.Scoped)-1]) == nil {
		return "" // no owner claim → no two-level reverse
	}
	// Must match MaterializedFlat: Flat = <objTable>_<relName>_flat, fn = <flat>_resources.
	return fmt.Sprintf("%s.%s_%s_flat_resources", s.definerSchema(), o.Table, rel.Name)
}

// asyncCheckSQL builds the MinimizeLatency affordance read for an object's `async` via-grant
// relation: a point membership read of the async INDEX for ($1 row, the relation's kind, the
// subject's own claim). The principal comes from the claims GUC (not a caller arg), so a caller
// cannot ask "can SOMEONE ELSE see this" via the cache — the same IDOR-safe symmetry the flat
// uses. Returns "" when the object has no async relation, or when no owner-plane subject claim
// resolves (the read needs the asking subject). NEVER references the floor.
func (s *Spec) asyncCheckSQL(o *Object) string {
	var rel *Relation
	for _, r := range o.Relations {
		if relationIsAsync(r) {
			rel = r
			break
		}
	}
	if rel == nil || len(o.Scoped) == 0 {
		return ""
	}
	cust := s.ownerSubject(o.Scoped[len(o.Scoped)-1])
	if cust == nil {
		return ""
	}
	kind := ""
	if len(rel.Types) > 0 {
		kind = rel.Types[0]
	}
	return fmt.Sprintf("SELECT allowed, as_of::text FROM %s_affordance($1, '%s', %s)",
		s.asyncIndexBase(o.Table, rel.Name), kind, s.claim(cust.Identifies))
}

// Object returns the named object's surface, or (zero, false).
func (a *AppCheckSurface) Object(name string) (AppObjectSurface, bool) {
	for _, o := range a.Objects {
		if o.Object == name {
			return o, true
		}
	}
	return AppObjectSurface{}, false
}

// CheckSQL is the point read-check: run under the subject's claims + RLS role, it
// reports whether the subject can SEE the row whose id binds to $1. Identical to
// Spec.PointCheckSQL(object) — reproduced on the surface so the projection is
// self-contained for a non-Go emitter. The boolean result is the `pointAllow` input to
// ComposeCan.
func (o AppObjectSurface) CheckSQL() string {
	return fmt.Sprintf("SELECT EXISTS (SELECT 1 FROM %s WHERE %s = $1)", o.Table, o.PK)
}

// CheckEditSQL is the point WRITE-check (EID-350): run under the subject's claims +
// RLS role, it reports whether the subject can EDIT the row whose id binds to $1 —
// i.e. the row is visible AND passes the object's UPDATE policy predicate (inlined,
// since a bare SELECT never triggers the UPDATE policy). "" when the object has no
// @rls update permission; the caller then has no write gate to apply.
func (o AppObjectSurface) CheckEditSQL() string { return o.EditCheckSQL }

// CheckManySQL is the batched point-check: $1 binds an array of row ids; run under the
// subject's claims it returns the PK of each one the subject can see (RLS drops the
// rest). The caller diffs the returned set against the input to learn allow/deny per
// id in one round-trip.
func (o AppObjectSurface) CheckManySQL() string {
	return fmt.Sprintf("SELECT %s FROM %s WHERE %s = ANY($1)", o.PK, o.Table, o.PK)
}

// ListResourcesSQL is the keyset-paginated list of the rows the subject can SEE: run
// under the subject's claims + RLS role, it returns a page of visible PKs in PK order.
// $1 is the after-cursor (the last PK of the previous page; bind NULL for the first
// page); $2 is the page size. RLS does the filtering, so only authorized rows are
// returned and the LIMIT pushes down — this is the grant-dominant-LIST fast path that
// needs no materialized index. Equal to "what the subject can SELECT" by construction.
func (o AppObjectSurface) ListResourcesSQL() string {
	// $1 is cast to text so a NULL first-page cursor has a determinable type under the
	// exec protocol (a bare `$1 IS NULL` leaves the planner unable to infer it); the
	// keyset comparison and ORDER BY share the text projection so the boundary aligns
	// with the order — a stable total order for the text/uuid PKs governed tables use.
	return fmt.Sprintf(
		"SELECT %s FROM %s WHERE ($1::text IS NULL OR %s::text > $1::text) ORDER BY %s::text LIMIT $2",
		o.PK, o.Table, o.PK, o.PK)
}

// ListResourcesFastSQL is the materialized-flat drive-from-flat variant of
// ListResourcesSQL, valid ONLY when FlatListFn != "" (a single-term, exclusion-free
// materialized via-group SELECT). It narrows the scan to the subject's reachable set via
// `<pk> IN (SELECT <flat>_resources())` so the keyset LIMIT pushes down instead of the
// planner filtering the whole table per-row under RLS. It STILL runs under the subject's
// claims + RLS role, so scope and the floor remain the enforcement — the IN is a candidate
// hint that returns the same rows as ListResourcesSQL (oracle-gated). Returns "" when the
// object is not fast-path-eligible, so the caller uses ListResourcesSQL.
func (o AppObjectSurface) ListResourcesFastSQL() string {
	if o.FlatListFn == "" {
		return ""
	}
	return fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s IN (SELECT %s()) AND ($1::text IS NULL OR %s::text > $1::text) ORDER BY %s::text LIMIT $2",
		o.PK, o.Table, o.PK, o.FlatListFn, o.PK, o.PK)
}
