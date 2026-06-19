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
		out.Objects = append(out.Objects, AppObjectSurface{
			Object: o.Name,
			Table:  o.Table,
			PK:     o.pk(),
		})
	}
	return out, nil
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
	return fmt.Sprintf(
		"SELECT %s FROM %s WHERE ($1 IS NULL OR %s > $1) ORDER BY %s LIMIT $2",
		o.PK, o.Table, o.PK, o.PK)
}
