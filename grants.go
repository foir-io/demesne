package demesne

import (
	"fmt"
	"strings"
)

// Reachability grants — the unified declarative concept (WS3 convergence, EID-265).
//
// A level-scoped Grant and a Descriptor's acl edge (AclEdge) are the SAME
// primitive: an owner-originated reachability grant, stored as a tuple in an edge
// table, enforced by a generated SECURITY DEFINER EXISTS over that edge. They
// differ ONLY in target granularity — a Grant reaches a whole topology-LEVEL
// subtree (cascade), an AclEdge reaches ONE object ROW — and therefore in the
// shape of the target predicate and its cost.
//
// This file makes that unity first-class in TWO ways, while keeping the physical
// stores deliberately SEPARATE (the moat: a single generic
// grants(grantee, target_kind, target_id, …) table would be exactly the Zanzibar
// relation-tuple store we reject; each shape must keep its own specialized,
// sargable predicate):
//
//  1. ReachGrant — an interface both *Grant and *AclEdge satisfy, so the whole
//     grant surface of a spec can be enumerated/inspected through one lens
//     (Spec.ReachGrants), classified by Granularity.
//  2. grantEdgeExists — the ONE shared emission mechanism: the `EXISTS (SELECT 1
//     FROM <edge> WHERE <conjuncts>)` shape both definer bodies are built from.
//     Each caller supplies its own specialized conjuncts (grantee match, target
//     match, validity/access/kind gates) in its own order — same shape, distinct
//     SQL, distinct store.

// GrantGranularity is the target a reachability grant confers reach to.
type GrantGranularity int

const (
	// LevelReach: an edge row grants reach to a whole topology-level subtree.
	LevelReach GrantGranularity = iota
	// RowReach: an edge row grants reach to a single object row.
	RowReach
)

func (g GrantGranularity) String() string {
	if g == RowReach {
		return "row"
	}
	return "level"
}

// ReachGrant is the unified concept over a level Grant and a descriptor AclEdge.
type ReachGrant interface {
	// EdgeTable is the grant store (the tuple table).
	EdgeTable() string
	// GranteeColumn is the column matched against the grantee's claim.
	GranteeColumn() string
	// Granularity is the target the grant reaches (a level subtree vs one row).
	Granularity() GrantGranularity
}

// *Grant is a level-subtree reachability grant.
func (g *Grant) EdgeTable() string             { return g.Table }
func (g *Grant) GranteeColumn() string         { return g.GranteeCol }
func (g *Grant) Granularity() GrantGranularity { return LevelReach }

// *AclEdge is a per-row reachability grant (the descriptor's grant list).
func (e *AclEdge) EdgeTable() string             { return e.Table }
func (e *AclEdge) GranteeColumn() string         { return e.PrincipalCol }
func (e *AclEdge) Granularity() GrantGranularity { return RowReach }

// ReachGrants enumerates every reachability grant in the spec as one concept —
// level-scoped grants and descriptor acl edges alike — irrespective of target
// granularity or physical store. Order: level grants (declaration order), then
// descriptor edges (object order).
func (s *Spec) ReachGrants() []ReachGrant {
	var out []ReachGrant
	for _, g := range s.Grants {
		out = append(out, g)
	}
	for _, o := range s.Objects {
		if o.Descriptor != nil && o.Descriptor.Grants != nil {
			out = append(out, o.Descriptor.Grants)
		}
	}
	return out
}

// grantEdgeExists renders the canonical reachability-grant predicate shared by
// every grant definer: an EXISTS over the edge table gated by the supplied
// conjuncts (the grantee match, the target match, and any validity / access /
// kind gates, in the caller's order). The shape is unified; the conjuncts — and
// thus the specialized, sargable SQL — stay each grant's own.
func grantEdgeExists(edge string, conjuncts ...string) string {
	return fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s)", edge, strings.Join(conjuncts, " AND "))
}

// grantDefinerName is the name of an object descriptor's grant-list EXISTS
// definer. A BARE edge (one descriptor per store) keeps the historical
// <table>_grants — byte-identical for any spec not using a discriminator. A
// DISCRIMINATED edge (several descriptors sharing one store) is suffixed by the
// object, so each descriptor gets its own collision-free definer over the shared
// table. Both emit sites (the definer body + the RLS call) MUST agree on this, so
// it lives here, computed once.
func grantDefinerName(obj *Object) string {
	g := obj.Descriptor.Grants
	if g.DiscrimCol != "" {
		return g.Table + "_grants_" + obj.Name
	}
	return g.Table + "_grants"
}

// *ViaGrant is a per-row reachability grant expressed as a GENERIC relation (the
// de-prescribed descriptor grant list). Same concept as an AclEdge, surfaced
// through the relation grammar.
func (e *ViaGrant) EdgeTable() string             { return e.Table }
func (e *ViaGrant) GranteeColumn() string         { return e.PrincipalCol }
func (e *ViaGrant) Granularity() GrantGranularity { return RowReach }

// grantRelation returns the object's grant relation (`via grant`) and its repr,
// or (nil, nil) — the de-prescribed form of the descriptor's grant list. An object
// has at most one (validation enforces it).
func grantRelation(o *Object) (*Relation, *ViaGrant) {
	for _, r := range o.Relations {
		if vg, ok := r.Repr.(ViaGrant); ok {
			vg := vg
			return r, &vg
		}
	}
	return nil, nil
}

// grantRelDefinerBase is the base name of a grant relation's per-kind EXISTS
// definers — <table>_grants, suffixed by the object when the store is
// discriminated (shared across kinds), exactly like grantDefinerName does for a
// descriptor. So a pure-relation object emits byte-identical grant definer names.
func grantRelDefinerBase(o *Object, vg *ViaGrant) string {
	if vg.DiscrimCol != "" {
		return vg.Table + "_grants_" + o.Name
	}
	return vg.Table + "_grants"
}

// grantRelBinding resolves the i-th grantee kind of a grant relation to (a) its
// generated definer name, (b) the principal-kind label stored in the acl, (c) the
// grantee parameter name, and (d) the claim a caller of that kind presents.
// Mirrors the descriptor's grantKindBinding: the FIRST (primary) kind takes the
// unsuffixed (by-kind) definer; each additional kind a kind-suffixed, collision-
// free definer over the shared store. Unlike the descriptor — where the primary
// list value is a free label decoupled from the owner subject — a grant relation
// unifies the kind label, the grantee parameter, and the claim subject as its
// declared type, which is the cleaner pure-relation form (and equals the
// descriptor's binding for Foir, where the list values name the subjects).
func (s *Spec) grantRelBinding(o *Object, vg *ViaGrant, r *Relation, i int) (name, kind, param, claim string) {
	kind = r.Types[i]
	param = kind
	if sub := s.subjectByName(kind); sub != nil {
		claim = sub.Identifies
	}
	base := grantRelDefinerBase(o, vg)
	if i == 0 {
		name = base
	} else {
		name = base + "_" + kind
	}
	return
}

// grantSelector splits a `<rel>:<access>` grant term into the relation name and
// access class, returning ok only when <rel> names a grant (ViaGrant) relation.
// A bare permkey (content:read) or a non-grant relation returns ok=false, so such
// a term falls through to the normal PDP-capability / relation handling. This is
// how `grantee:read` (which lexes as a single permkey) is distinguished from a
// real capability.
func grantSelector(ident string, rels map[string]*Relation) (relName, access string, ok bool) {
	i := strings.IndexByte(ident, ':')
	if i < 0 {
		return "", "", false
	}
	relName, access = ident[:i], ident[i+1:]
	r := rels[relName]
	if r == nil {
		return "", "", false
	}
	if _, isGrant := r.Repr.(ViaGrant); !isGrant {
		return "", "", false
	}
	return relName, access, true
}

// isGrantSelectorTerm reports whether a term ident is a grant relation referenced
// with an access class (`grantee:read`) — used by validation to classify it as a
// row-layer grant rather than a PDP capability.
func isGrantSelectorTerm(ident string, rels map[string]*Relation) bool {
	_, _, ok := grantSelector(ident, rels)
	return ok
}

// storeManageName is the write-moat dispatch definer for a discriminated grant
// store: auth.<store>_manage(p_type, p_id) → the matching kind's can-edit.
func storeManageName(table string) string { return table + "_manage" }

// storeDescriptors returns, in object order, the descriptor objects whose grant
// list is backed by the given store table. For a discriminated (shared) store
// these are the resource KINDS the store serves; the write-moat dispatch CASEs
// over them.
func (s *Spec) storeDescriptors(table string) []*Object {
	var out []*Object
	for _, o := range s.Objects {
		if o.Descriptor != nil && o.Descriptor.Grants != nil && o.Descriptor.Grants.Table == table {
			out = append(out, o)
		}
	}
	return out
}

// objectUsesStoreManage reports whether any of the object's permissions invoke
// the @store_manage write-moat builtin.
func objectUsesStoreManage(o *Object) bool {
	for _, pm := range o.Perms {
		for _, t := range pm.Expr {
			if t.Builtin == "store_manage" {
				return true
			}
		}
	}
	return false
}
