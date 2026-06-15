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
