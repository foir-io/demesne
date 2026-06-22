package demesne

import (
	"fmt"
	"strings"
)

type GrantGranularity int

const (
	LevelReach GrantGranularity = iota

	RowReach
)

func (g GrantGranularity) String() string {
	if g == RowReach {
		return "row"
	}
	return "level"
}

type ReachGrant interface {
	EdgeTable() string

	GranteeColumn() string

	Granularity() GrantGranularity
}

func (g *Grant) EdgeTable() string             { return g.Table }
func (g *Grant) GranteeColumn() string         { return g.GranteeCol }
func (g *Grant) Granularity() GrantGranularity { return LevelReach }

func (s *Spec) ReachGrants() []ReachGrant {
	var out []ReachGrant
	for _, g := range s.Grants {
		out = append(out, g)
	}
	for _, o := range s.Objects {
		if _, vg := grantRelation(o); vg != nil {
			out = append(out, vg)
		}
	}
	return out
}

func grantEdgeExists(edge string, conjuncts ...string) string {
	return fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s)", edge, strings.Join(conjuncts, " AND "))
}

func touchOnConflict(bareKey, nullableKey, sets []string) string {
	key := append([]string(nil), bareKey...)
	for _, c := range nullableKey {
		key = append(key, fmt.Sprintf("COALESCE(%s, '')", c))
	}
	return fmt.Sprintf("ON CONFLICT (%s) DO UPDATE SET %s", strings.Join(key, ", "), strings.Join(sets, ", "))
}

func (e *ViaGrant) EdgeTable() string             { return e.Table }
func (e *ViaGrant) GranteeColumn() string         { return e.PrincipalCol }
func (e *ViaGrant) Granularity() GrantGranularity { return RowReach }

func grantRelation(o *Object) (*Relation, *ViaGrant) {
	for _, r := range o.Relations {
		if vg, ok := r.Repr.(ViaGrant); ok {
			vg := vg
			return r, &vg
		}
	}
	return nil, nil
}

func grantRelDefinerBase(o *Object, vg *ViaGrant) string {
	if vg.DiscrimCol != "" {
		return vg.Table + "_grants_" + o.Name
	}
	return vg.Table + "_grants"
}

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

func isGrantSelectorTerm(ident string, rels map[string]*Relation) bool {
	_, _, ok := grantSelector(ident, rels)
	return ok
}

func storeManageName(table string) string { return table + "_manage" }

func objectGrantEdge(o *Object) *ViaGrant {
	_, vg := grantRelation(o)
	return vg
}

func (s *Spec) storeDescriptors(table string) []*Object {
	var out []*Object
	for _, o := range s.Objects {
		if e := objectGrantEdge(o); e != nil && e.Table == table {
			out = append(out, o)
		}
	}
	return out
}

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
