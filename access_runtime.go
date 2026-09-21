package demesne

import (
	"fmt"
	"strings"
)

type ResourceAccessSurface struct {
	Table string

	ScopeCols []string

	ModeCol string

	pk         string
	readModes  map[string]bool
	grantKinds map[string]bool

	aclTable     string
	recordCol    string
	kindCol      string
	principalCol string
	accessCol    string
	discrimCol   string
	discrimVal   string
	accessorFn   string
	conditional  bool
}

// ResourceAccessSurface describes object's grant store and its accessor
// enumerator.
//
// It refuses an object whose read admits a @claim, because that object has no
// plain enumerator to describe — see conditionalAccessors. Use
// ConditionalResourceAccessSurface, which returns the same surface over the
// conditional function and a query shape that carries the claim columns.
func (s *Spec) ResourceAccessSurface(object string) (*ResourceAccessSurface, error) {
	r, err := s.resourceAccessSurface(object)
	if err != nil {
		return nil, err
	}
	if r.conditional {
		return nil, fmt.Errorf("ResourceAccessSurface: object %q admits readers by a claim, so %s lists only the accessors it can name and never the ones the claim admits; call ConditionalResourceAccessSurface and decide what the claim rows mean for this caller", object, r.accessorFn)
	}
	return r, nil
}

// ConditionalResourceAccessSurface is ResourceAccessSurface for a caller that
// has accounted for claim-admitted readers. It accepts an object with or
// without a claim, so a caller written against it stays correct if a claim is
// added to the spec later.
func (s *Spec) ConditionalResourceAccessSurface(object string) (*ResourceAccessSurface, error) {
	return s.resourceAccessSurface(object)
}

func (s *Spec) resourceAccessSurface(object string) (*ResourceAccessSurface, error) {
	obj := s.objectByName(object)
	if obj == nil {
		return nil, fmt.Errorf("ResourceAccessSurface: no object %q in the spec", object)
	}

	edge := objectGrantEdge(obj)
	if edge == nil {
		return nil, fmt.Errorf("ResourceAccessSurface: object %q has no grant store (descriptor grants or a `via grant` relation)", object)
	}
	r := &ResourceAccessSurface{
		Table:        obj.Table,
		pk:           obj.pk(),
		readModes:    map[string]bool{},
		grantKinds:   map[string]bool{},
		aclTable:     edge.Table,
		recordCol:    edge.RecordCol,
		kindCol:      edge.KindCol,
		principalCol: edge.PrincipalCol,
		accessCol:    edge.AccessCol,
		discrimCol:   edge.DiscrimCol,
		discrimVal:   edge.DiscrimVal,
		accessorFn:   fmt.Sprintf("%s.%s_accessors", s.definerSchema(), obj.Table),
	}
	if len(s.conditionalAccessors(obj)) > 0 {
		r.conditional = true
		r.accessorFn = fmt.Sprintf("%s.%s_accessors_conditional", s.definerSchema(), obj.Table)
	}
	for _, lvl := range obj.Scoped {
		r.ScopeCols = append(r.ScopeCols, s.scopeCol(obj, lvl))
	}

	for _, pm := range obj.Perms {
		for _, t := range pm.Expr {
			if t.ModeCol != "" {
				r.ModeCol = t.ModeCol
				r.readModes[t.ModeVal] = true
			}
		}
	}
	if rel, _ := grantRelation(obj); rel != nil {
		for _, k := range rel.Types {
			r.grantKinds[k] = true
		}
	}
	return r, nil
}

func (r *ResourceAccessSurface) IsReadMode(mode string) bool { return r.readModes[mode] }

func (r *ResourceAccessSurface) GrantKindAllowed(kind string) bool { return r.grantKinds[kind] }

func (r *ResourceAccessSurface) ModeSQL() string {
	return fmt.Sprintf("SELECT %s FROM %s WHERE %s = $1", r.ModeCol, r.Table, r.pk)
}

func (r *ResourceAccessSurface) SetVisibilitySQL() string {
	return fmt.Sprintf("UPDATE %s SET %s = $1 WHERE %s = $2", r.Table, r.ModeCol, r.pk)
}

func (r *ResourceAccessSurface) GrantInsert(scope []string, resourceID, kind, principalID, access string) (string, []any) {
	cols := append([]string{}, r.ScopeCols...)
	args := make([]any, 0, len(scope)+5)
	for _, v := range scope {
		args = append(args, v)
	}
	if r.discrimCol != "" {
		cols = append(cols, r.discrimCol)
		args = append(args, r.discrimVal)
	}
	cols = append(cols, r.recordCol, r.kindCol, r.principalCol, r.accessCol)
	args = append(args, resourceID, kind, principalID, access)

	ph := make([]string, len(cols))
	for i := range ph {
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	conflict := []string{}
	if r.discrimCol != "" {
		conflict = append(conflict, r.discrimCol)
	}
	conflict = append(conflict, r.recordCol, r.kindCol, r.principalCol, r.accessCol)

	sql := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING RETURNING created_at",
		r.aclTable, strings.Join(cols, ", "), strings.Join(ph, ", "), strings.Join(conflict, ", "))
	return sql, args
}

func (r *ResourceAccessSurface) RevokeDelete(resourceID, kind, principalID, access string) (string, []any) {
	var conds []string
	var args []any
	add := func(col string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	add(r.recordCol, resourceID)
	if r.discrimCol != "" {
		add(r.discrimCol, r.discrimVal)
	}
	add(r.kindCol, kind)
	add(r.principalCol, principalID)
	if access != "" {
		add(r.accessCol, access)
	}
	return fmt.Sprintf("DELETE FROM %s WHERE %s", r.aclTable, strings.Join(conds, " AND ")), args
}

func (r *ResourceAccessSurface) ListGrantsSQL() string {
	sql := fmt.Sprintf("SELECT %s, %s, %s, created_at FROM %s WHERE %s = $1",
		r.kindCol, r.principalCol, r.accessCol, r.aclTable, r.recordCol)
	if r.discrimCol != "" {
		sql += fmt.Sprintf(" AND %s = $2", r.discrimCol)
	}
	return sql + " ORDER BY created_at"
}

func (r *ResourceAccessSurface) ListGrantsArgs(resourceID string) []any {
	if r.discrimCol != "" {
		return []any{resourceID, r.discrimVal}
	}
	return []any{resourceID}
}

// IsConditional reports whether this object's read admits a claim, so that its
// listing carries rows naming no principal.
func (r *ResourceAccessSurface) IsConditional() bool { return r.conditional }

// AccessorsSQL selects the enumerator. On a conditional surface it selects the
// claim columns too: they are the part of the answer that names nobody, and a
// caller that has asked for this surface has said it will read them.
func (r *ResourceAccessSurface) AccessorsSQL() string {
	if r.conditional {
		return fmt.Sprintf("SELECT source, principal_kind, principal_id, access, via_claim_key, via_claim_value FROM %s($1)", r.accessorFn)
	}
	return fmt.Sprintf("SELECT source, principal_kind, principal_id, access FROM %s($1)", r.accessorFn)
}
