package demesne

import (
	"fmt"
	"strings"
)

// Access runtime layer (the read/write dual of the emit layer). A descriptor
// object's RLS policies + read definers are GENERATED from its descriptor; a
// runtime that sets visibility, grants / revokes / lists access, or runs Expand
// needs the SAME descriptor layout to build its statements. ResourceAccessSurface
// is that projection plus the SQL shapes — one source of truth for the layout, so
// a handler never re-derives it (and can't drift from the emitted policies).
//
// Like the rest of the runtime glue (PointCheckSQL, ClaimsSetSQL) these are
// stdlib-pure: they return SQL strings + ordered args; the caller executes them
// under the principal's claims (db.WithRLS), so the DATABASE still enforces — this
// is NOT a second evaluator. Authorization stays in RLS (the @store_manage
// write-moat on the grant store, the SELECT predicate on reads); this layer only
// owns how the statements are SHAPED from the descriptor.
//
// `created_at` is treated as the grant edge's standard audit column (every grant
// is a timestamped fact); GrantInsert returns it and ListGrants selects it.
type ResourceAccessSurface struct {
	// Table is the resource's own table (e.g. records).
	Table string
	// ScopeCols are the containment columns root→leaf (e.g. tenant_id, project_id),
	// written on a new grant row.
	ScopeCols []string
	// ModeCol is the per-row visibility column (e.g. access_mode).
	ModeCol string

	readModes  map[string]bool
	grantKinds map[string]bool

	aclTable     string
	recordCol    string
	kindCol      string
	principalCol string
	accessCol    string
	discrimCol   string // "" when the grant store is single-kind (not shared)
	discrimVal   string
	accessorFn   string // qualified, e.g. auth.records_accessors
}

// ResourceAccessSurface projects an object's access descriptor into the runtime
// surface: its physical layout (table, scope/mode columns, the grant edge's
// columns + discriminator, the allowed grant kinds + read modes) and the
// generated accessor enumerator's qualified name. Errors if the object has no
// descriptor grant store.
func (s *Spec) ResourceAccessSurface(object string) (*ResourceAccessSurface, error) {
	obj := s.objectByName(object)
	if obj == nil {
		return nil, fmt.Errorf("ResourceAccessSurface: no object %q in the spec", object)
	}
	// The grant store comes from EITHER a descriptor `grants` edge or a `via grant`
	// relation (the pure-relation form) — objectGrantEdge unifies them, so the
	// runtime surface is byte-identical whichever way the object models access.
	edge := objectGrantEdge(obj)
	if edge == nil {
		return nil, fmt.Errorf("ResourceAccessSurface: object %q has no grant store (descriptor grants or a `via grant` relation)", object)
	}
	r := &ResourceAccessSurface{
		Table:        obj.Table,
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
	for _, lvl := range obj.Scoped {
		r.ScopeCols = append(r.ScopeCols, scopeCol(obj, lvl))
	}
	if d := obj.Descriptor; d != nil {
		// Descriptor form: the mode column + read/list modes are declared in the block.
		r.ModeCol = d.ModeCol
		for _, m := range d.Modes {
			switch m.Kind {
			case "read":
				r.readModes[m.Value] = true
			case "list":
				r.grantKinds[m.Value] = true
			}
		}
	} else {
		// Pure-relation form: read modes come from the `mode <col> = "<v>"` terms in
		// the object's permissions (the mode column + each sentinel), and the grant
		// kinds from the grant relation's declared types.
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
	}
	return r, nil
}

// IsReadMode reports whether a stored mode sentinel opens public read (e.g.
// "public"). The owner-only baseline ("private") is not a read mode.
func (r *ResourceAccessSurface) IsReadMode(mode string) bool { return r.readModes[mode] }

// GrantKindAllowed reports whether the descriptor's grant list admits a principal
// kind (e.g. "customer", "admin").
func (r *ResourceAccessSurface) GrantKindAllowed(kind string) bool { return r.grantKinds[kind] }

// ModeSQL reads a resource's visibility mode: $1 = resource id.
func (r *ResourceAccessSurface) ModeSQL() string {
	return fmt.Sprintf("SELECT %s FROM %s WHERE id = $1", r.ModeCol, r.Table)
}

// SetVisibilitySQL sets a resource's visibility mode: $1 = mode sentinel,
// $2 = resource id. Rides the resource's own edit RLS (a non-editor matches 0
// rows under USING — the caller treats 0 affected as a denial).
func (r *ResourceAccessSurface) SetVisibilitySQL() string {
	return fmt.Sprintf("UPDATE %s SET %s = $1 WHERE id = $2", r.Table, r.ModeCol)
}

// GrantInsert builds the grant INSERT and its ordered args. scope is the
// containment values root→leaf (matching ScopeCols). The row carries the
// discriminator constant when the store is shared; ON CONFLICT DO NOTHING makes a
// re-grant idempotent; RETURNING created_at echoes the grant timestamp. The
// WITH CHECK on the grant store (the @store_manage write-moat) enforces that the
// caller can edit the resource — an RLS-blocked INSERT errors (permission denied).
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

// RevokeDelete builds the grant DELETE and its ordered args. An empty access
// revokes every level this grantee holds; the discriminator scopes the delete to
// this resource kind. Under the caller's RLS a non-editor matches 0 rows (silent)
// — revoke is idempotent, so 0 removed is an honest result.
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

// ListGrantsSQL selects the explicit grant rows on a resource: (kind, principal,
// access, created_at), ordered by created_at. Pair with ListGrantsArgs.
func (r *ResourceAccessSurface) ListGrantsSQL() string {
	sql := fmt.Sprintf("SELECT %s, %s, %s, created_at FROM %s WHERE %s = $1",
		r.kindCol, r.principalCol, r.accessCol, r.aclTable, r.recordCol)
	if r.discrimCol != "" {
		sql += fmt.Sprintf(" AND %s = $2", r.discrimCol)
	}
	return sql + " ORDER BY created_at"
}

// ListGrantsArgs returns the args for ListGrantsSQL ($1 = resource id, and the
// discriminator constant when the store is shared).
func (r *ResourceAccessSurface) ListGrantsArgs(resourceID string) []any {
	if r.discrimCol != "" {
		return []any{resourceID, r.discrimVal}
	}
	return []any{resourceID}
}

// AccessorsSQL runs the Expand enumerator: the generated SECURITY DEFINER
// auth.<table>_accessors($1) → rows of (source, principal_kind, principal_id,
// access). $1 = resource id. The definer is built from the same descriptor, so the
// enumerated accessors agree with the SELECT predicate by construction.
func (r *ResourceAccessSurface) AccessorsSQL() string {
	return fmt.Sprintf("SELECT source, principal_kind, principal_id, access FROM %s($1)", r.accessorFn)
}
