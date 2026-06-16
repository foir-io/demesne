package demesne

import (
	"errors"
	"fmt"
	"sort"
)

// Schema is a snapshot of the target database's relevant structure — its tables
// and their columns. It is PLAIN DATA: the engine validates a spec against it
// (ValidateAgainst) without ever touching a database, so the engine stays
// stdlib-pure (the moat). The caller introspects the real DB — pg_catalog /
// information_schema — and populates a Schema; the engine checks that every
// table and column the spec references actually exists. This is the binding
// half of "point Demesne at your database and configure your authz" (WS4).
type Schema struct {
	tables map[string]map[string]Column // table → column name → column
	fks    []ForeignKey                 // foreign keys (for topology inference)
}

// Column is one column of a table, as introspected.
type Column struct {
	Name     string
	DataType string // the SQL type, e.g. "text", "uuid", "timestamp with time zone"
	Nullable bool
}

// ForeignKey is one FK edge: Table.Column references RefTable.RefColumn. Used by
// Scaffold to infer the tenancy hierarchy (which tables are containers).
type ForeignKey struct {
	Table, Column, RefTable, RefColumn string
}

// NewSchema returns an empty schema to populate via AddColumn / AddForeignKey.
func NewSchema() *Schema { return &Schema{tables: map[string]map[string]Column{}} }

// AddColumn records a column on a table (creating the table entry if needed).
func (s *Schema) AddColumn(table, name, dataType string, nullable bool) {
	if s.tables == nil {
		s.tables = map[string]map[string]Column{}
	}
	if s.tables[table] == nil {
		s.tables[table] = map[string]Column{}
	}
	s.tables[table][name] = Column{Name: name, DataType: dataType, Nullable: nullable}
}

// AddForeignKey records a foreign-key edge (Table.Column → RefTable.RefColumn).
func (s *Schema) AddForeignKey(table, column, refTable, refColumn string) {
	s.fks = append(s.fks, ForeignKey{Table: table, Column: column, RefTable: refTable, RefColumn: refColumn})
}

func (s *Schema) hasTable(table string) bool {
	_, ok := s.tables[table]
	return ok
}

func (s *Schema) hasColumn(table, col string) bool {
	cols, ok := s.tables[table]
	if !ok {
		return false
	}
	_, ok = cols[col]
	return ok
}

// ValidateAgainst checks that every table and column the spec references exists
// in the supplied schema — object tables and their scope/owner/mode columns,
// relation edges (column / edge / closure / composition) + their columns, the
// descriptor grant store, role stores, level-grant edges, and membership tables.
// A reference the database lacks is a spec/schema mismatch (a typo, a missing
// migration, drift, or a legacy column that no longer exists). All mismatches are
// reported together. Passing means the spec is BINDABLE to this database.
func (s *Spec) ValidateAgainst(sc *Schema) error {
	if sc == nil {
		return fmt.Errorf("ValidateAgainst: nil schema")
	}
	var errs []error
	// req records a needed (table, column); table=="" requires only the table.
	reqTable := func(table, ctx string) bool {
		if !sc.hasTable(table) {
			errs = append(errs, fmt.Errorf("%s: table %q not found in the database", ctx, table))
			return false
		}
		return true
	}
	reqCol := func(table, col, ctx string) {
		if !sc.hasTable(table) {
			errs = append(errs, fmt.Errorf("%s: table %q (for column %q) not found in the database", ctx, table, col))
			return
		}
		if !sc.hasColumn(table, col) {
			errs = append(errs, fmt.Errorf("%s: table %q has no column %q", ctx, table, col))
		}
	}

	for _, o := range s.Objects {
		oc := "object " + o.Name
		if !reqTable(o.Table, oc) {
			continue // no point checking columns of a missing table
		}
		// Scope columns (every ancestor level the object pins; the level-entity
		// uses its own `id`). A VIRTUAL level carries no scope column (a global
		// object scoped at the platform root has no containment column), so skip it.
		for _, lvl := range o.Scoped {
			if s.levelIsVirtual(lvl) {
				continue
			}
			reqCol(o.Table, scopeCol(o, lvl), oc+" scope")
		}
		// Relations.
		for _, r := range o.Relations {
			rc := fmt.Sprintf("%s relation %q", oc, r.Name)
			switch repr := r.Repr.(type) {
			case ViaColumn:
				reqCol(o.Table, repr.Column, rc)
			case ViaEdge:
				if reqTable(repr.Table, rc) {
					for _, c := range repr.Cols {
						reqCol(repr.Table, c, rc)
					}
				}
			case ViaComposition:
				reqTable(repr.Table, rc)
			case ViaClosure:
				reqCol(o.Table, repr.Col, rc)
				if reqTable(repr.Closure, rc) {
					reqCol(repr.Closure, repr.AncestorCol, rc)
					reqCol(repr.Closure, repr.DescendantCol, rc)
				}
				if reqTable(repr.Base, rc) {
					reqCol(repr.Base, repr.BaseID, rc)
					reqCol(repr.Base, repr.BaseParent, rc)
				}
			case ViaGroup:
				reqCol(o.Table, repr.Col, rc)
				if reqTable(repr.Closure, rc) {
					reqCol(repr.Closure, repr.GroupCol, rc)
					reqCol(repr.Closure, repr.MemberCol, rc)
				}
				if reqTable(repr.Edge, rc) {
					reqCol(repr.Edge, repr.EdgeMember, rc)
					reqCol(repr.Edge, repr.EdgeGroup, rc)
				}
			case ViaObject:
				// The FK column on this object; the other object's table is checked
				// when that object is validated.
				reqCol(o.Table, repr.Col, rc)
			case ViaMemberIn:
				// Column-sourced args reference this object's own table; the role
				// store (where membership lives) is checked under "Role stores" below.
				if repr.Principal.Col != "" {
					reqCol(o.Table, repr.Principal.Col, rc)
				}
				if repr.Scope.Col != "" {
					reqCol(o.Table, repr.Scope.Col, rc)
				}
			}
		}
		// Descriptor: owner axis, mode column, grant store.
		if d := o.Descriptor; d != nil {
			if d.Owner != nil {
				if vc, ok := d.Owner.Repr.(ViaColumn); ok {
					reqCol(o.Table, vc.Column, oc+" descriptor owner")
					if vc.DiscrimCol != "" {
						reqCol(o.Table, vc.DiscrimCol, oc+" descriptor owner kind")
					}
				}
			}
			if d.AdminOwner != nil {
				if vc, ok := d.AdminOwner.Repr.(ViaColumn); ok {
					reqCol(o.Table, vc.Column, oc+" descriptor admin owner")
					if vc.DiscrimCol != "" {
						reqCol(o.Table, vc.DiscrimCol, oc+" descriptor admin owner kind")
					}
				}
			}
			if d.ModeCol != "" {
				reqCol(o.Table, d.ModeCol, oc+" descriptor mode")
			}
			if g := d.Grants; g != nil && reqTable(g.Table, oc+" descriptor grants") {
				cols := []string{g.RecordCol, g.KindCol, g.PrincipalCol, g.AccessCol}
				if g.DiscrimCol != "" {
					cols = append(cols, g.DiscrimCol)
				}
				for _, c := range cols {
					reqCol(g.Table, c, oc+" descriptor grants")
				}
			}
		}
	}

	// Role stores.
	for _, rs := range s.RoleStores {
		rc := "rolestore " + rs.Name
		if reqTable(rs.Assignments, rc) {
			for _, c := range append([]string{rs.KindCol, rs.SubjectCol, rs.RoleCol, rs.RevokedCol}, rs.ScopeCols...) {
				reqCol(rs.Assignments, c, rc)
			}
		}
		if reqTable(rs.RolesTable, rc+" roles") {
			reqCol(rs.RolesTable, rs.RolesID, rc+" roles")
			reqCol(rs.RolesTable, rs.KeyCol, rc+" roles")
		}
	}

	// Level-scoped grants.
	for _, g := range s.Grants {
		gc := "grant " + g.Name
		if reqTable(g.Table, gc) {
			reqCol(g.Table, g.GranteeCol, gc)
			reqCol(g.Table, g.LevelCol, gc)
			if g.ActiveCol != "" {
				reqCol(g.Table, g.ActiveCol, gc)
			}
			if g.ExpiresCol != "" {
				reqCol(g.Table, g.ExpiresCol, gc)
			}
		}
	}

	// Membership subjects (the legacy god-flag form).
	for _, sub := range s.Subjects {
		if m := sub.Membership; m != nil {
			mc := "subject " + sub.Name + " membership"
			if reqTable(m.Table, mc) {
				reqCol(m.Table, m.IDCol, mc)
				reqCol(m.Table, m.FlagCol, mc)
				if m.ActiveCol != "" {
					reqCol(m.Table, m.ActiveCol, mc)
				}
			}
		}
	}

	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return errors.Join(errs...)
}
