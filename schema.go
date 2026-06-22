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

// Tables returns every table name recorded in the schema, sorted. Exposed for
// tooling (e.g. TableCoverage, which classifies the live tables against the spec).
func (s *Schema) Tables() []string {
	out := make([]string, 0, len(s.tables))
	for t := range s.tables {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (s *Schema) hasColumn(table, col string) bool {
	cols, ok := s.tables[table]
	if !ok {
		return false
	}
	_, ok = cols[col]
	return ok
}

// emissionReferencesPK reports whether the object's GENERATED SQL names its own
// primary-key column — so the bind-check must verify that column exists. It
// mirrors exactly the emit sites that use obj.pk(): a grant/edge/composition
// relation predicate (`<table>.<pk>`), a @kernel reachability gate (`r.<pk>`),
// and being the TARGET of another object's cross-object borrow (`<O>_can_<verb>`
// runs at this row). A pure containment-scoped object (only @scoped / owner-column
// / role terms) never names its PK, so it is NOT required to have one — the key
// may be composite or arbitrarily named. (The level-entity self column is the PK
// too, but it is checked as the object's leaf scope column, not here.)
func (s *Spec) emissionReferencesPK(o *Object) bool {
	for _, pm := range o.Perms {
		if contains(pm.Layers, "kernel") {
			return true // kernelDefiner: EXISTS(... WHERE r.<pk> = p_<obj>_id)
		}
	}
	for _, r := range o.Relations {
		switch r.Repr.(type) {
		case ViaGrant, ViaEdge, ViaComposition:
			return true // the predicate / grant fragments reference <table>.<pk>
		}
	}
	for _, other := range s.Objects {
		for _, r := range other.Relations {
			if vo, ok := r.Repr.(ViaObject); ok && vo.Object == o.Name {
				return true // <O>_can_<verb>(id): runs o's predicate at o.<pk>
			}
		}
	}
	return false
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
	b := &schBinder{sc: sc}

	for _, o := range s.Objects {
		s.schCheckObjectRefs(b, o)
	}
	for _, rs := range s.RoleStores {
		schCheckRoleStoreRefs(b, rs)
	}
	for _, g := range s.Grants {
		schCheckGrantRefs(b, g)
	}
	for _, sub := range s.Subjects {
		schCheckSubjectRefs(b, sub)
	}

	sort.Slice(b.errs, func(i, j int) bool { return b.errs[i].Error() < b.errs[j].Error() })
	return errors.Join(b.errs...)
}

// schBinder accumulates reference-check failures while ValidateAgainst walks a
// spec against a Schema. reqTable/reqCol mirror the original closures exactly so
// the reported errors (text and set) are unchanged.
type schBinder struct {
	sc   *Schema
	errs []error
}

// reqTable records a needed table; returns whether it exists.
func (b *schBinder) reqTable(table, ctx string) bool {
	if !b.sc.hasTable(table) {
		b.errs = append(b.errs, fmt.Errorf("%s: table %q not found in the database", ctx, table))
		return false
	}
	return true
}

// reqCol records a needed (table, column).
func (b *schBinder) reqCol(table, col, ctx string) {
	if !b.sc.hasTable(table) {
		b.errs = append(b.errs, fmt.Errorf("%s: table %q (for column %q) not found in the database", ctx, table, col))
		return
	}
	if !b.sc.hasColumn(table, col) {
		b.errs = append(b.errs, fmt.Errorf("%s: table %q has no column %q", ctx, table, col))
	}
}

// schCheckObjectRefs checks an object's table, primary key, scope columns,
// relations and permission mode terms.
func (s *Spec) schCheckObjectRefs(b *schBinder, o *Object) {
	oc := "object " + o.Name
	if !b.reqTable(o.Table, oc) {
		return // no point checking columns of a missing table
	}
	// The object's primary-key column must exist — but ONLY when emission
	// actually references it (a grant/edge/composition predicate, the @kernel
	// gate, or a cross-object borrow at this row); a pure containment-scoped
	// table never names its PK, so requiring `id` there would wrongly reject a
	// table whose key is composite or differently named. The level-entity's PK
	// is checked below as its leaf scope column. Declared `pk`, else `id`
	// (de-Foirs the `id` assumption, EID-278).
	if s.emissionReferencesPK(o) {
		b.reqCol(o.Table, o.pk(), oc+" pk")
	}
	// Scope columns (every ancestor level the object pins; the level-entity
	// uses its own primary key). A VIRTUAL level carries no scope column (a
	// global object scoped at the platform root has no containment column), so
	// skip it.
	for _, lvl := range o.Scoped {
		if s.levelIsVirtual(lvl) {
			continue
		}
		b.reqCol(o.Table, s.scopeCol(o, lvl), oc+" scope")
	}
	for _, r := range o.Relations {
		schCheckRelationRefs(b, o, r)
	}
	// Column-condition (visibility) terms in permissions reference a column on
	// this object's own table.
	for _, pm := range o.Perms {
		for _, t := range pm.Expr {
			if t.ModeCol != "" {
				b.reqCol(o.Table, t.ModeCol, oc+" mode term")
			}
		}
	}
}

// schCheckRelationRefs checks the tables/columns a single relation references,
// dispatching on its representation.
func schCheckRelationRefs(b *schBinder, o *Object, r *Relation) {
	rc := fmt.Sprintf("object %s relation %q", o.Name, r.Name)
	switch repr := r.Repr.(type) {
	case ViaColumn:
		b.reqCol(o.Table, repr.Column, rc)
		if repr.DiscrimCol != "" {
			b.reqCol(o.Table, repr.DiscrimCol, rc+" kind")
		}
	case ViaEdge:
		if b.reqTable(repr.Table, rc) {
			for _, c := range repr.Cols {
				b.reqCol(repr.Table, c, rc)
			}
		}
	case ViaComposition:
		if b.reqTable(repr.Table, rc) {
			b.reqCol(repr.Table, repr.ChildCol, rc)
			b.reqCol(repr.Table, repr.ParentCol, rc)
			if repr.KindCol != "" {
				b.reqCol(repr.Table, repr.KindCol, rc+" kind")
			}
		}
	case ViaClosure:
		b.reqCol(o.Table, repr.Col, rc)
		if b.reqTable(repr.Closure, rc) {
			b.reqCol(repr.Closure, repr.AncestorCol, rc)
			b.reqCol(repr.Closure, repr.DescendantCol, rc)
		}
		if b.reqTable(repr.Base, rc) {
			b.reqCol(repr.Base, repr.BaseID, rc)
			b.reqCol(repr.Base, repr.BaseParent, rc)
		}
	case ViaGroup:
		b.reqCol(o.Table, repr.Col, rc)
		if b.reqTable(repr.Closure, rc) {
			b.reqCol(repr.Closure, repr.GroupCol, rc)
			b.reqCol(repr.Closure, repr.MemberCol, rc)
		}
		if b.reqTable(repr.Edge, rc) {
			b.reqCol(repr.Edge, repr.EdgeMember, rc)
			b.reqCol(repr.Edge, repr.EdgeGroup, rc)
		}
	case ViaObject:
		// The FK column on this object; the other object's table is checked
		// when that object is validated.
		b.reqCol(o.Table, repr.Col, rc)
	case ViaGrant:
		// The 4-column access-class ACL store (+ a discriminator column when a
		// shared store), like the descriptor grant store.
		if b.reqTable(repr.Table, rc) {
			cols := []string{repr.RecordCol, repr.KindCol, repr.PrincipalCol, repr.AccessCol}
			if repr.DiscrimCol != "" {
				cols = append(cols, repr.DiscrimCol)
			}
			for _, c := range cols {
				b.reqCol(repr.Table, c, rc)
			}
		}
	case ViaMemberIn:
		// Column-sourced args reference this object's own table; the role
		// store (where membership lives) is checked under "Role stores" below.
		if repr.Principal.Col != "" {
			b.reqCol(o.Table, repr.Principal.Col, rc)
		}
		if repr.Scope.Col != "" {
			b.reqCol(o.Table, repr.Scope.Col, rc)
		}
	}
}

// schCheckRoleStoreRefs checks a role store's assignment and roles tables.
func schCheckRoleStoreRefs(b *schBinder, rs *RoleStore) {
	rc := "rolestore " + rs.Name
	if b.reqTable(rs.Assignments, rc) {
		for _, c := range append([]string{rs.KindCol, rs.SubjectCol, rs.RoleCol, rs.RevokedCol}, rs.ScopeCols...) {
			b.reqCol(rs.Assignments, c, rc)
		}
	}
	if b.reqTable(rs.RolesTable, rc+" roles") {
		b.reqCol(rs.RolesTable, rs.RolesID, rc+" roles")
		b.reqCol(rs.RolesTable, rs.KeyCol, rc+" roles")
		// The optional materialized permissions column (holds-resolver, EID-334) is
		// checked only when declared; "" means the rolestore has none.
		if rs.PermsCol != "" {
			b.reqCol(rs.RolesTable, rs.PermsCol, rc+" roles")
		}
	}
}

// schCheckGrantRefs checks a level-scoped grant's edge table and columns.
func schCheckGrantRefs(b *schBinder, g *Grant) {
	gc := "grant " + g.Name
	if b.reqTable(g.Table, gc) {
		b.reqCol(g.Table, g.GranteeCol, gc)
		b.reqCol(g.Table, g.LevelCol, gc)
		if g.ActiveCol != "" {
			b.reqCol(g.Table, g.ActiveCol, gc)
		}
		if g.ExpiresCol != "" {
			b.reqCol(g.Table, g.ExpiresCol, gc)
		}
	}
}

// schCheckSubjectRefs checks a membership subject (the legacy god-flag form).
func schCheckSubjectRefs(b *schBinder, sub *Subject) {
	m := sub.Membership
	if m == nil {
		return
	}
	mc := "subject " + sub.Name + " membership"
	if b.reqTable(m.Table, mc) {
		b.reqCol(m.Table, m.IDCol, mc)
		b.reqCol(m.Table, m.FlagCol, mc)
		if m.ActiveCol != "" {
			b.reqCol(m.Table, m.ActiveCol, mc)
		}
	}
}
