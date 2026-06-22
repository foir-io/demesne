package demesne

import (
	"errors"
	"fmt"
	"sort"
)

type Schema struct {
	tables map[string]map[string]Column
	fks    []ForeignKey
}

type Column struct {
	Name     string
	DataType string
	Nullable bool
}

type ForeignKey struct {
	Table, Column, RefTable, RefColumn string
}

func NewSchema() *Schema { return &Schema{tables: map[string]map[string]Column{}} }

func (s *Schema) AddColumn(table, name, dataType string, nullable bool) {
	if s.tables == nil {
		s.tables = map[string]map[string]Column{}
	}
	if s.tables[table] == nil {
		s.tables[table] = map[string]Column{}
	}
	s.tables[table][name] = Column{Name: name, DataType: dataType, Nullable: nullable}
}

func (s *Schema) AddForeignKey(table, column, refTable, refColumn string) {
	s.fks = append(s.fks, ForeignKey{Table: table, Column: column, RefTable: refTable, RefColumn: refColumn})
}

func (s *Schema) hasTable(table string) bool {
	_, ok := s.tables[table]
	return ok
}

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

func (s *Spec) emissionReferencesPK(o *Object) bool {
	for _, pm := range o.Perms {
		if contains(pm.Layers, "kernel") {
			return true
		}
	}
	for _, r := range o.Relations {
		switch r.Repr.(type) {
		case ViaGrant, ViaEdge, ViaComposition:
			return true
		}
	}
	for _, other := range s.Objects {
		for _, r := range other.Relations {
			if vo, ok := r.Repr.(ViaObject); ok && vo.Object == o.Name {
				return true
			}
		}
	}
	return false
}

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

type schBinder struct {
	sc   *Schema
	errs []error
}

func (b *schBinder) reqTable(table, ctx string) bool {
	if !b.sc.hasTable(table) {
		b.errs = append(b.errs, fmt.Errorf("%s: table %q not found in the database", ctx, table))
		return false
	}
	return true
}

func (b *schBinder) reqCol(table, col, ctx string) {
	if !b.sc.hasTable(table) {
		b.errs = append(b.errs, fmt.Errorf("%s: table %q (for column %q) not found in the database", ctx, table, col))
		return
	}
	if !b.sc.hasColumn(table, col) {
		b.errs = append(b.errs, fmt.Errorf("%s: table %q has no column %q", ctx, table, col))
	}
}

func (s *Spec) schCheckObjectRefs(b *schBinder, o *Object) {
	oc := "object " + o.Name
	if !b.reqTable(o.Table, oc) {
		return
	}

	if s.emissionReferencesPK(o) {
		b.reqCol(o.Table, o.pk(), oc+" pk")
	}

	for _, lvl := range o.Scoped {
		if s.levelIsVirtual(lvl) {
			continue
		}
		b.reqCol(o.Table, s.scopeCol(o, lvl), oc+" scope")
	}
	for _, r := range o.Relations {
		schCheckRelationRefs(b, o, r)
	}

	for _, pm := range o.Perms {
		for _, t := range pm.Expr {
			if t.ModeCol != "" {
				b.reqCol(o.Table, t.ModeCol, oc+" mode term")
			}
		}
	}
}

func schCheckComposition(b *schBinder, repr ViaComposition, rc string) {
	if !b.reqTable(repr.Table, rc) {
		return
	}
	b.reqCol(repr.Table, repr.ChildCol, rc)
	b.reqCol(repr.Table, repr.ParentCol, rc)
	if repr.KindCol != "" {
		b.reqCol(repr.Table, repr.KindCol, rc+" kind")
	}
}

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
		schCheckComposition(b, repr, rc)
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

		b.reqCol(o.Table, repr.Col, rc)
	case ViaGrant:

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

		if repr.Principal.Col != "" {
			b.reqCol(o.Table, repr.Principal.Col, rc)
		}
		if repr.Scope.Col != "" {
			b.reqCol(o.Table, repr.Scope.Col, rc)
		}
	}
}

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

		if rs.PermsCol != "" {
			b.reqCol(rs.RolesTable, rs.PermsCol, rc+" roles")
		}
	}
}

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
