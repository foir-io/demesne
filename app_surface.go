package demesne

import (
	"fmt"
)

type AppCheckSurface struct {
	Objects []AppObjectSurface
}

type AppObjectSurface struct {
	Object string
	Table  string
	PK     string

	FlatListFn string

	AsyncCheckSQL string

	EditCheckSQL string

	// Checks holds one point-check per @check permission (verb + SQL): compiled
	// predicates exposed as Can<Verb>, with no RLS policy.
	Checks []AppCheck
}

// AppCheck is one @check permission's point-check: its verb and the boolean SELECT.
type AppCheck struct {
	Verb     string
	CheckSQL string
}

func (s *Spec) EmitAppSurface() (*AppCheckSurface, error) {
	if len(s.Objects) == 0 {
		return nil, fmt.Errorf("EmitAppSurface: the spec declares no objects")
	}
	out := &AppCheckSurface{Objects: make([]AppObjectSurface, 0, len(s.Objects))}
	for _, o := range s.Objects {

		if !o.pointCheckable() {
			continue
		}
		editSQL, err := s.editPointCheckSQL(o)
		if err != nil {
			return nil, fmt.Errorf("EmitAppSurface: %s edit point-check: %w", o.Name, err)
		}
		var checks []AppCheck
		for _, pm := range o.Perms {
			if !contains(pm.Layers, "check") {
				continue
			}
			sql, err := s.permPointCheckSQL(o, pm)
			if err != nil {
				return nil, fmt.Errorf("EmitAppSurface: %s.%s @check point-check: %w", o.Name, pm.Verb, err)
			}
			if sql == "" {
				continue
			}
			checks = append(checks, AppCheck{Verb: pm.Verb, CheckSQL: sql})
		}
		out.Objects = append(out.Objects, AppObjectSurface{
			Object:        o.Name,
			Table:         o.Table,
			PK:            o.pk(),
			FlatListFn:    s.flatListFn(o),
			AsyncCheckSQL: s.asyncCheckSQL(o),
			EditCheckSQL:  editSQL,
			Checks:        checks,
		})
	}
	return out, nil
}

func (s *Spec) flatListFn(o *Object) string {
	var sel *Perm
	for _, pm := range o.Perms {
		if pm.Maps == "select" {
			sel = pm
			break
		}
	}

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
		return ""
	}

	return fmt.Sprintf("%s.%s_%s_flat_resources", s.definerSchema(), o.Table, rel.Name)
}

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
		s.asyncIndexBase(o.Table, rel.Name), kind, s.idClaim(cust.Identifies))
}

func (a *AppCheckSurface) Object(name string) (AppObjectSurface, bool) {
	for _, o := range a.Objects {
		if o.Object == name {
			return o, true
		}
	}
	return AppObjectSurface{}, false
}

func (o AppObjectSurface) CheckSQL() string {
	return fmt.Sprintf("SELECT EXISTS (SELECT 1 FROM %s WHERE %s = $1)", o.Table, o.PK)
}

func (o AppObjectSurface) CheckEditSQL() string { return o.EditCheckSQL }

// CheckVerbSQL returns the point-check SQL for a @check verb, or "" if the object
// has no @check permission of that name.
func (o AppObjectSurface) CheckVerbSQL(verb string) string {
	for _, c := range o.Checks {
		if c.Verb == verb {
			return c.CheckSQL
		}
	}
	return ""
}

func (o AppObjectSurface) CheckManySQL() string {
	return fmt.Sprintf("SELECT %s FROM %s WHERE %s = ANY($1)", o.PK, o.Table, o.PK)
}

func (o AppObjectSurface) ListResourcesSQL() string {

	return fmt.Sprintf(
		"SELECT %s FROM %s WHERE ($1::text IS NULL OR %s::text > $1::text) ORDER BY %s::text LIMIT $2",
		o.PK, o.Table, o.PK, o.PK)
}

func (o AppObjectSurface) ListResourcesFastSQL() string {
	if o.FlatListFn == "" {
		return ""
	}
	return fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s IN (SELECT %s()) AND ($1::text IS NULL OR %s::text > $1::text) ORDER BY %s::text LIMIT $2",
		o.PK, o.Table, o.PK, o.FlatListFn, o.PK, o.PK)
}
