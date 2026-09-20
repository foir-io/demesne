package demesne

import (
	"errors"
	"fmt"
	"strings"
)

type PermissionExport struct {
	Verb   string
	Name   string
	Params []ExportParameter
	Pos    Pos
}

type ExportParameter struct {
	Column string
	Type   string
	Name   string
}

var exportParameterTypes = map[string]bool{
	"text": true, "uuid": true, "smallint": true, "integer": true, "bigint": true, "boolean": true,
	"json": true, "jsonb": true, "numeric": true, "timestamptz": true, "timestamp": true, "date": true,
}

func (p ExportParameter) name() string {
	if p.Name != "" {
		return p.Name
	}
	return "p_" + p.Column
}

func (p *parser) parsePermissionExport(o *Object) error {
	export := PermissionExport{Pos: Pos{p.cur().line}}
	p.advance()
	var err error
	if export.Verb, err = p.ident(); err != nil {
		return err
	}
	if err = p.expectKw("as"); err != nil {
		return err
	}
	if export.Name, err = p.ident(); err != nil {
		return err
	}
	if _, err = p.expect(tLParen); err != nil {
		return err
	}
	for {
		var param ExportParameter
		if param.Column, err = p.ident(); err != nil {
			return err
		}
		if param.Type, err = p.ident(); err != nil {
			return err
		}
		if p.acceptKw("as") {
			if param.Name, err = p.ident(); err != nil {
				return err
			}
		}
		export.Params = append(export.Params, param)
		if p.peekKind() != tComma {
			break
		}
		p.advance()
	}
	if _, err = p.expect(tRParen); err != nil {
		return err
	}
	o.Exports = append(o.Exports, export)
	return nil
}

func (o *Object) mappedPerm(verb string) *Perm {
	for _, pm := range o.Perms {
		if pm.Verb == verb && contains(pm.Layers, "rls") && !pm.PredicateOnly && opToCmd[pm.Maps] != "" {
			return pm
		}
	}
	return nil
}

func (s *Spec) exportedRow(obj *Object, pm *Perm) *Object {
	row := *obj
	row.Perms = []*Perm{pm}
	row.Requires = nil
	row.ReachUses = nil
	for _, u := range obj.ReachUses {
		if len(u.Ops) == 0 || contains(u.Ops, pm.Maps) {
			row.ReachUses = append(row.ReachUses, u)
		}
	}
	terms := append([]*Term(nil), pm.Expr...)
	if rq := obj.requireFor(pm.Verb); rq != nil {
		row.Requires = []*Require{rq}
		terms = append(terms, rq.Expr...)
	}
	for _, a := range obj.Admits {
		if contains(a.Ops, pm.Maps) {
			row.Perms = append(row.Perms, a.perm(pm.Maps))
			terms = append(terms, a.Expr...)
		}
	}
	used := map[string]bool{}
	for _, t := range terms {
		used[strings.Split(t.Ident, ":")[0]] = true
		used[t.SessionRel] = true
		used[t.ExcludeRel] = true
	}
	row.Relations = nil
	for _, rel := range obj.Relations {
		for _, kind := range rel.Types {
			if s.Topology.LevelByName(kind) != nil {
				used[rel.Name] = true
			}
		}
		if used[rel.Name] {
			row.Relations = append(row.Relations, rel)
		}
	}
	return &row
}

func (s *Spec) exportedColumns(row *Object) map[string]bool {
	binder := &schBinder{columns: map[string]map[string]bool{}}
	s.schCheckObjectRefs(binder, row)
	for _, pm := range row.Perms {
		if pm.Guard != nil {
			binder.reqCol(row.Table, pm.Guard.Col, "export guard")
		}
	}
	for _, rq := range row.Requires {
		for _, t := range rq.Expr {
			for _, column := range []string{t.ModeCol, t.SelfCol} {
				if column != "" {
					binder.reqCol(row.Table, column, "export requirement")
				}
			}
			if t.WithinLevel != "" {
				binder.reqCol(row.Table, s.scopeCol(row, t.WithinLevel), "export requirement")
			}
			for _, arg := range t.ExternalArgs {
				if arg.Col != "" {
					binder.reqCol(row.Table, arg.Col, "export requirement")
				}
			}
		}
	}
	return binder.columns[row.Table]
}

func (s *Spec) validatePermissionExports() error {
	var errs []error
	names := map[string]bool{}
	for _, obj := range s.Objects {
		for _, export := range obj.Exports {
			if names[export.Name] {
				errs = append(errs, fmt.Errorf("line %d: permission export %q is declared twice", export.Pos.Line, export.Name))
			}
			names[export.Name] = true
			errs = append(errs, s.validatePermissionExport(obj, export)...)
		}
	}
	return errors.Join(errs...)
}

func (s *Spec) validatePermissionExport(obj *Object, export PermissionExport) []error {
	pm := obj.mappedPerm(export.Verb)
	if pm == nil {
		return []error{fmt.Errorf("line %d: export %s.%s needs a permission that maps a table operation under @rls", export.Pos.Line, obj.Name, export.Verb)}
	}
	var errs []error
	params, names := map[string]bool{}, map[string]bool{}
	for _, param := range export.Params {
		if names[param.name()] || params[param.Column] {
			errs = append(errs, fmt.Errorf("line %d: export %q binds column %q or parameter %q twice", export.Pos.Line, export.Name, param.Column, param.name()))
		}
		names[param.name()] = true
		params[param.Column] = true
		if !exportParameterTypes[param.Type] {
			errs = append(errs, fmt.Errorf("line %d: export %q parameter %q has unsupported type %q", export.Pos.Line, export.Name, param.name(), param.Type))
		}
	}
	for column := range s.exportedColumns(s.exportedRow(obj, pm)) {
		if !params[column] {
			errs = append(errs, fmt.Errorf("line %d: export %q reads row column %q, which no parameter binds", export.Pos.Line, export.Name, column))
		}
	}
	return errs
}

func (s *Spec) defEmitPermissionExports(out *[]GenFn, virtual map[string]bool) error {
	seen := map[string]bool{}
	for _, fn := range *out {
		seen[fn.Name] = true
	}
	for _, obj := range s.Objects {
		for _, export := range obj.Exports {
			if seen[export.Name] {
				return fmt.Errorf("permission export %q collides with a generated function", export.Name)
			}
			seen[export.Name] = true
			pm := obj.mappedPerm(export.Verb)
			if pm == nil {
				return fmt.Errorf("permission export %q: object %q has no mapped permission %q", export.Name, obj.Name, export.Verb)
			}
			pred, err := s.admissionWithRequire(obj, pm, s.ownerSubject(obj.Scoped[len(obj.Scoped)-1]), virtual)
			if err != nil {
				return err
			}
			var args, columns []string
			for _, param := range export.Params {
				args = append(args, param.name()+" "+param.Type)
				columns = append(columns, param.name()+" AS "+param.Column)
			}
			*out = append(*out, GenFn{Name: export.Name, Sig: strings.Join(args, ", "), Body: pred + " FROM (SELECT " + strings.Join(columns, ", ") + ") AS " + obj.Table})
		}
	}
	return nil
}
