package demesne

import (
	"errors"
	"fmt"
	"strings"
)

type Admit struct {
	Ops  []string
	Expr []*Term
	Tree *PermNode
	Pos  Pos
}

func (a *Admit) perm(op string) *Perm {
	return &Perm{Verb: "admit", Expr: a.Expr, Tree: a.Tree, Layers: []string{"rls"}, Maps: op, Pos: a.Pos}
}

func (p *parser) parseAdmit(o *Object) error {
	a := &Admit{Pos: Pos{p.cur().line}}
	p.advance()
	ops, err := p.parseOperationList()
	if err != nil {
		return err
	}
	a.Ops = ops
	if _, err := p.expect(tEq); err != nil {
		return err
	}
	tree, err := p.parsePermUnion()
	if err != nil {
		return err
	}
	a.Tree = tree
	a.Expr = tree.Leaves()
	o.Admits = append(o.Admits, a)
	return nil
}

func (s *Spec) admissionPredicate(obj *Object, pm *Perm, cust *Subject, virtual map[string]bool) (string, error) {
	pred, err := s.rlsPredicate(obj, pm, cust, virtual)
	if err != nil {
		return "", err
	}
	arms, err := s.admitArms(obj, pm.Maps, cust, virtual)
	if err != nil {
		return "", err
	}
	if len(arms) == 0 {
		return pred, nil
	}
	return "(" + pred + ") OR " + strings.Join(arms, " OR "), nil
}

func (s *Spec) admitArms(obj *Object, op string, cust *Subject, virtual map[string]bool) ([]string, error) {
	var arms []string
	for _, a := range obj.Admits {
		if !contains(a.Ops, op) {
			continue
		}
		arm, err := s.admitArmPredicate(obj, a, op, cust, virtual)
		if err != nil {
			return nil, err
		}
		arms = append(arms, "("+arm+")")
	}
	return arms, nil
}

func (s *Spec) admitArmPredicate(obj *Object, a *Admit, op string, cust *Subject, virtual map[string]bool) (string, error) {
	custClaim := ""
	if cust != nil {
		custClaim = cust.Identifies
	}
	rels := map[string]*Relation{}
	for _, r := range obj.Relations {
		rels[r.Name] = r
	}
	objLeaf := obj.Scoped[len(obj.Scoped)-1]
	_, grantInject := s.rlsSubjectBranches(obj, virtual, objLeaf, virtual[objLeaf], s.objectReferencesStaff(obj), op)
	terms, err := s.nodeFrags(obj, a.perm(op), a.Tree, rels, custClaim)
	if err != nil {
		return "", err
	}
	if len(terms) == 0 {
		return "", fmt.Errorf("object %q admit %s: no emittable term", obj.Name, op)
	}
	block, err := s.rlsContainmentBlock(obj, objLeaf, grantInject, op)
	if err != nil {
		return "", err
	}
	if block == "" {
		return strings.Join(terms, " OR "), nil
	}
	return block + " AND (" + strings.Join(terms, " OR ") + ")", nil
}

func (s *Spec) admissionWithRequire(obj *Object, pm *Perm, cust *Subject, virtual map[string]bool) (string, error) {
	pred, err := s.admissionPredicate(obj, pm, cust, virtual)
	if err != nil {
		return "", err
	}
	req, err := s.permRequireSQL(obj, pm, cust)
	if err != nil {
		return "", err
	}
	if req == "" {
		return pred, nil
	}
	return fmt.Sprintf("(%s) AND (%s)", pred, req), nil
}

func (s *Spec) validateAdmits(o *Object, rels map[string]*Relation) error {
	var errs []error
	mapped := map[string]bool{}
	for _, pm := range o.Perms {
		if contains(pm.Layers, "rls") && !pm.PredicateOnly {
			mapped[pm.Maps] = true
		}
	}
	for _, a := range o.Admits {
		for _, op := range a.Ops {
			switch {
			case opToCmd[op] == "":
				errs = append(errs, fmt.Errorf("line %d: object %q admits unknown operation %q", a.Pos.Line, o.Name, op))
			case !mapped[op]:
				errs = append(errs, fmt.Errorf("line %d: object %q admits %s, but no @rls permission maps %s, so there is no policy to join", a.Pos.Line, o.Name, op, op))
			}
		}
		pm := a.perm("")
		if err := valCheckPermPolarity(o, pm); err != nil {
			errs = append(errs, err)
		}
		if err := valCheckPermTerms(s, o, pm, rels, true, false, false, false); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
