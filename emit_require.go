package demesne

import (
	"fmt"
	"strings"
)

func (s *Spec) externalCallSQL(t *Term) (string, error) {
	ext := s.externalByName(t.ExternalFn)
	if ext == nil {
		return "", fmt.Errorf("@external(%s): no `external predicate %s(...)` declaration — an adopter-supplied predicate must be declared before it can be required", t.ExternalFn, t.ExternalFn)
	}
	if len(ext.ArgTypes) != len(t.ExternalArgs) {
		return "", fmt.Errorf("@external(%s): declared with %d argument(s), called with %d", t.ExternalFn, len(ext.ArgTypes), len(t.ExternalArgs))
	}
	args := make([]string, 0, len(t.ExternalArgs))
	for _, a := range t.ExternalArgs {
		switch {
		case a.Claim != "":
			args = append(args, s.idClaim(a.Claim))
		case a.Lit != "":
			args = append(args, "'"+a.Lit+"'")
		default:
			args = append(args, a.Col)
		}
	}
	return fmt.Sprintf("%s.%s(%s)", s.definerSchema(), ext.Name, strings.Join(args, ", ")), nil
}

func (s *Spec) requireLeafFrags(obj *Object, pm *Perm, n *PermNode, rels map[string]*Relation, custClaim string) ([]string, error) {
	t := n.Term
	switch {
	case t.Builtin == "external":
		frag, err := s.externalCallSQL(t)
		if err != nil {
			return nil, fmt.Errorf("object %q require %q: %w", obj.Name, pm.Verb, err)
		}
		return []string{frag}, nil
	case t.Builtin == "self":
		return []string{fmt.Sprintf("%s = %s", t.SelfCol, s.idClaim(s.adminIdentify()))}, nil
	case t.GrantRef != "", t.Builtin == "scoped", t.Builtin == "public", t.Builtin == "open":
		return nil, fmt.Errorf("object %q require %q: term %s widens — a `require` compiles to a RESTRICTIVE policy and can only narrow; a term that confers reach belongs in the `permission` line",
			obj.Name, pm.Verb, t.String())
	}
	return s.emitTerm(obj, pm, t, rels, custClaim)
}

func (s *Spec) requirePredicate(obj *Object, pm *Perm, rq *Require, cust *Subject) (string, error) {
	custClaim := ""
	if cust != nil {
		custClaim = cust.Identifies
	}
	rels := map[string]*Relation{}
	for _, r := range obj.Relations {
		rels[r.Name] = r
	}
	frags, err := s.nodeFragsMode(obj, pm, rq.Tree, rels, custClaim, true)
	if err != nil {
		return "", err
	}
	if len(frags) == 0 {
		return "", fmt.Errorf("object %q require %q: compiles to no predicate — a RESTRICTIVE policy with an empty predicate denies every write", obj.Name, rq.Verb)
	}
	return strings.Join(frags, " OR "), nil
}

func (s *Spec) permRequireSQL(obj *Object, pm *Perm, cust *Subject) (string, error) {
	rq := obj.requireFor(pm.Verb)
	if rq == nil {
		return "", nil
	}
	return s.requirePredicate(obj, pm, rq, cust)
}

func (s *Spec) permPredicate(obj *Object, pm *Perm, cust *Subject, virtual map[string]bool) (string, error) {
	pred, err := s.rlsPredicate(obj, pm, cust, virtual)
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
