package demesne

import (
	"errors"
	"fmt"
	"strings"
)

type GrantScope struct {
	Level   string
	Column  string
	Missing string
}

type GrantUse struct {
	Grant    string
	Via      string
	Bound    string
	Unscoped bool
	Ops      []string
	Pos      Pos
}

var orderedTableOps = []string{"select", "insert", "update", "delete"}

func (g *Grant) definerBase() string {
	if g.Named != "" {
		return g.Named
	}
	return g.Table
}

func (o *Object) grantUse(grant, op string) *GrantUse {
	for i := range o.ReachUses {
		u := &o.ReachUses[i]
		if u.Grant == grant && (len(u.Ops) == 0 || contains(u.Ops, op)) {
			return u
		}
	}
	return nil
}

func (p *parser) parseOperationList() ([]string, error) {
	var ops []string
	for {
		op, err := p.ident()
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
		if p.peekKind() != tComma {
			return ops, nil
		}
		p.advance()
	}
}

func (p *parser) parseGrantScope(g *Grant) error {
	var scope GrantScope
	var err error
	if scope.Level, err = p.ident(); err != nil {
		return err
	}
	if err = p.expectKw("on"); err != nil {
		return err
	}
	if scope.Column, err = p.ident(); err != nil {
		return err
	}
	if err = p.expectKw("missing"); err != nil {
		return err
	}
	if scope.Missing, err = p.ident(); err != nil {
		return err
	}
	g.Scopes = append(g.Scopes, scope)
	return nil
}

func (p *parser) parseGrantUse(o *Object) error {
	use := GrantUse{Pos: Pos{p.cur().line}}
	p.advance()
	var err error
	if use.Grant, err = p.ident(); err != nil {
		return err
	}
	switch {
	case p.acceptKw("unscoped"):
		use.Unscoped = true
	case p.acceptKw("bound"):
		use.Bound, err = p.ident()
	case p.acceptKw("via"):
		use.Via, err = p.ident()
	default:
		return p.errf("reach %s needs `unscoped`, `bound <level>` or `via <grant>`", use.Grant)
	}
	if err != nil {
		return err
	}
	if p.acceptKw("for") {
		if use.Ops, err = p.parseOperationList(); err != nil {
			return err
		}
	}
	o.ReachUses = append(o.ReachUses, use)
	return nil
}

func (s *Spec) sessionClaim(key string) string {
	setting, cast := "request.jwt.claims", "json"
	if s.Claims != nil {
		setting, cast = s.Claims.Setting, s.Claims.Cast
	}
	return fmt.Sprintf("(NULLIF(current_setting('%s', true), '')::%s ->> '%s')", setting, cast, key) + s.idCast()
}

func (s *Spec) grantSessionScopeConjuncts(g *Grant) []string {
	var out []string
	for _, scope := range g.Scopes {
		claim := s.sessionClaim(s.claimKeyForLevel(scope.Level))
		terms := []string{scope.Column + " IS NULL"}
		if scope.Missing == "allow" {
			terms = append(terms, claim+" IS NULL")
		}
		terms = append(terms, scope.Column+" = "+claim)
		out = append(out, "("+strings.Join(terms, " OR ")+")")
	}
	return out
}

func (s *Spec) grantScopeDefiners(g *Grant, conj []string) []GenFn {
	if len(g.Scopes) == 0 {
		return nil
	}
	base := g.definerBase() + "_reach"
	unscoped := append([]string(nil), conj...)
	for _, scope := range g.Scopes {
		unscoped = append(unscoped, scope.Column+" IS NULL")
	}
	setConj := append([]string{conj[0]}, unscoped[2:]...)
	out := []GenFn{
		{Name: base + "_unscoped", Sig: fmt.Sprintf("user_id %s, check_%s_id %s", s.idType(), g.Level, s.idType()), Body: grantEdgeExists(g.Table, unscoped...)},
		{Name: base + "_unscoped_set", Sig: "user_id " + s.idType(), Returns: "SETOF " + s.idType(), Body: fmt.Sprintf("%s FROM %s WHERE %s", g.LevelCol, g.Table, strings.Join(setConj, " AND "))},
	}
	explicit := append([]string(nil), conj...)
	args := []string{"user_id " + s.idType(), fmt.Sprintf("check_%s_id %s", g.Level, s.idType())}
	for _, scope := range g.Scopes {
		param := "check_" + scope.Level + "_id"
		empty := param + " IS NULL"
		if s.idType() == "text" {
			empty = param + " = ''"
		}
		explicit = append(explicit, fmt.Sprintf("(%s IS NULL OR %s OR %s = %s)", scope.Column, empty, scope.Column, param))
		args = append(args, param+" "+s.idType())
		out = append(out, GenFn{Name: base + "_in_" + scope.Level, Sig: strings.Join(args, ", "), Body: grantEdgeExists(g.Table, explicit...)})
	}
	return out
}

func (s *Spec) grantReachedBySubject(name string) bool {
	for _, sub := range s.Subjects {
		if sub.Reach == "grant" && sub.ReachGrant == name {
			return true
		}
	}
	return false
}

func (s *Spec) grantSelectedAsVia(name string) bool {
	for _, o := range s.Objects {
		for _, u := range o.ReachUses {
			if u.Via == name {
				return true
			}
		}
	}
	return false
}

func (s *Spec) enumeratedGrant(obj *Object, g *Grant) *Grant {
	if g.ClaimKey != "" || !s.levelOnObjectPath(obj, g.Level) {
		return nil
	}
	if !s.grantReachedBySubject(g.Name) && s.grantSelectedAsVia(g.Name) {
		return nil
	}
	if u := obj.grantUse(g.Name, "select"); u != nil && u.Via != "" {
		return s.grantByName(u.Via)
	}
	return g
}

func (s *Spec) validateGrantReach() error {
	var errs []error
	bases := map[string]*Grant{}
	names := map[string]bool{}
	for _, g := range s.Grants {
		if names[g.Name] {
			errs = append(errs, fmt.Errorf("line %d: grant %q is declared twice", g.Pos.Line, g.Name))
		}
		names[g.Name] = true
		if g.ClaimKey != "" {
			errs = append(errs, s.validateClaimGrant(g)...)
			continue
		}
		errs = append(errs, s.validateGrantScopes(g)...)
		if prior := bases[g.definerBase()]; prior != nil && !sameGrantEmission(prior, g) {
			errs = append(errs, fmt.Errorf("line %d: grants %q and %q both emit %s_reach from different edges; give one its own definer name with `named`", g.Pos.Line, prior.Name, g.Name, g.definerBase()))
		} else if prior == nil {
			bases[g.definerBase()] = g
		}
	}
	for _, o := range s.Objects {
		errs = append(errs, s.validateGrantUses(o)...)
	}
	return errors.Join(errs...)
}

func sameGrantEmission(a, b *Grant) bool {
	if a.Table != b.Table || a.GranteeCol != b.GranteeCol || a.LevelCol != b.LevelCol ||
		a.ActiveCol != b.ActiveCol || a.ExpiresCol != b.ExpiresCol || len(a.Scopes) != len(b.Scopes) {
		return false
	}
	for i := range a.Scopes {
		if a.Scopes[i] != b.Scopes[i] {
			return false
		}
	}
	return true
}

func (s *Spec) validateClaimGrant(g *Grant) []error {
	var errs []error
	if s.levelIsVirtual(g.Level) {
		errs = append(errs, fmt.Errorf("line %d: claim grant %q reaches virtual level %q, which has no column to lift", g.Pos.Line, g.Name, g.Level))
	}
	if len(g.Verbs) == 0 {
		errs = append(errs, fmt.Errorf("line %d: claim grant %q must name the operations it confers", g.Pos.Line, g.Name))
	}
	if g.ActiveCol != "" || g.ExpiresCol != "" || g.IDCol != "" || g.GrantedByCol != "" || g.RevokedByCol != "" ||
		g.CreatedAtCol != "" || len(g.ExtraCols) != 0 || g.Named != "" || len(g.Scopes) != 0 {
		errs = append(errs, fmt.Errorf("line %d: claim grant %q has no edge, so it takes no edge options", g.Pos.Line, g.Name))
	}
	return errs
}

func (s *Spec) validateGrantScopes(g *Grant) []error {
	var errs []error
	previous := g.Level
	seenCols := map[string]bool{g.GranteeCol: true, g.LevelCol: true}
	for _, scope := range g.Scopes {
		if !s.levelDescendsFrom(scope.Level, previous) || s.levelIsVirtual(scope.Level) {
			errs = append(errs, fmt.Errorf("line %d: grant %q scope %q must be a non-virtual level below %q", g.Pos.Line, g.Name, scope.Level, previous))
		}
		if scope.Missing != "allow" && scope.Missing != "deny" {
			errs = append(errs, fmt.Errorf("line %d: grant %q scope %q: missing must be allow or deny, got %q", g.Pos.Line, g.Name, scope.Level, scope.Missing))
		}
		if seenCols[scope.Column] {
			errs = append(errs, fmt.Errorf("line %d: grant %q scope %q reuses column %q", g.Pos.Line, g.Name, scope.Level, scope.Column))
		}
		seenCols[scope.Column] = true
		previous = scope.Level
	}
	return errs
}

func (s *Spec) levelDescendsFrom(level, ancestor string) bool {
	if level == ancestor {
		return false
	}
	paths, err := s.Topology.AncestorPaths(level)
	if err != nil {
		return false
	}
	for _, path := range paths {
		for _, l := range path {
			if l.Name == ancestor {
				return true
			}
		}
	}
	return false
}

func (g *Grant) hasScope(level string) bool {
	for _, scope := range g.Scopes {
		if scope.Level == level {
			return true
		}
	}
	return false
}

func (s *Spec) validateGrantUses(o *Object) []error {
	var errs []error
	claimed := map[string]bool{}
	for _, u := range o.ReachUses {
		g := s.grantByName(u.Grant)
		if g == nil || g.ClaimKey != "" {
			errs = append(errs, fmt.Errorf("line %d: object %q selects the reach of %q, which is not an edge grant", u.Pos.Line, o.Name, u.Grant))
			continue
		}
		errs = append(errs, s.validateGrantUseTarget(o, g, u)...)
		ops := u.Ops
		if len(ops) == 0 {
			ops = orderedTableOps
		}
		for _, op := range ops {
			if opToCmd[op] == "" {
				errs = append(errs, fmt.Errorf("line %d: object %q reach %s names unknown operation %q", u.Pos.Line, o.Name, g.Name, op))
				continue
			}
			if len(u.Ops) > 0 && !g.Confers(op) {
				errs = append(errs, fmt.Errorf("line %d: object %q reach %s selects %s, which grant %q does not confer", u.Pos.Line, o.Name, g.Name, op, g.Name))
			}
			if claimed[g.Name+":"+op] {
				errs = append(errs, fmt.Errorf("line %d: object %q selects the reach of %q for %s twice", u.Pos.Line, o.Name, g.Name, op))
			}
			claimed[g.Name+":"+op] = true
		}
	}
	return errs
}

func (s *Spec) validateGrantUseTarget(o *Object, g *Grant, u GrantUse) []error {
	var errs []error
	if !contains(o.Scoped, g.Level) {
		errs = append(errs, fmt.Errorf("line %d: object %q selects the reach of %q at %q, which is outside its scope", u.Pos.Line, o.Name, g.Name, g.Level))
	}
	if !s.grantReachedBySubject(g.Name) {
		errs = append(errs, fmt.Errorf("line %d: object %q selects the reach of %q, which no subject reaches through", u.Pos.Line, o.Name, g.Name))
	}
	switch {
	case u.Via != "":
		errs = append(errs, s.validateGrantUseVia(o, g, u)...)
	case len(g.Scopes) == 0:
		errs = append(errs, fmt.Errorf("line %d: object %q reach %s: unscoped and bound need a grant with scope levels", u.Pos.Line, o.Name, g.Name))
	case u.Bound != "" && !g.hasScope(u.Bound):
		errs = append(errs, fmt.Errorf("line %d: object %q reach %s bound %s: the level must be one of the grant's scopes", u.Pos.Line, o.Name, g.Name, u.Bound))
	}
	return errs
}

func (s *Spec) validateGrantUseVia(o *Object, g *Grant, u GrantUse) []error {
	via := s.grantByName(u.Via)
	if via == nil || via.ClaimKey != "" || via == g || via.Level != g.Level {
		return []error{fmt.Errorf("line %d: object %q reach %s via %s: the replacement must be another edge grant at %q", u.Pos.Line, o.Name, g.Name, u.Via, g.Level)}
	}
	ops := u.Ops
	if len(ops) == 0 {
		ops = orderedTableOps
	}
	var errs []error
	for _, op := range ops {
		if g.Confers(op) && !via.Confers(op) {
			errs = append(errs, fmt.Errorf("line %d: object %q reach %s via %s: %q does not confer %s", u.Pos.Line, o.Name, g.Name, u.Via, u.Via, op))
		}
	}
	return errs
}

func (s *Spec) validateBorrowOperation(r *Relation, vo ViaObject) []error {
	if vo.Op == "" {
		return nil
	}
	if opToCmd[vo.Op] == "" {
		return []error{fmt.Errorf("line %d: relation %q borrows for unknown operation %q", r.Pos.Line, r.Name, vo.Op)}
	}
	other := s.objectByName(vo.Object)
	if other == nil {
		return nil
	}
	for _, pm := range other.Perms {
		if pm.Verb == vo.Verb && !pm.PredicateOnly {
			return []error{fmt.Errorf("line %d: relation %q borrows %s->%s for %s, but that permission already maps %s; `for` selects the operation of a predicate-only permission", r.Pos.Line, r.Name, vo.Object, vo.Verb, vo.Op, pm.Maps)}
		}
	}
	return nil
}
