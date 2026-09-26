package demesne

import (
	"fmt"
	"sort"
	"strings"
)

type Policy struct {
	Object string
	Table  string
	Name   string
	Cmd    string
	Using  string
	Check  string

	Restrictive bool
}

type RLSResult struct {
	Policies    []Policy
	Unsupported []string

	TableSchema string
}

func (r *RLSResult) tableSchema() string {
	if r.TableSchema != "" {
		return r.TableSchema
	}
	return "public"
}

func (s *Spec) claim(key string) string {
	setting, cast := "request.jwt.claims", "json"
	if s.Claims != nil {
		setting, cast = s.Claims.Setting, s.Claims.Cast
	}
	return fmt.Sprintf("(current_setting('%s', true)::%s ->> '%s')", setting, cast, key)
}

func (s *Spec) idClaim(key string) string {
	return s.claim(key) + s.idCast()
}

func accessFor(op string) string {
	switch op {
	case "select":
		return "read"
	case "delete":
		return "delete"
	default:
		return "write"
	}
}

var opToCmd = map[string]string{
	"select": "SELECT", "insert": "INSERT", "update": "UPDATE", "delete": "DELETE",
}

func (s *Spec) EmitRLS() (*RLSResult, error) {
	chain, err := s.Topology.Chain()
	if err != nil {
		return nil, err
	}
	virtual := map[string]bool{}
	for _, l := range chain {
		if l.Virtual {
			virtual[l.Name] = true
		}
	}

	res := &RLSResult{TableSchema: s.tableSchema()}
	for _, obj := range s.Objects {
		objLeaf := obj.Scoped[len(obj.Scoped)-1]
		custSubj := s.ownerSubject(objLeaf)
		for _, pm := range obj.Perms {
			if !contains(pm.Layers, "rls") {
				continue
			}
			if pm.PredicateOnly {
				continue
			}
			pred, err := s.admissionPredicate(obj, pm, custSubj, virtual)
			if err != nil {
				res.Unsupported = append(res.Unsupported, fmt.Sprintf("%s.%s: %v", obj.Name, pm.Verb, err))
				continue
			}
			op := pm.Maps
			if opToCmd[op] == "" {
				res.Unsupported = append(res.Unsupported, fmt.Sprintf("%s.%s: @rls permission has no table-op maps", obj.Name, pm.Verb))
				continue
			}
			res.Policies = append(res.Policies, opPolicy(obj, op, obj.Table+"_"+op, pred, false))

			req, err := s.permRequireSQL(obj, pm, custSubj)
			if err != nil {
				res.Unsupported = append(res.Unsupported, fmt.Sprintf("%s.%s: %v", obj.Name, pm.Verb, err))
				continue
			}
			if req != "" {
				res.Policies = append(res.Policies, opPolicy(obj, op, obj.Table+"_"+op+"_require", req, true))
			}
		}
	}
	return res, nil
}

func opPolicy(obj *Object, op, name, pred string, restrictive bool) Policy {
	pol := Policy{Object: obj.Name, Table: obj.Table, Name: name, Cmd: opToCmd[op], Restrictive: restrictive}
	switch op {
	case "select", "delete":
		pol.Using = pred
	case "insert":
		pol.Check = pred
	case "update":
		pol.Using = pred
		pol.Check = pred
	}
	return pol
}

func (s *Spec) editPointCheckSQL(o *Object) (string, error) {
	var upd *Perm
	for _, pm := range o.Perms {
		if contains(pm.Layers, "rls") && pm.Maps == "update" {
			upd = pm
			break
		}
	}
	if upd == nil {
		return "", nil
	}
	return s.permPointCheckSQL(o, upd)
}

// permPointCheckSQL compiles a permission's predicate into a boolean point-check
// evaluated under the caller's own claims:
//
//	SELECT EXISTS (SELECT 1 FROM <table> WHERE <pk> = $1 AND (<predicate>))
//
// It backs both CanEdit (the @rls UPDATE predicate) and @check accessors.
func (s *Spec) permPointCheckSQL(o *Object, pm *Perm) (string, error) {
	chain, err := s.Topology.Chain()
	if err != nil {
		return "", err
	}
	virtual := map[string]bool{}
	for _, l := range chain {
		if l.Virtual {
			virtual[l.Name] = true
		}
	}
	cust := s.ownerSubject(o.Scoped[len(o.Scoped)-1])
	pred, err := s.admissionWithRequire(o, pm, cust, virtual)
	if err != nil {
		return "", err
	}
	if pred == "" {
		return "", nil
	}
	return fmt.Sprintf("SELECT EXISTS (SELECT 1 FROM %s WHERE %s = $1 AND (%s))", o.Table, o.pk(), pred), nil
}

func (s *Spec) ownerSubject(leafLevel string) *Subject {
	for _, sub := range s.Subjects {
		if sub.Binds == "owner" && sub.Anchor == leafLevel {
			return sub
		}
	}
	return nil
}

func (s *Spec) adminIdentify() string {
	for _, sub := range s.Subjects {
		if sub.Binds == "admin" {
			return sub.Identifies
		}
	}
	return "sub"
}

func (s *Spec) adminName() string {
	for _, sub := range s.Subjects {
		if sub.Binds == "admin" {
			return sub.Name
		}
	}
	return "admin"
}

func (s *Spec) scopeCol(obj *Object, lvl string) string {
	if obj.IsLevelEntity() && lvl == obj.Level {
		return obj.pk()
	}
	if l := s.Topology.LevelByName(lvl); l != nil {
		return l.scopeColumn()
	}
	return lvl + "_id"
}

func (s *Spec) claimKeyForLevel(level string) string {
	if l := s.Topology.LevelByName(level); l != nil {
		return l.claimKey()
	}
	return level + "_id"
}

func reqClaim(custClaim string, obj *Object, what string) error {
	if custClaim == "" {
		return fmt.Errorf("object %q: %s references the owner axis, but no owner subject (a subject `binds owner` at level %q) resolves a claim — refusing to emit an empty-claim predicate",
			obj.Name, what, obj.Scoped[len(obj.Scoped)-1])
	}
	return nil
}

func guardSQL(g *Guard) string {
	if g.Op == "<>" {
		return fmt.Sprintf("(%s IS NULL OR %s <> '%s')", g.Col, g.Col, g.Val)
	}
	return fmt.Sprintf("%s = '%s'", g.Col, g.Val)
}

func (s *Spec) rlsPredicate(obj *Object, pm *Perm, cust *Subject, virtual map[string]bool) (string, error) {
	custClaim := ""
	if cust != nil {
		custClaim = cust.Identifies
	}
	rels := map[string]*Relation{}
	for _, r := range obj.Relations {
		rels[r.Name] = r
	}
	objLeaf := obj.Scoped[len(obj.Scoped)-1]

	objIsGlobal := virtual[objLeaf]
	objHasStaffTerm := s.objectReferencesStaff(obj)

	top, grantInject := s.rlsSubjectBranches(obj, virtual, objLeaf, objIsGlobal, objHasStaffTerm, pm.Maps)

	top, scopedGrant, err := s.rlsExprTopBranches(obj, pm, top, grantInject)
	if err != nil {
		return "", err
	}

	blockTerms, err := s.nodeFrags(obj, pm, pm.Tree, rels, custClaim)
	if err != nil {
		return "", err
	}

	block, err := s.rlsContainmentBlock(obj, objLeaf, grantInject, pm.Maps)
	if err != nil {
		return "", err
	}
	if len(blockTerms) > 0 {
		if block != "" {
			block += " AND (" + strings.Join(blockTerms, " OR ") + ")"
		} else {
			block = strings.Join(blockTerms, " OR ")
		}
	}

	containmentBearing := scopedGrant || len(blockTerms) > 0
	if len(top) == 0 && !containmentBearing {
		return "", fmt.Errorf("no emittable grant terms")
	}

	branches := top
	if block != "" && containmentBearing {
		branches = append(branches, "("+block+")")
	}
	if len(branches) == 0 {
		return "", fmt.Errorf("object %q permission %q: no emittable grant — a global object needs a platform-role subject", obj.Name, pm.Verb)
	}
	pred := strings.Join(branches, " OR ")
	if pm.SelfCheck != "" {
		guard := fmt.Sprintf("(%s IS NULL OR %s = %s)", pm.SelfCheck, pm.SelfCheck, s.idClaim(s.adminIdentify()))
		pred = fmt.Sprintf("%s AND (%s)", guard, pred)
	}
	return pred, nil
}

func (s *Spec) rlsSubjectBranches(obj *Object, virtual map[string]bool, objLeaf string, objIsGlobal, objHasStaffTerm bool, op string) ([]string, map[string][]string) {
	var top []string
	grantInject := map[string][]string{}
	for _, sub := range s.Subjects {
		switch {
		case sub.Membership != nil && virtual[sub.Anchor]:

			fn := fmt.Sprintf("%s.%s(%s)", s.definerSchema(), membershipFn(sub.Membership), s.idClaim(sub.Identifies))
			if obj.IsLevelEntity() || objIsGlobal {
				top = append(top, fn)
			} else {
				top = append(top, fmt.Sprintf("(%s AND %s IS NULL)", fn, s.claim(s.claimKeyForLevel(objLeaf))))
			}
		case s.isPlatformRoleSubject(sub) && (objHasStaffTerm || (objIsGlobal && sub.Anchor == objLeaf)):

			top = append(top, fmt.Sprintf("%s.%s(%s)", s.definerSchema(), platformRoleFn(sub.Anchor), s.idClaim(sub.Identifies)))
		case sub.Reach == "grant":

			top, grantInject = s.rlsApplyGrantReach(obj, sub, objLeaf, objIsGlobal, top, grantInject, op)
		}
	}
	s.rlsApplyClaimReach(obj, objIsGlobal, grantInject, op)
	return top, grantInject
}

func (s *Spec) rlsApplyClaimReach(obj *Object, objIsGlobal bool, grantInject map[string][]string, op string) {
	if objIsGlobal {
		return
	}
	for _, g := range s.Grants {
		if g.ClaimKey == "" || !g.Confers(op) || !contains(obj.Scoped, g.Level) {
			continue
		}
		grantInject[g.Level] = append(grantInject[g.Level], s.claimReachPredicate(g))
	}
}

func (s *Spec) rlsApplyGrantReach(obj *Object, sub *Subject, objLeaf string, objIsGlobal bool, top []string, grantInject map[string][]string, op string) ([]string, map[string][]string) {
	g := s.grantByName(sub.ReachGrant)
	if g == nil || !contains(obj.Scoped, g.Level) {
		return top, grantInject
	}
	// A grant that does not confer this op contributes no branch to it, which is
	// how a reach can carry read without carrying update or delete.
	if !g.Confers(op) {
		return top, grantInject
	}
	if g.Table == obj.Table {
		return top, grantInject
	}
	reach, ok := s.grantReachPredicate(obj, g, sub.Identifies, op)
	if !ok {
		return top, grantInject
	}
	if s.grantReachIsContained(obj, sub, g, objLeaf, objIsGlobal) {
		grantInject[g.Level] = append(grantInject[g.Level], reach)
	} else {
		top = append(top, reach)
	}
	return top, grantInject
}

// grantReachIsContained decides whether a grant's reach joins the CONTAINMENT
// conjunct or the TOP-LEVEL branch list, and the difference is load-bearing on
// INSERT. A top-level branch stands alone: satisfying it satisfies the policy,
// and the enclosing scope conjuncts contribute nothing. A term spliced into
// containment has to satisfy them too.
//
// A grant ABOVE the object's leaf is contained. It reaches down through levels
// the object still carries, so those conjuncts stay meaningful underneath it.
//
// A grant AT the object's leaf is the case that decides where a level's own
// grant lands, and the answer turns on where the REACHING SUBJECT sits rather
// than on the grant alone:
//
//   - A subject anchored OUTSIDE the level it reaches into is an authority
//     arriving from above, and its reach is its whole warrant: the reach
//     function carries the bound itself. Containing it would ask the row to
//     justify a decision that was never about the row's position.
//
//   - A subject anchored AT the grant's own level sits inside the topology, and
//     its grant names a peer rather than conferring authority over the tree. Its
//     reach has to be conjoined with the levels above it, or a grant at that
//     level authorises a row in a sibling branch outright.
//
// The second arm is why this is not simply `g.Level != objLeaf`. Dropping that
// test reroutes the first arm too, converting a top-level branch into a
// conjunct on every object whose leaf is the grant's level, which narrows an
// authority meant to arrive from above.
func (s *Spec) grantReachIsContained(obj *Object, sub *Subject, g *Grant, objLeaf string, objIsGlobal bool) bool {
	if obj.IsLevelEntity() || objIsGlobal {
		return false
	}
	if g.Level != objLeaf {
		return true
	}
	return sub.Anchor == g.Level
}

func (s *Spec) rlsExprTopBranches(obj *Object, pm *Perm, top []string, grantInject map[string][]string) ([]string, bool, error) {

	scopedGrant := false
	for _, t := range pm.Expr {
		if t.Builtin == "scoped" {
			scopedGrant = true
		}
	}
	for _, t := range pm.Expr {
		if t.GrantRef == "" {
			continue
		}
		if g := s.grantByName(t.GrantRef); g != nil && !g.Confers(pm.Maps) {
			continue
		}
		reach, err := s.grantRefReach(obj, t.GrantRef, pm.Maps)
		if err != nil {
			return nil, false, err
		}
		if reach == "" {
			continue
		}
		// A grant may be named twice over: once by a subject that reaches
		// through it, and again by a `via grant` term in the permission
		// expression. Both resolve to the same reach call, but the first may
		// already have been spliced into containment, and this list is only
		// deduped against itself. Adding it here anyway emits the reach twice
		// and the second copy is a TOP-LEVEL disjunct, which stands alone and
		// undoes the containment the first copy was placed under.
		if grantReachIsInjected(grantInject, reach) {
			continue
		}
		if !contains(top, reach) {
			top = append(top, reach)
		}
	}
	for _, t := range pm.Expr {
		if t.Builtin == "public" && !contains(top, "true") {
			top = append(top, "true")
		}
	}
	for _, t := range pm.Expr {
		if t.Builtin != "self" {
			continue
		}
		frag := fmt.Sprintf("%s = %s", t.SelfCol, s.idClaim(s.adminIdentify()))
		if !contains(top, frag) {
			top = append(top, frag)
		}
	}
	return top, scopedGrant, nil
}

// grantReachIsInjected reports whether a reach has already been placed in the
// containment conjunct at some level, so a second reference to the same grant
// does not also emit it at the top level where it would stand alone.
func grantReachIsInjected(grantInject map[string][]string, reach string) bool {
	for _, reaches := range grantInject {
		if contains(reaches, reach) {
			return true
		}
	}
	return false
}

func (s *Spec) rlsContainmentBlock(obj *Object, objLeaf string, grantInject map[string][]string, op string) (string, error) {
	paths, err := s.Topology.AncestorPaths(objLeaf)
	if err != nil {
		return "", err
	}
	var pathPreds []string
	for _, path := range paths {
		var cols []string
		for _, lvl := range path {
			if lvl.Virtual || (obj.IsLevelEntity() && lvl.Name == obj.Level) {
				continue
			}
			col := s.scopeCol(obj, lvl.Name)
			colPred := fmt.Sprintf("%s = %s", col, s.idClaim(lvl.claimKey()))
			// A wildcard makes two admissions, and only one of them is bounded.
			//
			// A caller carrying NO claim at this level was never confined by it,
			// so a row belonging to no instance stays in scope for them on every
			// op. That admission is unconditional: withdrawing it would confine
			// a caller by a level they do not stand in, hiding rows that are
			// nobody's from everybody.
			//
			// A caller standing IN an instance is the bounded one. Letting them
			// reach a row that belongs to no instance is the point of a shared
			// tier on a read, and on a write it is a caller reaching outside the
			// instance that confines them.
			//
			// So a bounded wildcard keeps the first admission and drops the
			// second on the ops it does not name. IS NOT DISTINCT FROM is
			// exactly that pair: true when both are absent, true when they
			// match, false when the caller stands somewhere and the row does
			// not. It is a strict narrowing of the unbounded form, differing
			// only in the cell where a claim-carrying caller met a NULL row.
			switch {
			case obj.scopeIsWildcardFor(lvl.Name, op):
				colPred = fmt.Sprintf("(%s IS NULL OR %s)", col, colPred)
			case obj.scopeIsWildcard(lvl.Name):
				colPred = fmt.Sprintf("%s IS NOT DISTINCT FROM %s", col, s.idClaim(lvl.claimKey()))
			}
			if reaches := grantInject[lvl.Name]; len(reaches) > 0 {

				colPred = "(" + colPred + " OR " + strings.Join(reaches, " OR ") + ")"
			}
			cols = append(cols, colPred)
		}
		pathPreds = append(pathPreds, strings.Join(cols, " AND "))
	}
	if len(pathPreds) == 1 {
		return pathPreds[0], nil
	}
	for i := range pathPreds {
		pathPreds[i] = "(" + pathPreds[i] + ")"
	}
	return strings.Join(pathPreds, " OR "), nil
}

func (s *Spec) grantRefReach(obj *Object, grantName, op string) (string, error) {
	g := s.grantByName(grantName)
	if g == nil {
		return "", fmt.Errorf("object %q: permission references unknown grant %q (via grant)", obj.Name, grantName)
	}
	if !contains(obj.Scoped, g.Level) {
		return "", fmt.Errorf("object %q: `via grant %s` confers reach at level %q, not in the object's scope %v", obj.Name, grantName, g.Level, obj.Scoped)
	}
	claim := ""
	for _, sub := range s.Subjects {
		if sub.Reach == "grant" && sub.ReachGrant == grantName {
			claim = sub.Identifies
			break
		}
	}
	if claim == "" {
		return "", fmt.Errorf("object %q: grant %q has no reaching subject (a `subject … reach via grant %s`) to supply a claim", obj.Name, grantName, grantName)
	}
	reach, _ := s.grantReachPredicate(obj, g, claim, op)
	return reach, nil
}

// grantReachPredicate is the reach as an RLS predicate.
//
// `<col> IN (SELECT … FROM <grant>_reach_set(<claim>))` rather than a scalar
// `<grant>_reach(<claim>, <col>)`, and the difference is the plan and not the
// meaning. The two are equivalent —
//
//	EXISTS (SELECT 1 FROM T WHERE grantee = $1 AND level = row)
//	  ≡  row IN (SELECT level FROM T WHERE grantee = $1)
//
// — but a SECURITY DEFINER carrying a SET clause cannot be inlined, so the
// scalar form is re-entered once per candidate row while the set form resolves
// once as a hashed subplan. A predicate is evaluated on every row a sort or an
// aggregate has to consider, and LIMIT cannot short-circuit that, so the scalar
// cost is linear in the table rather than in the grant.
//
// The scalar definer is still emitted and is still what another definer's body
// calls, where the value is a parameter and the call happens once.
func (s *Spec) grantReachPredicate(obj *Object, g *Grant, claim, op string) (string, bool) {
	col := s.scopeCol(obj, g.Level)
	member := func(fn string) string {
		return fmt.Sprintf("%s IN (SELECT %s.%s(%s))", col, s.definerSchema(), fn, s.idClaim(claim))
	}
	use := obj.grantUse(g.Name, op)
	switch {
	case use == nil:
		return member(g.definerBase() + "_reach_set"), true
	case use.Via != "":
		via := s.grantByName(use.Via)
		if via == nil || !via.Confers(op) {
			return "", false
		}
		return member(via.definerBase() + "_reach_set"), true
	case use.Unscoped:
		return member(g.definerBase() + "_reach_unscoped_set"), true
	}
	return fmt.Sprintf("(%s OR (%s AND %s = %s))",
		member(g.definerBase()+"_reach_unscoped_set"), member(g.definerBase()+"_reach_set"),
		s.scopeCol(obj, use.Bound), s.idClaim(s.claimKeyForLevel(use.Bound))), true
}

func (s *Spec) claimReachPredicate(g *Grant) string {
	return fmt.Sprintf("%s = '%s'", s.claim(g.ClaimKey), strings.ReplaceAll(g.ClaimValue, "'", "''"))
}

func (s *Spec) objectVerbPredicate(obj *Object, verb string, virtual map[string]bool) (string, error) {
	return s.objectVerbPredicateFor(obj, verb, "", virtual)
}

func (s *Spec) objectVerbPredicateFor(obj *Object, verb, op string, virtual map[string]bool) (string, error) {
	for _, pm := range obj.Perms {
		if pm.Verb == verb && contains(pm.Layers, "rls") {
			if op != "" {
				borrowed := *pm
				borrowed.Maps = op
				pm = &borrowed
			}
			cust := s.ownerSubject(obj.Scoped[len(obj.Scoped)-1])
			return s.permPredicate(obj, pm, cust, virtual)
		}
	}
	return "", fmt.Errorf("object %q has no @rls permission %q for a cross-object reference", obj.Name, verb)
}

func (s *Spec) argSrcSQL(a ArgSrc) string {
	if a.Claim != "" {
		return s.idClaim(a.Claim)
	}
	return a.Col
}

func (s *Spec) relationClaim(r *Relation, fallback string) string {
	if r != nil && len(r.Types) > 0 {
		if sub := s.subjectByName(r.Types[0]); sub != nil && sub.Identifies != "" {
			return sub.Identifies
		}
	}
	return fallback
}

func (s *Spec) modePlaneScope(scope, custClaim string) string {
	if sub := s.subjectByName(scope); sub != nil && sub.Identifies == custClaim {
		return s.claim(custClaim) + " IS NOT NULL"
	}
	return s.claim(custClaim) + " IS NULL"
}

func (s *Spec) objectReferencesStaff(obj *Object) bool {
	for _, r := range obj.Relations {
		if _, ok := r.Repr.(ViaRole); !ok {
			continue
		}
		if len(r.Types) > 0 {
			if st := s.subjectByName(r.Types[0]); st != nil && s.isPlatformRoleSubject(st) {
				return true
			}
		}
	}
	return false
}

func (s *Spec) guardable(t *Term, rels map[string]*Relation) bool {
	if t.Builtin == "session" {
		return true
	}
	if t.WalkVerb != "" {
		return false
	}
	if r := rels[t.Ident]; r != nil {
		switch r.Repr.(type) {
		case ViaRole:

			if len(r.Types) > 0 {
				if st := s.subjectByName(r.Types[0]); st != nil && s.isPlatformRoleSubject(st) {
					return false
				}
			}
			return true
		case ViaMemberIn:

			return true
		}
	}
	return false
}

func (s *Spec) rlsLeafFrags(obj *Object, pm *Perm, n *PermNode, rels map[string]*Relation, custClaim string) ([]string, error) {
	if n.Term.Builtin == "scoped" {
		return nil, nil
	}
	if n.Term.GrantRef != "" || n.Term.Builtin == "public" || n.Term.Builtin == "self" {
		return nil, nil
	}
	frags, err := s.emitTerm(obj, pm, n.Term, rels, custClaim)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range frags {
		if pm.Guard != nil && s.guardable(n.Term, rels) {
			f = fmt.Sprintf("(%s AND %s)", f, guardSQL(pm.Guard))
		}
		out = append(out, f)
	}
	return out, nil
}

func (s *Spec) nodeFrags(obj *Object, pm *Perm, n *PermNode, rels map[string]*Relation, custClaim string) ([]string, error) {
	return s.nodeFragsMode(obj, pm, n, rels, custClaim, false)
}

func (s *Spec) nodeFragsMode(obj *Object, pm *Perm, n *PermNode, rels map[string]*Relation, custClaim string, require bool) ([]string, error) {
	if n == nil {
		return nil, nil
	}
	switch n.Op {
	case "leaf":
		if require {
			return s.requireLeafFrags(obj, pm, n, rels, custClaim)
		}
		return s.rlsLeafFrags(obj, pm, n, rels, custClaim)
	case "or":
		var out []string
		for _, k := range n.Kids {
			kf, err := s.nodeFragsMode(obj, pm, k, rels, custClaim, require)
			if err != nil {
				return nil, err
			}
			out = append(out, kf...)
		}
		return out, nil
	case "and":
		var parts []string
		for _, k := range n.Kids {
			kf, err := s.nodeFragsMode(obj, pm, k, rels, custClaim, require)
			if err != nil {
				return nil, err
			}
			if len(kf) == 0 {
				continue
			}
			parts = append(parts, "("+strings.Join(kf, " OR ")+")")
		}
		if len(parts) == 0 {
			return nil, nil
		}
		return []string{strings.Join(parts, " AND ")}, nil
	case "not":
		kf, err := s.nodeFragsMode(obj, pm, n.Kids[0], rels, custClaim, require)
		if err != nil {
			return nil, err
		}
		if len(kf) == 0 {
			return nil, nil
		}

		return []string{fmt.Sprintf("(%s) IS NOT TRUE", strings.Join(kf, " OR "))}, nil
	}
	return nil, fmt.Errorf("unknown permission node op %q", n.Op)
}

func (s *Spec) emitTerm(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, custClaim string) ([]string, error) {
	if t.ModeCol != "" {
		return s.rlsEmitMode(t, custClaim), nil
	}
	if t.WalkVerb != "" {
		return s.rlsEmitWalk(obj, t, rels)
	}

	if relName, access, ok := grantSelector(t.Ident, rels); ok {
		r := rels[relName]
		vg := r.Repr.(ViaGrant)
		return s.emitGrantFrags(obj, r, &vg, access, custClaim)
	}
	if frags, handled, err := s.rlsEmitBuiltin(obj, pm, t, rels, custClaim); handled {
		return frags, err
	}
	return s.rlsEmitRelation(obj, pm, t, rels, custClaim)
}

func (s *Spec) rlsEmitMode(t *Term, custClaim string) []string {
	frag := fmt.Sprintf("%s = '%s'", t.ModeCol, t.ModeVal)
	if t.ModeScope != "" {
		frag = fmt.Sprintf("%s AND %s", frag, s.modePlaneScope(t.ModeScope, custClaim))
	}
	return []string{frag}
}

func (s *Spec) rlsEmitWalk(obj *Object, t *Term, rels map[string]*Relation) ([]string, error) {
	parent := rels[t.Ident]
	if parent == nil {
		return nil, fmt.Errorf("role-walk references unknown relation %q", t.Ident)
	}
	col, ok := parent.Repr.(ViaColumn)
	if !ok {
		return nil, fmt.Errorf("role-walk parent %q must be a column relation", t.Ident)
	}
	level := parent.Types[0]
	path, err := s.Topology.AncestorPath(level)
	if err != nil {
		return nil, fmt.Errorf("role-walk %q->%s: %w", t.Ident, t.WalkVerb, err)
	}
	var nonVirtual []*Level
	for _, lvl := range path {
		if lvl.Virtual {
			continue
		}
		nonVirtual = append(nonVirtual, lvl)
	}
	args := []string{s.idClaim(s.adminIdentify())}
	for i, lvl := range nonVirtual {
		if i == len(nonVirtual)-1 {
			args = append(args, col.Column)
		} else {
			args = append(args, s.scopeCol(obj, lvl.Name))
		}
	}
	return []string{fmt.Sprintf("%s.is_%s_%s(%s)", s.definerSchema(), level, s.adminName(), strings.Join(args, ", "))}, nil
}

func (s *Spec) memberinReachFrag(level string, member bool) (string, error) {
	if member {
		name := fmt.Sprintf("%s_memberin_%s", s.adminName(), level)
		return fmt.Sprintf("%s.%s(%s, %s)", s.definerSchema(), name, s.idClaim(s.adminIdentify()), s.idClaim(s.claimKeyForLevel(level))), nil
	}
	path, err := s.Topology.AncestorPath(level)
	if err != nil {
		return "", fmt.Errorf("memberin %s reachedby: %w", level, err)
	}
	args := []string{s.idClaim(s.adminIdentify())}
	for _, lvl := range path {
		if lvl.Virtual {
			continue
		}
		args = append(args, s.idClaim(s.claimKeyForLevel(lvl.Name)))
	}
	return fmt.Sprintf("%s.is_%s_%s(%s)", s.definerSchema(), level, s.adminName(), strings.Join(args, ", ")), nil
}

func (s *Spec) rlsEmitBuiltin(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, custClaim string) ([]string, bool, error) {
	switch {
	case t.Builtin == "open":

		return []string{"true"}, true, nil
	case t.Builtin == "app_scope":
		frags, err := s.rlsEmitAppScope(obj, t, rels, custClaim)
		return frags, true, err
	case t.Builtin == "store_manage":
		frags, err := s.rlsEmitStoreManage(obj, t)
		return frags, true, err
	case t.Builtin == "session":
		frags, err := s.rlsEmitSession(obj, pm, t, rels, custClaim)
		return frags, true, err
	case t.Builtin == "kind":

		return []string{fmt.Sprintf("%s = '%s'", s.claim("kind"), t.KindVal)}, true, nil
	case t.Builtin == "claim":

		return []string{fmt.Sprintf("%s = '%s'", s.claim(t.ClaimKey), t.ClaimVal)}, true, nil
	case t.Builtin == "within":
		col := s.scopeCol(obj, t.WithinLevel)
		claim := s.idClaim(s.claimKeyForLevel(t.WithinLevel))
		if t.WithinNullable {
			return []string{fmt.Sprintf("(%s IS NULL OR %s = %s)", col, col, claim)}, true, nil
		}
		return []string{fmt.Sprintf("%s = %s", col, claim)}, true, nil
	case t.Builtin == "holds":
		frags, err := s.rlsEmitHolds(obj, t)
		return frags, true, err
	case t.Builtin != "":
		return nil, true, fmt.Errorf("builtin @%s is not emittable in RLS", t.Builtin)
	case isPermKeyLit(t.Ident):
		return nil, true, fmt.Errorf("capability term %q belongs to the PDP, not RLS", t.Ident)
	}
	return nil, false, nil
}

func (s *Spec) rlsEmitHolds(obj *Object, t *Term) ([]string, error) {
	rs, err := s.holdsRoleStore(t.HoldsPerm)
	if err != nil {
		return nil, fmt.Errorf("@holds(%q) on %q: %w", t.HoldsPerm, obj.Name, err)
	}
	if rs.PermsCol == "" {
		return nil, fmt.Errorf("@holds(%q) on %q: rolestore %q declares no `permissions` column", t.HoldsPerm, obj.Name, rs.Name)
	}
	chain, err := s.Topology.Chain()
	if err != nil {
		return nil, err
	}
	planeDepth := s.rolestorePlaneDepth(rs)
	args := []string{s.idClaim(s.adminIdentify())}
	i := 0
	for _, l := range chain {
		if l.Virtual {
			continue
		}
		if i >= len(rs.ScopeCols) || i >= planeDepth {
			break
		}
		if contains(obj.Scoped, l.Name) {
			args = append(args, s.scopeCol(obj, l.Name))
		} else {
			args = append(args, "NULL")
		}
		i++
	}
	args = append(args, "'"+t.HoldsPerm+"'")
	return []string{fmt.Sprintf("%s.%s(%s)", s.definerSchema(), s.holdsPermFn(rs), strings.Join(args, ", "))}, nil
}

func (s *Spec) rlsEmitAppScope(obj *Object, t *Term, rels map[string]*Relation, custClaim string) ([]string, error) {
	if err := reqClaim(custClaim, obj, "@app_scope"); err != nil {
		return nil, err
	}
	base := s.claim(custClaim) + " IS NULL"
	// Each exclusion is ANDed on: the plane admits a subject-less caller, minus
	// every plane whose owner relation is named here. Order follows the spec so
	// the emission is stable and a diff reads as the spec reads.
	for _, ex := range t.ExcludeRels {
		r := rels[ex]
		if r == nil {
			return nil, fmt.Errorf("@app_scope(exclude %q): unknown relation", ex)
		}
		vc, ok := r.Repr.(ViaColumn)
		if !ok {
			return nil, fmt.Errorf("@app_scope(exclude %q): excluded relation must be an owner column", ex)
		}
		if vc.DiscrimCol != "" {
			base = fmt.Sprintf("(%s AND %s IS DISTINCT FROM '%s')", base, vc.DiscrimCol, vc.DiscrimVal)
		} else {
			base = fmt.Sprintf("(%s AND %s IS NULL)", base, vc.Column)
		}
	}
	return []string{base}, nil
}

func (s *Spec) rlsEmitStoreManage(obj *Object, t *Term) ([]string, error) {
	descs := s.storeDescriptors(obj.Table)
	if len(descs) == 0 {
		return nil, fmt.Errorf("@store_manage on %q: no object uses table %q as a grant store", obj.Name, obj.Table)
	}
	g := objectGrantEdge(descs[0])
	if g.DiscrimCol == "" {
		return nil, fmt.Errorf("@store_manage on %q: store %q is not discriminated (a single-kind store uses `via object <kind>->edit`)", obj.Name, obj.Table)
	}
	return []string{fmt.Sprintf("%s.%s(%s, %s)", s.definerSchema(), storeManageName(obj.Table), g.DiscrimCol, g.RecordCol)}, nil
}

func (s *Spec) rlsEmitSession(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, custClaim string) ([]string, error) {
	leaf := obj.Scoped[len(obj.Scoped)-1]
	self := fmt.Sprintf("%s = %s", s.scopeCol(obj, leaf), s.idClaim(s.claimKeyForLevel(leaf)))
	if t.SessionRel == "" {
		return []string{self}, nil
	}
	roleFrag, err := s.emitTerm(obj, pm, &Term{Ident: t.SessionRel}, rels, custClaim)
	if err != nil {
		return nil, err
	}
	return []string{fmt.Sprintf("%s AND %s", self, roleFrag[0])}, nil
}

func (s *Spec) rlsEmitRelation(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, custClaim string) ([]string, error) {
	r := rels[t.Ident]
	if r == nil {
		return nil, fmt.Errorf("unknown relation %q", t.Ident)
	}
	access := accessFor(pm.Maps)
	pk := obj.Table + "." + obj.pk()
	switch repr := r.Repr.(type) {
	case ViaColumn:

		claimKey := s.relationClaim(r, custClaim)
		if err := reqClaim(claimKey, obj, "owner relation "+t.Ident); err != nil {
			return nil, err
		}
		base := fmt.Sprintf("%s = %s", repr.Column, s.idClaim(claimKey))

		if repr.DiscrimCol != "" {
			base = fmt.Sprintf("(%s AND %s = '%s')", base, repr.DiscrimCol, repr.DiscrimVal)
		}
		return []string{base}, nil
	case ViaEdge:

		if err := reqClaim(custClaim, obj, "edge relation "+t.Ident); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("%s.%s(%s, %s, '%s')", s.definerSchema(), repr.Table, s.idClaim(custClaim), pk, access)}, nil
	case ViaComposition:

		call := fmt.Sprintf("%s.%s_composition_%s(%s, '%s')", s.definerSchema(), obj.Name, r.Name, pk, access)
		return []string{s.probed(compositionProbe(obj, repr), call)}, nil
	case ViaClosure:
		if repr.Claim != "" {
			call := fmt.Sprintf("%s.%s_reachable(%s, %s)", s.definerSchema(), repr.Closure, s.idClaim(repr.Claim), repr.Col)
			if repr.Missing == "allow" {
				call = fmt.Sprintf("(%s IS NULL OR %s)", s.claim(repr.Claim), call)
			}
			return []string{call}, nil
		}
		if err := reqClaim(custClaim, obj, "closure relation "+t.Ident); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("%s.%s_reachable(%s, %s)", s.definerSchema(), repr.Closure, s.idClaim(custClaim), repr.Col)}, nil
	case ViaGroup:

		if err := reqClaim(custClaim, obj, "group relation "+t.Ident); err != nil {
			return nil, err
		}
		if repr.Materialized {

			return []string{fmt.Sprintf("%s_member(%s, %s)", s.groupFlatName(obj, r, repr), pk, s.idClaim(custClaim))}, nil
		}
		return []string{fmt.Sprintf("%s.%s_member(%s, %s)", s.definerSchema(), repr.Closure, repr.Col, s.idClaim(custClaim))}, nil
	case ViaMemberIn:

		name := fmt.Sprintf("%s_memberin_%s", s.adminName(), repr.Level)
		frag := fmt.Sprintf("%s.%s(%s, %s)", s.definerSchema(), name, s.argSrcSQL(repr.Principal), s.argSrcSQL(repr.Scope))
		if repr.ReachedBy {
			reach, err := s.memberinReachFrag(repr.Level, repr.ReachMember)
			if err != nil {
				return nil, err
			}
			frag = "(" + frag + " AND " + reach + ")"
		}
		return []string{frag}, nil
	case ViaObject:

		call := fmt.Sprintf("%s.%s(%s)", s.definerSchema(), repr.functionName(), repr.Col)
		return []string{s.probed(s.objectProbe(obj, repr), call)}, nil
	case ViaGrant:

		return s.emitGrantFrags(obj, r, &repr, accessFor(pm.Maps), custClaim)
	case ViaRole:
		return s.rlsEmitRole(obj, r, repr)
	default:
		return nil, fmt.Errorf("relation %q has an unknown representation", r.Name)
	}
}

// probed puts a relation definer's cheap first hop in front of the call, inside
// a definer body only. A definer called from another definer's body is planned
// afresh on every outer call, so a caller the hop rules out should never reach
// it. The probe is implied by the callee, which makes the conjunction equal to
// the call alone; it is only equal where the probe reads with the callee's
// privileges, which a definer body does and a policy does not.
func (s *Spec) probed(probe, call string) string {
	if !s.definerBody || probe == "" {
		return call
	}
	return "(" + probe + " AND " + call + ")"
}

func compositionProbe(obj *Object, vc ViaComposition) string {
	if vc.Table == obj.Table && vc.ChildCol == obj.pk() {
		return fmt.Sprintf("%s.%s IS NOT NULL", obj.Table, vc.ParentCol)
	}
	conds := []string{fmt.Sprintf("hop.%s = %s.%s", vc.ChildCol, obj.Table, obj.pk())}
	if vc.KindCol != "" {
		conds = append(conds, fmt.Sprintf("hop.%s = '%s'", vc.KindCol, vc.KindVal))
	}
	conds = append(conds, fmt.Sprintf("hop.%s IS NOT NULL", vc.ParentCol))
	return fmt.Sprintf("EXISTS (SELECT 1 FROM %s hop WHERE %s)", vc.Table, strings.Join(conds, " AND "))
}

func (s *Spec) objectProbe(obj *Object, vo ViaObject) string {
	other := s.objectByName(vo.Object)
	if other == nil {
		return ""
	}
	return fmt.Sprintf("EXISTS (SELECT 1 FROM %s hop WHERE hop.%s = %s.%s)", other.Table, other.pk(), obj.Table, vo.Col)
}

func (s *Spec) rlsEmitRole(obj *Object, r *Relation, repr ViaRole) ([]string, error) {

	if st := s.subjectByName(r.Types[0]); st != nil && s.isPlatformRoleSubject(st) {
		return []string{fmt.Sprintf("%s.%s(%s)", s.definerSchema(), platformRoleFn(st.Anchor), s.idClaim(st.Identifies))}, nil
	}

	var cols []string
	for _, lvl := range obj.Scoped {
		cols = append(cols, s.scopeCol(obj, lvl))
	}

	fn := fmt.Sprintf("%s_has_%s_role", s.adminName(), obj.Name)
	return []string{fmt.Sprintf("%s.%s(%s, %s)", s.definerSchema(), fn, s.idClaim(s.adminIdentify()), strings.Join(cols, ", "))}, nil
}

func (s *Spec) emitGrantFrags(obj *Object, r *Relation, vg *ViaGrant, access, custClaim string) ([]string, error) {
	var frags []string
	for i := range r.Types {
		name, _, _, claim := s.grantRelBinding(obj, vg, r, i)
		if claim == "" {
			return nil, fmt.Errorf("grant relation %q kind %q: no subject resolves a claim", r.Name, r.Types[i])
		}
		frag := fmt.Sprintf("%s.%s(%s, %s, '%s')", s.definerSchema(), name, s.idClaim(claim), obj.Table+"."+obj.pk(), access)
		if plane := s.grantKindPlaneGuard(claim, custClaim); plane != "" {
			frag = "(" + frag + " AND " + plane + ")"
		}
		frags = append(frags, frag)
	}
	return frags, nil
}

// grantKindPlaneGuard binds a grant row's principal KIND to the caller's plane.
//
// A multi-kind grant relation emits one fragment per kind, each keyed on that
// kind's own claim. That is only as strong as the claims being disjoint, and
// they are not symmetrical: the owner-plane claim is minted for owner-plane
// callers and nobody else, so a fragment keyed on it already answers false for
// everyone else. The other plane's claim is the generic subject, which an
// adopter may also populate for an owner-plane caller — and then a grant row
// naming the OTHER kind becomes reachable by an id collision across two id
// spaces that were never meant to meet.
//
// So the guard is emitted where it is load-bearing and not where it is implied:
// a kind on the non-owner plane is conjoined with "the owner claim is absent".
// The mirror test on an owner-plane kind is left out deliberately, because the
// fragment's own argument already is that claim — emitting it would restate the
// call's first parameter as a condition on itself.
//
// Narrowing only. It removes no principal from any enumeration (the accessor
// definers list grant ROWS, and every row still lists), and it takes access
// away only from a caller answering to a kind that was never theirs.
func (s *Spec) grantKindPlaneGuard(claim, custClaim string) string {
	if custClaim == "" || claim == custClaim {
		return ""
	}
	return s.claim(custClaim) + " IS NULL"
}

func ownerColPresent(vc ViaColumn) string {
	base := vc.Column + " IS NOT NULL"
	if vc.DiscrimCol == "" {
		return base
	}
	return fmt.Sprintf("%s AND %s = '%s'", base, vc.DiscrimCol, vc.DiscrimVal)
}

func (r *RLSResult) GovernedTables() []string {
	set := map[string]bool{}
	for _, p := range r.Policies {
		set[p.Table] = true
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (r *RLSResult) EnablementSQL() string {
	var b strings.Builder
	sch := r.tableSchema()
	for _, t := range r.GovernedTables() {
		fmt.Fprintf(&b, "ALTER TABLE %s.%s ENABLE ROW LEVEL SECURITY;\n", sch, t)
		fmt.Fprintf(&b, "ALTER TABLE %s.%s FORCE ROW LEVEL SECURITY;\n", sch, t)
	}
	return b.String()
}

func (r *RLSResult) PolicySQL(role string) string {
	pols := append([]Policy(nil), r.Policies...)
	sort.Slice(pols, func(i, j int) bool {
		if pols[i].Table != pols[j].Table {
			return pols[i].Table < pols[j].Table
		}
		return pols[i].Name < pols[j].Name
	})
	var b strings.Builder
	sch := r.tableSchema()
	for _, p := range pols {
		kind := ""
		if p.Restrictive {
			kind = " AS RESTRICTIVE"
		}
		fmt.Fprintf(&b, "DROP POLICY IF EXISTS %s ON %s.%s;\n", p.Name, sch, p.Table)
		fmt.Fprintf(&b, "CREATE POLICY %s ON %s.%s%s FOR %s TO %s", p.Name, sch, p.Table, kind, p.Cmd, role)
		if p.Using != "" {
			fmt.Fprintf(&b, "\n    USING (%s)", p.Using)
		}
		if p.Check != "" {
			fmt.Fprintf(&b, "\n    WITH CHECK (%s)", p.Check)
		}
		b.WriteString(";\n\n")
	}
	return b.String()
}

func (s *Spec) DefinerNames() ([]string, error) {
	res, err := s.EmitRLS()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, p := range res.Policies {
		for _, body := range []string{p.Using, p.Check} {
			for _, fn := range scanDefiners(body, s.definerSchema()) {
				set[fn] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func membershipFn(m *Membership) string { return m.FlagCol }

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func scanDefiners(sql, schema string) []string {
	var out []string
	marker := schema + "."
	for i := 0; i+len(marker) <= len(sql); {
		idx := strings.Index(sql[i:], marker)
		if idx < 0 {
			break
		}
		start := i + idx + len(marker)
		j := start
		for j < len(sql) && (isIdent(sql[j])) {
			j++
		}
		if j < len(sql) && sql[j] == '(' {
			out = append(out, marker+sql[start:j])
		}
		i = j
	}
	return out
}
