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
			pred, err := s.rlsPredicate(obj, pm, custSubj, virtual)
			if err != nil {
				res.Unsupported = append(res.Unsupported, fmt.Sprintf("%s.%s: %v", obj.Name, pm.Verb, err))
				continue
			}
			op := pm.Maps
			if opToCmd[op] == "" {
				res.Unsupported = append(res.Unsupported, fmt.Sprintf("%s.%s: @rls permission has no table-op maps", obj.Name, pm.Verb))
				continue
			}
			pol := Policy{Object: obj.Name, Table: obj.Table, Name: obj.Table + "_" + op, Cmd: opToCmd[op]}
			switch op {
			case "select", "delete":
				pol.Using = pred
			case "insert":
				pol.Check = pred
			case "update":
				pol.Using = pred
				pol.Check = pred
			}
			res.Policies = append(res.Policies, pol)
		}
	}
	return res, nil
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
	pred, err := s.rlsPredicate(o, upd, cust, virtual)
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

	top, grantInject := s.rlsSubjectBranches(obj, virtual, objLeaf, objIsGlobal, objHasStaffTerm)

	top, scopedGrant, err := s.rlsExprTopBranches(obj, pm, top)
	if err != nil {
		return "", err
	}

	blockTerms, err := s.nodeFrags(obj, pm, pm.Tree, rels, custClaim)
	if err != nil {
		return "", err
	}

	block, err := s.rlsContainmentBlock(obj, objLeaf, grantInject)
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
	return strings.Join(branches, " OR "), nil
}

func (s *Spec) rlsSubjectBranches(obj *Object, virtual map[string]bool, objLeaf string, objIsGlobal, objHasStaffTerm bool) ([]string, map[string][]string) {
	var top []string
	grantInject := map[string][]string{}
	for _, sub := range s.Subjects {
		switch {
		case sub.Membership != nil && virtual[sub.Anchor]:

			fn := fmt.Sprintf("%s.%s(%s)", s.definerSchema(), membershipFn(sub.Membership), s.claim(sub.Identifies))
			if obj.IsLevelEntity() || objIsGlobal {
				top = append(top, fn)
			} else {
				top = append(top, fmt.Sprintf("(%s AND %s IS NULL)", fn, s.claim(s.claimKeyForLevel(objLeaf))))
			}
		case s.isPlatformRoleSubject(sub) && (objHasStaffTerm || (objIsGlobal && sub.Anchor == objLeaf)):

			top = append(top, fmt.Sprintf("%s.%s(%s)", s.definerSchema(), platformRoleFn(sub.Anchor), s.claim(sub.Identifies)))
		case sub.Reach == "grant":

			top, grantInject = s.rlsApplyGrantReach(obj, sub, objLeaf, objIsGlobal, top, grantInject)
		}
	}
	return top, grantInject
}

func (s *Spec) rlsApplyGrantReach(obj *Object, sub *Subject, objLeaf string, objIsGlobal bool, top []string, grantInject map[string][]string) ([]string, map[string][]string) {
	g := s.grantByName(sub.ReachGrant)
	if g == nil || !contains(obj.Scoped, g.Level) {
		return top, grantInject
	}
	reach := fmt.Sprintf("%s.%s_reach(%s, %s)", s.definerSchema(), g.Table, s.claim(sub.Identifies), s.scopeCol(obj, g.Level))
	if g.Level != objLeaf && !obj.IsLevelEntity() && !objIsGlobal {

		grantInject[g.Level] = append(grantInject[g.Level], reach)
	} else {

		top = append(top, reach)
	}
	return top, grantInject
}

func (s *Spec) rlsExprTopBranches(obj *Object, pm *Perm, top []string) ([]string, bool, error) {

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
		reach, err := s.grantRefReach(obj, t.GrantRef)
		if err != nil {
			return nil, false, err
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
	return top, scopedGrant, nil
}

func (s *Spec) rlsContainmentBlock(obj *Object, objLeaf string, grantInject map[string][]string) (string, error) {
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
			colPred := fmt.Sprintf("%s = %s", s.scopeCol(obj, lvl.Name), s.claim(lvl.claimKey()))
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

func (s *Spec) grantRefReach(obj *Object, grantName string) (string, error) {
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
	return fmt.Sprintf("%s.%s_reach(%s, %s)", s.definerSchema(), g.Table, s.claim(claim), s.scopeCol(obj, g.Level)), nil
}

func (s *Spec) objectVerbPredicate(obj *Object, verb string, virtual map[string]bool) (string, error) {
	for _, pm := range obj.Perms {
		if pm.Verb == verb && contains(pm.Layers, "rls") {
			cust := s.ownerSubject(obj.Scoped[len(obj.Scoped)-1])
			return s.rlsPredicate(obj, pm, cust, virtual)
		}
	}
	return "", fmt.Errorf("object %q has no @rls permission %q for a cross-object reference", obj.Name, verb)
}

func (s *Spec) argSrcSQL(a ArgSrc) string {
	if a.Claim != "" {
		return s.claim(a.Claim)
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
	if n.Term.GrantRef != "" || n.Term.Builtin == "public" {
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
	if n == nil {
		return nil, nil
	}
	switch n.Op {
	case "leaf":
		return s.rlsLeafFrags(obj, pm, n, rels, custClaim)
	case "or":
		var out []string
		for _, k := range n.Kids {
			kf, err := s.nodeFrags(obj, pm, k, rels, custClaim)
			if err != nil {
				return nil, err
			}
			out = append(out, kf...)
		}
		return out, nil
	case "and":
		var parts []string
		for _, k := range n.Kids {
			kf, err := s.nodeFrags(obj, pm, k, rels, custClaim)
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
		kf, err := s.nodeFrags(obj, pm, n.Kids[0], rels, custClaim)
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
		return s.rlsEmitWalk(t, rels)
	}

	if relName, access, ok := grantSelector(t.Ident, rels); ok {
		r := rels[relName]
		vg := r.Repr.(ViaGrant)
		return s.emitGrantFrags(obj, r, &vg, access)
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

func (s *Spec) rlsEmitWalk(t *Term, rels map[string]*Relation) ([]string, error) {
	parent := rels[t.Ident]
	if parent == nil {
		return nil, fmt.Errorf("role-walk references unknown relation %q", t.Ident)
	}
	col, ok := parent.Repr.(ViaColumn)
	if !ok {
		return nil, fmt.Errorf("role-walk parent %q must be a column relation", t.Ident)
	}
	return []string{fmt.Sprintf("%s.is_%s_%s(%s, %s)", s.definerSchema(), parent.Types[0], s.adminName(), s.claim(s.adminIdentify()), col.Column)}, nil
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
	case t.Builtin != "":
		return nil, true, fmt.Errorf("builtin @%s is not emittable in RLS", t.Builtin)
	case isPermKeyLit(t.Ident):
		return nil, true, fmt.Errorf("capability term %q belongs to the PDP, not RLS", t.Ident)
	}
	return nil, false, nil
}

func (s *Spec) rlsEmitAppScope(obj *Object, t *Term, rels map[string]*Relation, custClaim string) ([]string, error) {
	if err := reqClaim(custClaim, obj, "@app_scope"); err != nil {
		return nil, err
	}
	base := s.claim(custClaim) + " IS NULL"
	if t.ExcludeRel != "" {
		r := rels[t.ExcludeRel]
		if r == nil {
			return nil, fmt.Errorf("@app_scope(exclude %q): unknown relation", t.ExcludeRel)
		}
		vc, ok := r.Repr.(ViaColumn)
		if !ok {
			return nil, fmt.Errorf("@app_scope(exclude %q): excluded relation must be an owner column", t.ExcludeRel)
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
	self := fmt.Sprintf("%s = %s", s.scopeCol(obj, leaf), s.claim(s.claimKeyForLevel(leaf)))
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
		base := fmt.Sprintf("%s = %s", repr.Column, s.claim(claimKey))

		if repr.DiscrimCol != "" {
			base = fmt.Sprintf("(%s AND %s = '%s')", base, repr.DiscrimCol, repr.DiscrimVal)
		}
		return []string{base}, nil
	case ViaEdge:

		if err := reqClaim(custClaim, obj, "edge relation "+t.Ident); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("%s.%s(%s, %s, '%s')", s.definerSchema(), repr.Table, s.claim(custClaim), pk, access)}, nil
	case ViaComposition:

		return []string{fmt.Sprintf("%s.%s_composition_%s(%s, '%s')", s.definerSchema(), obj.Name, r.Name, pk, access)}, nil
	case ViaClosure:

		if err := reqClaim(custClaim, obj, "closure relation "+t.Ident); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("%s.%s_reachable(%s, %s)", s.definerSchema(), repr.Closure, s.claim(custClaim), repr.Col)}, nil
	case ViaGroup:

		if err := reqClaim(custClaim, obj, "group relation "+t.Ident); err != nil {
			return nil, err
		}
		if repr.Materialized {

			return []string{fmt.Sprintf("%s_member(%s, %s)", s.groupFlatName(obj, r, repr), pk, s.claim(custClaim))}, nil
		}
		return []string{fmt.Sprintf("%s.%s_member(%s, %s)", s.definerSchema(), repr.Closure, repr.Col, s.claim(custClaim))}, nil
	case ViaMemberIn:

		name := fmt.Sprintf("%s_memberin_%s", s.adminName(), repr.Level)
		return []string{fmt.Sprintf("%s.%s(%s, %s)", s.definerSchema(), name, s.argSrcSQL(repr.Principal), s.argSrcSQL(repr.Scope))}, nil
	case ViaObject:

		return []string{fmt.Sprintf("%s.%s_can_%s(%s)", s.definerSchema(), repr.Object, repr.Verb, repr.Col)}, nil
	case ViaGrant:

		return s.emitGrantFrags(obj, r, &repr, accessFor(pm.Maps))
	case ViaRole:
		return s.rlsEmitRole(obj, r, repr)
	default:
		return nil, fmt.Errorf("relation %q has an unknown representation", r.Name)
	}
}

func (s *Spec) rlsEmitRole(obj *Object, r *Relation, repr ViaRole) ([]string, error) {

	if st := s.subjectByName(r.Types[0]); st != nil && s.isPlatformRoleSubject(st) {
		return []string{fmt.Sprintf("%s.%s(%s)", s.definerSchema(), platformRoleFn(st.Anchor), s.claim(st.Identifies))}, nil
	}

	var cols []string
	for _, lvl := range obj.Scoped {
		cols = append(cols, s.scopeCol(obj, lvl))
	}

	fn := fmt.Sprintf("%s_has_%s_role", s.adminName(), obj.Name)
	if repr.HasRank {
		fn = "is_" + repr.RankMin
	}
	return []string{fmt.Sprintf("%s.%s(%s, %s)", s.definerSchema(), fn, s.claim(s.adminIdentify()), strings.Join(cols, ", "))}, nil
}

func (s *Spec) emitGrantFrags(obj *Object, r *Relation, vg *ViaGrant, access string) ([]string, error) {
	var frags []string
	for i := range r.Types {
		name, _, _, claim := s.grantRelBinding(obj, vg, r, i)
		if claim == "" {
			return nil, fmt.Errorf("grant relation %q kind %q: no subject resolves a claim", r.Name, r.Types[i])
		}
		frags = append(frags, fmt.Sprintf("%s.%s(%s, %s, '%s')", s.definerSchema(), name, s.claim(claim), obj.Table+"."+obj.pk(), access))
	}
	return frags, nil
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
		fmt.Fprintf(&b, "DROP POLICY IF EXISTS %s ON %s.%s;\n", p.Name, sch, p.Table)
		fmt.Fprintf(&b, "CREATE POLICY %s ON %s.%s FOR %s TO %s", p.Name, sch, p.Table, p.Cmd, role)
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
