package demesne

import (
	"fmt"
	"sort"
	"strings"
)

type GenFn struct {
	Name   string
	Schema string

	TableSchema string
	Sig         string
	Body        string

	Returns string

	RawBody bool
}

func (d GenFn) schema() string {
	if d.Schema != "" {
		return d.Schema
	}
	return "auth"
}

func (d GenFn) tableSchema() string {
	if d.TableSchema != "" {
		return d.TableSchema
	}
	return "public"
}

func (d GenFn) ArgTypes() string {
	if strings.TrimSpace(d.Sig) == "" {
		return ""
	}
	parts := strings.Split(d.Sig, ",")
	types := make([]string, 0, len(parts))
	for _, p := range parts {
		f := strings.Fields(strings.TrimSpace(p))
		types = append(types, f[len(f)-1])
	}
	return strings.Join(types, ", ")
}

func (d GenFn) CreateSQL() string {
	returns := d.Returns
	if returns == "" {
		returns = "boolean"
	}
	body := "  SELECT " + d.Body + ";"
	if d.RawBody {
		body = d.Body
	}
	return fmt.Sprintf(
		"CREATE OR REPLACE FUNCTION %s.%s(%s)\nRETURNS %s\nLANGUAGE sql\nSTABLE\nSECURITY DEFINER\nSET search_path = %s\nAS $$\n%s\n$$;",
		d.schema(), d.Name, d.Sig, returns, d.tableSchema(), body)
}

func DefinersSQL(defs []GenFn) string {
	var b strings.Builder
	for _, d := range defs {
		b.WriteString(d.CreateSQL())
		b.WriteString("\n\n")
	}
	return b.String()
}

func (s *Spec) EmitDefiners() ([]GenFn, error) {
	var out []GenFn

	virtual := s.defVirtualLevels()

	if err := s.defEmitMembership(&out); err != nil {
		return nil, err
	}
	s.defEmitGrantReach(&out)

	rs := roleStoreByName(s)
	rankIdx := rankIndex(s)
	presetLevels := presetLevelMap(s)
	seen := map[string]bool{}

	if err := s.defEmitRoleDefiners(&out, seen, rs, rankIdx, presetLevels); err != nil {
		return nil, err
	}
	s.defEmitPlatformRoles(&out, seen, rs, presetLevels)
	s.defEmitScopedMemberin(&out, seen, rs)
	if err := s.defEmitKernel(&out, seen); err != nil {
		return nil, err
	}
	s.defEmitGrantRelations(&out, seen)
	if err := s.defEmitAccessors(&out, seen); err != nil {
		return nil, err
	}
	if err := s.defEmitStructuralAccessors(&out, seen); err != nil {
		return nil, err
	}
	s.defEmitClosure(&out, seen)
	s.defEmitGroup(&out, seen)
	if err := s.defEmitCrossObject(&out, seen, virtual); err != nil {
		return nil, err
	}
	if err := s.defEmitComposition(&out, seen, virtual); err != nil {
		return nil, err
	}
	if err := s.defEmitStoreManage(&out, seen, virtual); err != nil {
		return nil, err
	}
	s.defEmitMaterializedFlatMembers(&out, seen)

	for i := range out {
		out[i].Schema = s.definerSchema()
		out[i].TableSchema = s.tableSchema()
	}
	return out, nil
}

func (s *Spec) defVirtualLevels() map[string]bool {
	vchain, _ := s.Topology.Chain()
	virtual := map[string]bool{}
	for _, l := range vchain {
		if l.Virtual {
			virtual[l.Name] = true
		}
	}
	return virtual
}

func (s *Spec) defEmitMembership(out *[]GenFn) error {
	for _, sub := range s.Subjects {
		m := sub.Membership
		if m == nil {
			continue
		}
		if m.IDCol == "" || m.FlagCol == "" {
			return fmt.Errorf("subject %q membership needs (idcol, flagcol)", sub.Name)
		}
		body := fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s = user_id AND %s", m.Table, m.IDCol, m.FlagCol)
		if m.ActiveCol != "" {
			body += fmt.Sprintf(" AND %s = '%s'", m.ActiveCol, m.ActiveVal)
		}
		body += ")"
		*out = append(*out, GenFn{Name: m.FlagCol, Sig: "user_id text", Body: body})
	}
	return nil
}

func (s *Spec) defEmitGrantReach(out *[]GenFn) {
	gseen := map[string]bool{}
	for _, g := range s.Grants {
		name := g.Table + "_reach"
		if gseen[name] {
			continue
		}
		gseen[name] = true

		conj := []string{
			fmt.Sprintf("%s = user_id", g.GranteeCol),
			fmt.Sprintf("%s = check_%s_id", g.LevelCol, g.Level),
		}
		if g.ActiveCol != "" {
			conj = append(conj, fmt.Sprintf("%s IS NULL", g.ActiveCol))
		}
		if g.ExpiresCol != "" {
			conj = append(conj, fmt.Sprintf("%s > now()", g.ExpiresCol))
		}
		*out = append(*out, GenFn{Name: name, Sig: fmt.Sprintf("user_id text, check_%s_id text", g.Level), Body: grantEdgeExists(g.Table, conj...)})
	}
}

func (s *Spec) defEmitRoleDefiners(out *[]GenFn, seen map[string]bool, rs *RoleStore, rankIdx map[string]int, presetLevels map[string][]string) error {
	for _, obj := range s.Objects {
		rels := map[string]*Relation{}
		for _, r := range obj.Relations {
			rels[r.Name] = r
		}
		for _, pm := range obj.Perms {
			for _, t := range pm.Expr {
				d, ok, err := s.roleDefinerForTerm(obj, pm, t, rels, rs, rankIdx, presetLevels)
				if err != nil {
					return err
				}
				if ok && !seen[d.Name] {
					seen[d.Name] = true
					*out = append(*out, d)
				}
			}
		}
	}
	return nil
}

func (s *Spec) defEmitPlatformRoles(out *[]GenFn, seen map[string]bool, rs *RoleStore, presetLevels map[string][]string) {
	for _, sub := range s.Subjects {
		if !s.isPlatformRoleSubject(sub) || rs == nil {
			continue
		}
		name := platformRoleFn(sub.Anchor)
		if seen[name] {
			continue
		}
		seen[name] = true
		*out = append(*out, s.roleDefiner(name, rs, sub.Anchor, presetLevels[sub.Anchor], ""))
	}
}

func (s *Spec) defEmitScopedMemberin(out *[]GenFn, seen map[string]bool, rs *RoleStore) {
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			mi, ok := r.Repr.(ViaMemberIn)
			if !ok || rs == nil {
				continue
			}
			name := fmt.Sprintf("%s_memberin_%s", s.adminName(), mi.Level)
			if seen[name] {
				continue
			}
			seen[name] = true
			sCol := s.scopeColForLevel(rs, mi.Level)
			body := fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s = p_principal AND %s = p_%s AND %s = '%s' AND %s IS NULL)",
				rs.Assignments, rs.SubjectCol, sCol, mi.Level, rs.KindCol, rs.KindVal, rs.RevokedCol)
			*out = append(*out, GenFn{Name: name, Sig: fmt.Sprintf("p_principal text, p_%s text", mi.Level), Body: body})
		}
	}
}

func (s *Spec) defEmitKernel(out *[]GenFn, seen map[string]bool) error {
	for _, obj := range s.Objects {
		for _, pm := range obj.Perms {
			if !contains(pm.Layers, "kernel") {
				continue
			}
			d, err := s.kernelDefiner(obj)
			if err != nil {
				return err
			}
			if !seen[d.Name] {
				seen[d.Name] = true
				*out = append(*out, d)
			}
		}
	}
	return nil
}

func (s *Spec) defEmitGrantRelations(out *[]GenFn, seen map[string]bool) {
	for _, obj := range s.Objects {
		r, vg := grantRelation(obj)
		if r == nil {
			continue
		}
		for i := range r.Types {
			name, kind, param, _ := s.grantRelBinding(obj, vg, r, i)
			if seen[name] {
				continue
			}
			seen[name] = true
			conjuncts := []string{fmt.Sprintf("%s = p_%s_id", vg.RecordCol, obj.Name)}
			if vg.DiscrimCol != "" {
				conjuncts = append(conjuncts, fmt.Sprintf("%s = '%s'", vg.DiscrimCol, vg.DiscrimVal))
			}
			conjuncts = append(conjuncts,
				fmt.Sprintf("%s = '%s'", vg.KindCol, kind),
				fmt.Sprintf("%s = p_%s_id", vg.PrincipalCol, param),
				fmt.Sprintf("%s = p_access", vg.AccessCol),
			)
			*out = append(*out, GenFn{
				Name: name,
				Sig:  fmt.Sprintf("p_%s_id text, p_%s_id text, p_access text", param, obj.Name),
				Body: grantEdgeExists(vg.Table, conjuncts...),
			})
		}
	}
}

func (s *Spec) defEmitAccessors(out *[]GenFn, seen map[string]bool) error {
	for _, obj := range s.Objects {
		if _, vg := grantRelation(obj); vg == nil {
			continue
		}
		name := obj.Table + "_accessors"
		if seen[name] {
			continue
		}

		if ok, reason := s.accessorCoverage(obj); !ok {
			return fmt.Errorf("object %q: cannot soundly enumerate accessors (auth.%s would under-report) — %s", obj.Name, name, reason)
		}
		seen[name] = true
		*out = append(*out, s.pureAccessorDefiners(obj)...)
	}
	return nil
}

func accessorReprCovered(r Repr) bool {
	switch r.(type) {
	case ViaColumn, ViaGrant, ViaRole, ViaGroup, ViaClosure, ViaComposition:
		return true
	default:
		return false
	}
}

func accessorTreeOp(n *PermNode) string {
	if n == nil {
		return ""
	}
	switch n.Op {
	case "not":
		return "and not"
	case "and":
		return "and"
	}
	for _, k := range n.Kids {
		if op := accessorTreeOp(k); op != "" {
			return op
		}
	}
	return ""
}

func (s *Spec) accessorCoverage(obj *Object) (bool, string) {
	return s.accessorCoverageSeen(obj, map[string]bool{})
}

func (s *Spec) accessorCoverageSeen(obj *Object, seen map[string]bool) (bool, string) {
	if seen[obj.Name] {
		return true, ""
	}
	seen[obj.Name] = true
	rels := map[string]*Relation{}
	for _, r := range obj.Relations {
		rels[r.Name] = r
	}
	var sel *Perm
	for _, pm := range obj.Perms {
		if pm.Maps == "select" {
			sel = pm
			break
		}
	}
	if sel == nil {
		return true, ""
	}
	if accessorTreeOp(sel.Tree) != "" {

		if _, ok := s.accessorTreeSQL(obj, sel.Tree, rels); !ok {
			return false, "its SELECT permission intersects/excludes over a term the accessor enumerator cannot compose (only owner/grant/group/closure/object leaves)"
		}
		return true, ""
	}
	for _, t := range sel.Expr {
		if t == nil || t.Ident == "" {
			continue
		}
		r := rels[t.Ident]
		if r == nil {
			continue
		}
		if vo, ok := r.Repr.(ViaObject); ok {
			if cov, reason := s.viaObjectCovered(vo, seen); !cov {
				return false, fmt.Sprintf("relation %q borrows %s->%s, not soundly enumerable (%s)", t.Ident, vo.Object, vo.Verb, reason)
			}
			continue
		}
		if !accessorReprCovered(r.Repr) {
			return false, fmt.Sprintf("relation %q (%T) has no accessor branch yet (reverse builder is WS1)", t.Ident, r.Repr)
		}
	}
	return true, ""
}

func (s *Spec) viaObjectCovered(vo ViaObject, seen map[string]bool) (bool, string) {
	other := s.objectByName(vo.Object)
	if other == nil {
		return false, fmt.Sprintf("borrowed object %q not found", vo.Object)
	}
	readVerb := ""
	for _, pm := range other.Perms {
		if pm.Maps == "select" {
			readVerb = pm.Verb
			break
		}
	}
	if readVerb == "" || vo.Verb != readVerb {
		return false, fmt.Sprintf("only a read borrow is reversible (%q is not %q's select verb)", vo.Verb, vo.Object)
	}
	if _, vg := grantRelation(other); vg == nil {
		return false, fmt.Sprintf("borrowed object %q has no accessor enumerator", vo.Object)
	}
	return s.accessorCoverageSeen(other, seen)
}

func structuralAccessorCoverage(obj *Object) (bool, string) {
	rels := map[string]*Relation{}
	for _, r := range obj.Relations {
		rels[r.Name] = r
	}
	var sel *Perm
	for _, pm := range obj.Perms {
		if pm.Maps == "select" {
			sel = pm
			break
		}
	}
	if sel == nil {
		return true, ""
	}
	if op := accessorTreeOp(sel.Tree); op != "" {
		return false, fmt.Sprintf("its SELECT permission uses %q, which the union enumerator cannot represent", op)
	}
	for _, t := range sel.Expr {

		if t == nil || t.Builtin != "" || t.WalkVerb != "" || t.Ident == "" {
			continue
		}
		r := rels[t.Ident]
		if r == nil {
			continue
		}
		switch r.Repr.(type) {
		case ViaRole, ViaMemberIn:

		default:
			return false, fmt.Sprintf("relation %q (%T) is not enumerable by the structural accessor path (only via-role / via-memberin)", t.Ident, r.Repr)
		}
	}
	return true, ""
}

func (s *Spec) defEmitStructuralAccessors(out *[]GenFn, seen map[string]bool) error {
	for _, obj := range s.Objects {
		if !obj.IsLevelEntity() {
			continue
		}
		name := obj.Table + "_accessors"
		if seen[name] {
			continue
		}
		d, ok, err := s.structuralAccessorDefiner(obj)
		if err != nil {
			return err
		}
		if ok {

			if cov, reason := structuralAccessorCoverage(obj); !cov {
				return fmt.Errorf("object %q: cannot soundly enumerate structural accessors (auth.%s would under-report) — %s", obj.Name, name, reason)
			}
			seen[name] = true
			*out = append(*out, d)
		}
	}
	return nil
}

func (s *Spec) defEmitClosure(out *[]GenFn, seen map[string]bool) {
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			c, ok := r.Repr.(ViaClosure)
			if !ok {
				continue
			}
			name := c.Closure + "_reachable"
			if seen[name] {
				continue
			}
			seen[name] = true
			*out = append(*out, GenFn{
				Name: name,
				Sig:  "p_ancestor text, p_descendant text",
				Body: fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s = p_ancestor AND %s = p_descendant)", c.Closure, c.AncestorCol, c.DescendantCol),
			})
		}
	}
}

func (s *Spec) defEmitGroup(out *[]GenFn, seen map[string]bool) {
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			g, ok := r.Repr.(ViaGroup)
			if !ok {
				continue
			}
			name := g.Closure + "_member"
			if seen[name] {
				continue
			}
			seen[name] = true
			*out = append(*out, GenFn{
				Name: name,
				Sig:  "p_group text, p_member text",
				Body: fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s = p_group AND %s = p_member)", g.Closure, g.GroupCol, g.MemberCol),
			})
		}
	}
}

func (s *Spec) defEmitMaterializedFlatMembers(out *[]GenFn, seen map[string]bool) {
	for _, f := range s.EmitMaterializedFlats() {
		name := f.Flat + "_member"
		if !seen[name] {
			seen[name] = true
			*out = append(*out, f.MemberDefiner())
		}

		if rname := f.Flat + "_resources"; f.HasReverse() && !seen[rname] {
			seen[rname] = true
			*out = append(*out, f.ResourcesDefiner())
		}
	}
}

func (s *Spec) defEmitCrossObject(out *[]GenFn, seen map[string]bool, virtual map[string]bool) error {
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			vo, ok := r.Repr.(ViaObject)
			if !ok {
				continue
			}
			name := vo.Object + "_can_" + vo.Verb
			if seen[name] {
				continue
			}
			seen[name] = true
			other := s.objectByName(vo.Object)
			if other == nil {
				return fmt.Errorf("relation %q references unknown object %q", r.Name, vo.Object)
			}
			pred, err := s.objectVerbPredicate(other, vo.Verb, virtual)
			if err != nil {
				return err
			}
			*out = append(*out, GenFn{
				Name: name,
				Sig:  fmt.Sprintf("p_%s_id text", vo.Object),
				Body: fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s.%s = p_%s_id AND (%s))", other.Table, other.Table, other.pk(), vo.Object, pred),
			})
		}
	}
	return nil
}

func (s *Spec) defEmitComposition(out *[]GenFn, seen map[string]bool, virtual map[string]bool) error {

	branches := []struct{ access, op string }{
		{"read", "select"}, {"write", "update"}, {"delete", "delete"},
	}
	for _, obj := range s.Objects {
		base := obj.withoutComposition()
		for _, r := range obj.Relations {
			vc, ok := r.Repr.(ViaComposition)
			if !ok {
				continue
			}
			name := obj.Name + "_composition_" + r.Name
			if seen[name] {
				continue
			}
			seen[name] = true
			var cases []string
			for _, b := range branches {
				pred, err := s.opPredicate(base, b.op, virtual)
				if err != nil {
					return err
				}
				if pred == "" {
					continue
				}

				cases = append(cases, fmt.Sprintf("WHEN '%s' THEN EXISTS (SELECT 1 FROM %s WHERE %s.%s = e.%s AND (%s))",
					b.access, obj.Table, obj.Table, obj.pk(), vc.ParentCol, pred))
			}
			if len(cases) == 0 {
				return fmt.Errorf("object %q composition relation %q: object has no cascadable @rls verb predicate", obj.Name, r.Name)
			}
			kindFilter := ""
			if vc.KindCol != "" {
				kindFilter = fmt.Sprintf(" AND e.%s = '%s'", vc.KindCol, vc.KindVal)
			}
			body := fmt.Sprintf(
				"EXISTS (SELECT 1 FROM %s e WHERE e.%s = p_%s_id%s AND CASE p_access %s ELSE false END)",
				vc.Table, vc.ChildCol, obj.Name, kindFilter, strings.Join(cases, " "))
			*out = append(*out, GenFn{
				Name: name,
				Sig:  fmt.Sprintf("p_%s_id text, p_access text", obj.Name),
				Body: body,
			})
		}
	}
	return nil
}

func (s *Spec) opPredicate(obj *Object, op string, virtual map[string]bool) (string, error) {
	for _, pm := range obj.Perms {
		if contains(pm.Layers, "rls") && pm.Maps == op {
			cust := s.ownerSubject(obj.Scoped[len(obj.Scoped)-1])
			return s.rlsPredicate(obj, pm, cust, virtual)
		}
	}
	return "", nil
}

func (o *Object) withoutComposition() *Object {
	comp := map[string]bool{}
	var rels []*Relation
	for _, r := range o.Relations {
		if _, ok := r.Repr.(ViaComposition); ok {
			comp[r.Name] = true
			continue
		}
		rels = append(rels, r)
	}
	cp := *o
	cp.Relations = rels
	perms := make([]*Perm, 0, len(o.Perms))
	for _, pm := range o.Perms {
		pc := *pm
		pc.Tree = pruneCompLeaves(pm.Tree, comp)
		pc.Expr = pruneCompExpr(pm.Expr, comp)
		perms = append(perms, &pc)
	}
	cp.Perms = perms
	return &cp
}

func pruneCompLeaves(n *PermNode, comp map[string]bool) *PermNode {
	if n == nil {
		return nil
	}
	switch n.Op {
	case "leaf":
		if n.Term != nil && comp[n.Term.Ident] {
			return nil
		}
		return n
	case "or", "and":
		var kids []*PermNode
		for _, k := range n.Kids {
			if pk := pruneCompLeaves(k, comp); pk != nil {
				kids = append(kids, pk)
			}
		}
		if len(kids) == 0 {
			return nil
		}
		if len(kids) == 1 && n.Op == "or" {
			return kids[0]
		}
		cp := *n
		cp.Kids = kids
		return &cp
	case "not":
		pk := pruneCompLeaves(n.Kids[0], comp)
		if pk == nil {
			return nil
		}
		cp := *n
		cp.Kids = []*PermNode{pk}
		return &cp
	}
	return n
}

func pruneCompExpr(expr []*Term, comp map[string]bool) []*Term {
	out := make([]*Term, 0, len(expr))
	for _, t := range expr {
		if comp[t.Ident] {
			continue
		}
		out = append(out, t)
	}
	return out
}

func (s *Spec) defEmitStoreManage(out *[]GenFn, seen map[string]bool, virtual map[string]bool) error {
	manageStores := map[string]bool{}
	for _, obj := range s.Objects {
		if objectUsesStoreManage(obj) {
			manageStores[obj.Table] = true
		}
	}
	storeNames := make([]string, 0, len(manageStores))
	for st := range manageStores {
		storeNames = append(storeNames, st)
	}
	sort.Strings(storeNames)
	for _, store := range storeNames {
		whens, err := s.defStoreManageWhens(out, seen, virtual, store)
		if err != nil {
			return err
		}
		name := storeManageName(store)
		if seen[name] {
			continue
		}
		seen[name] = true
		*out = append(*out, GenFn{
			Name: name,
			Sig:  "p_type text, p_id text",
			Body: fmt.Sprintf("(CASE p_type %s ELSE false END)", strings.Join(whens, " ")),
		})
	}
	return nil
}

func (s *Spec) defStoreManageWhens(out *[]GenFn, seen map[string]bool, virtual map[string]bool, store string) ([]string, error) {
	var whens []string
	for _, o := range s.storeDescriptors(store) {
		canEdit := o.Name + "_can_edit"
		if !seen[canEdit] {
			seen[canEdit] = true
			pred, err := s.objectVerbPredicate(o, "edit", virtual)
			if err != nil {
				return nil, fmt.Errorf("@store_manage dispatch for %q: %w", store, err)
			}
			*out = append(*out, GenFn{
				Name: canEdit,
				Sig:  "p_id text",
				Body: fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s.%s = p_id AND (%s))", o.Table, o.Table, o.pk(), pred),
			})
		}
		whens = append(whens, fmt.Sprintf("WHEN '%s' THEN %s.%s(p_id)", objectGrantEdge(o).DiscrimVal, s.definerSchema(), canEdit))
	}
	return whens, nil
}

func (s *Spec) roleDefinerForTerm(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, rs *RoleStore, rankIdx map[string]int, presetLevels map[string][]string) (GenFn, bool, error) {
	if rs == nil {
		return GenFn{}, false, nil
	}

	if t.WalkVerb != "" {
		parent := rels[t.Ident]
		if parent == nil {
			return GenFn{}, false, fmt.Errorf("walk references unknown relation %q", t.Ident)
		}
		lvl := parent.Types[0]
		fn := fmt.Sprintf("is_%s_%s", lvl, s.adminName())
		keys := presetLevels[lvl]
		return s.roleDefiner(fn, rs, lvl, keys, s.operatorReach(lvl)), true, nil
	}

	relName := t.Ident
	if t.Builtin == "session" && t.SessionRel != "" {
		relName = t.SessionRel
	}
	r := rels[relName]
	if r == nil {
		return GenFn{}, false, nil
	}
	vr, ok := r.Repr.(ViaRole)
	if !ok {
		return GenFn{}, false, nil
	}

	if len(r.Types) > 0 {
		if st := s.subjectByName(r.Types[0]); st != nil && s.isPlatformRoleSubject(st) {
			return GenFn{}, false, nil
		}
	}
	objLevel := obj.Scoped[len(obj.Scoped)-1]
	keys := presetLevels[objLevel]
	if vr.HasRank {

		keys = atOrAbove(keys, vr.RankMin, rankIdx)
		recurse := s.parentLevelRecurse(obj)
		return s.roleDefiner("is_"+vr.RankMin, rs, objLevel, keys, recurse), true, nil
	}

	return s.roleDefiner(fmt.Sprintf("%s_has_%s_role", s.adminName(), obj.Name), rs, objLevel, keys, ""), true, nil
}

func (s *Spec) roleDefiner(name string, rs *RoleStore, level string, keys []string, recurse string) GenFn {

	chain, _ := s.Topology.Chain()
	var nonVirtual []string
	for _, l := range chain {
		if !l.Virtual {
			nonVirtual = append(nonVirtual, l.Name)
		}
	}

	onPath := map[string]bool{}
	if path, err := s.Topology.AncestorPath(level); err == nil {
		for _, l := range path {
			onPath[l.Name] = true
		}
	}

	args := []string{"user_id text"}
	var scope []string
	for i, lvl := range nonVirtual {
		if i >= len(rs.ScopeCols) {
			break
		}
		col := rs.ScopeCols[i]
		if onPath[lvl] {
			arg := "check_" + lvl + "_id"
			args = append(args, arg+" text")
			scope = append(scope, fmt.Sprintf("ra.%s = %s", col, arg))
		} else {
			scope = append(scope, fmt.Sprintf("ra.%s IS NULL", col))
		}
	}
	sort.Strings(keys)
	quoted := make([]string, len(keys))
	for i, k := range keys {
		quoted[i] = "'" + k + "'"
	}
	exists := fmt.Sprintf(
		"EXISTS (SELECT 1 FROM %s ra JOIN %s r ON r.%s = ra.%s WHERE ra.%s = '%s' AND ra.%s = user_id AND %s AND ra.%s IS NULL AND r.%s IN (%s))",
		rs.Assignments, rs.RolesTable, rs.RolesID, rs.RoleCol,
		rs.KindCol, rs.KindVal, rs.SubjectCol, strings.Join(scope, " AND "),
		rs.RevokedCol, rs.KeyCol, strings.Join(quoted, ", "))
	body := exists
	if recurse != "" {
		body = s.definerSchema() + "." + recurse + " OR " + exists
	}
	return GenFn{Name: name, Sig: strings.Join(args, ", "), Body: body}
}

func (s *Spec) parentLevelRecurse(obj *Object) string {
	if len(obj.Scoped) < 2 {
		return s.operatorReach(obj.Scoped[len(obj.Scoped)-1])
	}
	parent := obj.Scoped[len(obj.Scoped)-2]
	return fmt.Sprintf("is_%s_%s(user_id, check_%s_id)", parent, s.adminName(), parent)
}

func (s *Spec) operatorReach(level string) string {
	for _, sub := range s.Subjects {
		if sub.Membership != nil {
			return sub.Membership.FlagCol + "(user_id)"
		}
		if sub.Reach == "grant" {
			if g := s.grantByName(sub.ReachGrant); g != nil && g.Level == level {
				return fmt.Sprintf("%s_reach(user_id, check_%s_id)", g.Table, g.Level)
			}
		}
	}
	return ""
}

func platformRoleFn(anchor string) string { return "has_" + anchor + "_role" }

func (s *Spec) isPlatformRoleSubject(sub *Subject) bool {
	return sub.Roles != "" && !sub.RolesNone && sub.Membership == nil &&
		sub.Reach != "grant" && s.levelIsVirtual(sub.Anchor)
}

func (s *Spec) selectUsesAppScope(obj *Object) bool {
	for _, pm := range obj.Perms {
		if pm.Maps != "select" {
			continue
		}
		for _, t := range pm.Expr {
			if t != nil && t.Builtin == "app_scope" {
				return true
			}
		}
	}
	return false
}

func (s *Spec) ownerPrincipalName(obj *Object) string {
	for _, r := range obj.Relations {
		if r.Name == "owner" && len(r.Types) > 0 {
			if _, ok := r.Repr.(ViaColumn); ok {
				return r.Types[0]
			}
		}
	}
	if sub := s.ownerSubject(obj.Scoped[len(obj.Scoped)-1]); sub != nil {
		return sub.Name
	}
	return "principal"
}

func (s *Spec) pureAccessorDefiners(obj *Object) []GenFn {
	rels := map[string]*Relation{}
	for _, r := range obj.Relations {
		rels[r.Name] = r
	}
	var sel *Perm
	for _, pm := range obj.Perms {
		if pm.Maps == "select" {
			sel = pm
			break
		}
	}

	if sel != nil && accessorTreeOp(sel.Tree) != "" {
		if composed, ok := s.accessorTreeSQL(obj, sel.Tree, rels); ok {
			return []GenFn{accessorGenFn(obj.Table, []string{composed})}
		}
	}

	var branches []string
	var adminExcl string
	if sel != nil {

		branches = append(branches, defOwnerAccessorBranches(obj, sel, rels)...)

		adminExcl = defAdminExclCond(sel, rels)
	}

	if _, vg := grantRelation(obj); vg != nil {
		branches = append(branches, grantAccessorBranch(vg))
	}

	if rb, ok := s.roleAccessorBranch(obj, adminExcl); ok {
		branches = append(branches, rb)
	}

	branches = append(branches, s.defGroupAccessorBranches(obj, sel, rels)...)

	branches = append(branches, defClosureAccessorBranches(obj, sel, rels)...)

	branches = append(branches, s.defObjectAccessorBranches(obj, sel, rels)...)

	comp := s.defCompositionAccessorBranches(obj, sel, rels)
	if len(comp) == 0 {
		return []GenFn{accessorGenFn(obj.Table, branches)}
	}
	direct := accessorGenFnNamed(obj.Table+"_direct_accessors", branches)
	full := accessorGenFn(obj.Table, append(
		[]string{fmt.Sprintf("SELECT d.source, d.principal_kind, d.principal_id, d.access FROM %s.%s_direct_accessors(p_id) d", s.definerSchema(), obj.Table)},
		comp...))
	return []GenFn{direct, full}
}

func (s *Spec) defCompositionAccessorBranches(obj *Object, sel *Perm, rels map[string]*Relation) []string {
	if sel == nil {
		return nil
	}
	var branches []string
	for _, t := range sel.Expr {
		if t == nil || t.Ident == "" {
			continue
		}
		r := rels[t.Ident]
		if r == nil {
			continue
		}
		vc, ok := r.Repr.(ViaComposition)
		if !ok {
			continue
		}
		branches = append(branches, compositionAccessorBranch(obj.Table, s.definerSchema(), vc))
	}
	return branches
}

func compositionAccessorBranch(table, schema string, vc ViaComposition) string {
	conds := []string{fmt.Sprintf("e.%s = p_id", vc.ChildCol)}
	if vc.KindCol != "" {
		conds = append(conds, fmt.Sprintf("e.%s = '%s'", vc.KindCol, vc.KindVal))
	}
	return fmt.Sprintf(
		"SELECT a.source, a.principal_kind, a.principal_id, a.access\n    FROM %s e\n    JOIN LATERAL %s.%s_direct_accessors(e.%s) a ON true\n    WHERE %s",
		vc.Table, schema, table, vc.ParentCol, strings.Join(conds, " AND "))
}

func (s *Spec) defGroupAccessorBranches(obj *Object, sel *Perm, rels map[string]*Relation) []string {
	if sel == nil {
		return nil
	}
	var branches []string
	for _, t := range sel.Expr {
		if t == nil || t.Ident == "" {
			continue
		}
		r := rels[t.Ident]
		if r == nil {
			continue
		}
		g, ok := r.Repr.(ViaGroup)
		if !ok {
			continue
		}
		kind := ""
		if len(r.Types) > 0 {
			kind = r.Types[0]
		}
		branches = append(branches, groupAccessorBranch(obj.Table, obj.pk(), kind, g, s.groupFlatName(obj, r, g)))
	}
	return branches
}

func groupAccessorBranch(table, pk, kind string, g ViaGroup, flat string) string {
	if g.Materialized && flat != "" {
		return fmt.Sprintf(
			"SELECT 'group'::text, '%s'::text, f.principal_id, 'read'::text\n    FROM %s f\n    WHERE f.resource_id = p_id",
			kind, flat)
	}
	return fmt.Sprintf(
		"SELECT 'group'::text, '%s'::text, c.%s, 'read'::text\n    FROM %s t\n    JOIN %s c ON c.%s = t.%s\n    WHERE t.%s = p_id",
		kind, g.MemberCol, table, g.Closure, g.GroupCol, g.Col, pk)
}

func (s *Spec) groupFlatName(obj *Object, r *Relation, g ViaGroup) string {
	if !g.Materialized {
		return ""
	}
	return fmt.Sprintf("%s.%s_%s_flat", s.definerSchema(), obj.Table, r.Name)
}

func defClosureAccessorBranches(obj *Object, sel *Perm, rels map[string]*Relation) []string {
	if sel == nil {
		return nil
	}
	var branches []string
	for _, t := range sel.Expr {
		if t == nil || t.Ident == "" {
			continue
		}
		r := rels[t.Ident]
		if r == nil {
			continue
		}
		c, ok := r.Repr.(ViaClosure)
		if !ok {
			continue
		}
		kind := ""
		if len(r.Types) > 0 {
			kind = r.Types[0]
		}
		branches = append(branches, closureAccessorBranch(obj.Table, obj.pk(), kind, c))
	}
	return branches
}

func closureAccessorBranch(table, pk, kind string, c ViaClosure) string {
	return fmt.Sprintf(
		"SELECT 'closure'::text, '%s'::text, x.%s, 'read'::text\n    FROM %s t\n    JOIN %s x ON x.%s = t.%s\n    WHERE t.%s = p_id",
		kind, c.AncestorCol, table, c.Closure, c.DescendantCol, c.Col, pk)
}

func (s *Spec) defObjectAccessorBranches(obj *Object, sel *Perm, rels map[string]*Relation) []string {
	if sel == nil {
		return nil
	}
	var branches []string
	for _, t := range sel.Expr {
		if t == nil || t.Ident == "" {
			continue
		}
		r := rels[t.Ident]
		if r == nil {
			continue
		}
		vo, ok := r.Repr.(ViaObject)
		if !ok {
			continue
		}
		other := s.objectByName(vo.Object)
		if other == nil {
			continue
		}
		branches = append(branches, objectAccessorBranch(obj.Table, obj.pk(), vo, other.Table, s.definerSchema()))
	}
	return branches
}

func objectAccessorBranch(table, pk string, vo ViaObject, otherTable, schema string) string {
	return fmt.Sprintf(
		"SELECT a.source, a.principal_kind, a.principal_id, a.access\n    FROM %s t\n    JOIN LATERAL %s.%s_accessors(t.%s) a ON true\n    WHERE t.%s = p_id",
		table, schema, otherTable, vo.Col, pk)
}

func (s *Spec) accessorBranchForTerm(obj *Object, t *Term, rels map[string]*Relation) (string, bool) {
	if t == nil || t.Ident == "" {
		return "", false
	}

	name := t.Ident
	if rn, _, ok := grantSelector(t.Ident, rels); ok {
		name = rn
	}
	r := rels[name]
	if r == nil {
		return "", false
	}
	kind := ""
	if len(r.Types) > 0 {
		kind = r.Types[0]
	}
	switch repr := r.Repr.(type) {
	case ViaColumn:
		return ownerAccessorBranch(obj.Table, obj.pk(), kind, repr, false), true
	case ViaGrant:
		return grantAccessorBranch(&repr), true
	case ViaGroup:
		return groupAccessorBranch(obj.Table, obj.pk(), kind, repr, s.groupFlatName(obj, r, repr)), true
	case ViaClosure:
		return closureAccessorBranch(obj.Table, obj.pk(), kind, repr), true
	case ViaObject:
		if ok, _ := s.viaObjectCovered(repr, map[string]bool{}); !ok {
			return "", false
		}
		other := s.objectByName(repr.Object)
		if other == nil {
			return "", false
		}
		return objectAccessorBranch(obj.Table, obj.pk(), repr, other.Table, s.definerSchema()), true
	}
	return "", false
}

func (s *Spec) accessorTreeSQL(obj *Object, n *PermNode, rels map[string]*Relation) (string, bool) {
	if n == nil {
		return "", false
	}
	switch n.Op {
	case "leaf":
		return s.accessorBranchForTerm(obj, n.Term, rels)
	case "or":
		var parts []string
		for _, k := range n.Kids {
			sql, ok := s.accessorTreeSQL(obj, k, rels)
			if !ok {
				return "", false
			}
			parts = append(parts, "("+sql+")")
		}
		if len(parts) == 0 {
			return "", false
		}
		return strings.Join(parts, "\n  UNION ALL\n  "), true
	case "and":
		return s.accessorAndSQL(obj, n, rels)
	}
	return "", false
}

func (s *Spec) accessorAndSQL(obj *Object, n *PermNode, rels map[string]*Relation) (string, bool) {
	var positives, negatives []*PermNode
	for _, k := range n.Kids {
		if k.Op == "not" {
			if len(k.Kids) != 1 {
				return "", false
			}
			negatives = append(negatives, k.Kids[0])
		} else {
			positives = append(positives, k)
		}
	}
	if len(positives) == 0 {
		return "", false
	}
	base, ok := s.accessorTreeSQL(obj, positives[0], rels)
	if !ok {
		return "", false
	}
	idIn := func(sub string) string {
		return fmt.Sprintf("(a.principal_kind, a.principal_id) IN (SELECT b.principal_kind, b.principal_id FROM (%s) b(source, principal_kind, principal_id, access))", sub)
	}
	idNotIn := func(sub string) string {
		return fmt.Sprintf("(a.principal_kind, a.principal_id) NOT IN (SELECT b.principal_kind, b.principal_id FROM (%s) b(source, principal_kind, principal_id, access))", sub)
	}
	var filters []string
	for _, p := range positives[1:] {
		sub, ok := s.accessorTreeSQL(obj, p, rels)
		if !ok {
			return "", false
		}
		filters = append(filters, idIn(sub))
	}
	for _, ng := range negatives {
		sub, ok := s.accessorTreeSQL(obj, ng, rels)
		if !ok {
			return "", false
		}
		filters = append(filters, idNotIn(sub))
	}
	if len(filters) == 0 {
		return base, true
	}
	return fmt.Sprintf("SELECT a.* FROM (%s) a(source, principal_kind, principal_id, access)\n    WHERE %s", base, strings.Join(filters, "\n      AND ")), true
}

func defOwnerAccessorBranches(obj *Object, sel *Perm, rels map[string]*Relation) []string {
	var branches []string
	first := true
	for _, t := range sel.Expr {
		if t == nil || t.Ident == "" {
			continue
		}
		r := rels[t.Ident]
		if r == nil {
			continue
		}
		vc, ok := r.Repr.(ViaColumn)
		if !ok {
			continue
		}
		kind := ""
		if len(r.Types) > 0 {
			kind = r.Types[0]
		}
		branches = append(branches, ownerAccessorBranch(obj.Table, obj.pk(), kind, vc, first))
		first = false
	}
	return branches
}

func defAdminExclCond(sel *Perm, rels map[string]*Relation) string {
	for _, t := range sel.Expr {
		if t != nil && t.Builtin == "app_scope" && t.ExcludeRel != "" {
			if r := rels[t.ExcludeRel]; r != nil {
				if vc, ok := r.Repr.(ViaColumn); ok {
					return ownerExclCond(vc)
				}
			}
		}
	}
	return ""
}

func ownerAccessorBranch(table, pk, kind string, vc ViaColumn, first bool) string {
	if first {
		return fmt.Sprintf(
			"SELECT 'owner'::text AS source, '%s'::text AS principal_kind, %s AS principal_id, 'write'::text AS access\n    FROM %s WHERE %s = p_id AND %s",
			kind, vc.Column, table, pk, ownerColPresent(vc))
	}
	return fmt.Sprintf(
		"SELECT 'owner'::text, '%s'::text, %s, 'write'::text\n    FROM %s WHERE %s = p_id AND %s",
		kind, vc.Column, table, pk, ownerColPresent(vc))
}

func ownerExclCond(vc ViaColumn) string {
	if vc.DiscrimCol != "" {
		return fmt.Sprintf("r.%s IS DISTINCT FROM '%s'", vc.DiscrimCol, vc.DiscrimVal)
	}
	return fmt.Sprintf("r.%s IS NULL", vc.Column)
}

func grantAccessorBranch(g *ViaGrant) string {
	conds := []string{fmt.Sprintf("%s = p_id", g.RecordCol)}
	if g.DiscrimCol != "" {
		conds = append(conds, fmt.Sprintf("%s = '%s'", g.DiscrimCol, g.DiscrimVal))
	}
	return fmt.Sprintf(
		"SELECT 'grant'::text, %s, %s, %s\n    FROM %s WHERE %s",
		g.KindCol, g.PrincipalCol, g.AccessCol, g.Table, strings.Join(conds, " AND "))
}

func (s *Spec) roleAccessorBranch(obj *Object, adminExcl string) (string, bool) {
	rs := roleStoreByName(s)
	if rs == nil || !s.selectUsesAppScope(obj) {
		return "", false
	}
	var scopeConds []string
	for i, lvl := range obj.Scoped {
		if i >= len(rs.ScopeCols) {
			break
		}
		rsCol := rs.ScopeCols[i]
		rowCol := s.scopeCol(obj, lvl)
		if i == len(obj.Scoped)-1 {
			scopeConds = append(scopeConds, fmt.Sprintf("(ra.%s IS NULL OR ra.%s = r.%s)", rsCol, rsCol, rowCol))
		} else {
			scopeConds = append(scopeConds, fmt.Sprintf("ra.%s = r.%s", rsCol, rowCol))
		}
	}
	where := []string{"r." + obj.pk() + " = p_id"}
	if adminExcl != "" {
		where = append(where, adminExcl)
	}
	return fmt.Sprintf(
		"SELECT 'role'::text, '%s'::text, ra.%s, 'read'::text\n    FROM %s r\n    JOIN %s ra ON ra.%s = '%s' AND ra.%s IS NULL AND %s\n    WHERE %s",
		rs.KindVal, rs.SubjectCol, obj.Table, rs.Assignments,
		rs.KindCol, rs.KindVal, rs.RevokedCol, strings.Join(scopeConds, " AND "),
		strings.Join(where, " AND ")), true
}

func accessorGenFn(table string, branches []string) GenFn {
	return accessorGenFnNamed(table+"_accessors", branches)
}

func accessorGenFnNamed(name string, branches []string) GenFn {
	return GenFn{
		Name:    name,
		Sig:     "p_id text",
		Returns: "TABLE(source text, principal_kind text, principal_id text, access text)",
		RawBody: true,
		Body:    "  " + strings.Join(branches, "\n  UNION ALL\n  "),
	}
}

func (s *Spec) structuralAccessorDefiner(obj *Object) (GenFn, bool, error) {
	rs := roleStoreByName(s)
	if rs == nil {
		return GenFn{}, false, nil
	}
	var sel *Perm
	for _, pm := range obj.Perms {
		if pm.Maps == "select" {
			sel = pm
			break
		}
	}
	if sel == nil {
		return GenFn{}, false, nil
	}
	rels := map[string]*Relation{}
	for _, r := range obj.Relations {
		rels[r.Name] = r
	}
	presetLevels := presetLevelMap(s)
	rankIdx := rankIndex(s)

	var branches []string
	for _, t := range sel.Expr {
		b, err := s.structuralTermEnum(obj, t, rels, rs, presetLevels, rankIdx)
		if err != nil {
			return GenFn{}, false, err
		}
		branches = append(branches, b...)
	}

	for _, g := range s.Grants {
		if s.levelOnObjectPath(obj, g.Level) {
			branches = append(branches, s.impersonationEnumSQL(obj, g))
		}
	}
	if len(branches) == 0 {
		return GenFn{}, false, nil
	}
	return GenFn{
		Name:    obj.Table + "_accessors",
		Sig:     "p_id text",
		Returns: "TABLE(source text, principal_kind text, principal_id text, access text)",
		RawBody: true,
		Body:    "  " + strings.Join(branches, "\n  UNION\n  "),
	}, true, nil
}

func (s *Spec) structuralTermEnum(obj *Object, t *Term, rels map[string]*Relation, rs *RoleStore, presetLevels map[string][]string, rankIdx map[string]int) ([]string, error) {
	if t.WalkVerb != "" {

		parent := rels[t.Ident]
		if parent == nil {
			return nil, fmt.Errorf("structural accessors: walk references unknown relation %q", t.Ident)
		}
		lvl := parent.Types[0]
		return []string{s.roleEnumSQL(obj, rs, lvl, presetLevels[lvl], "role", "read")}, nil
	}
	if t.Builtin != "" {

		return nil, nil
	}
	r := rels[t.Ident]
	if r == nil {
		return nil, nil
	}
	switch repr := r.Repr.(type) {
	case ViaRole:
		if len(r.Types) > 0 {
			if st := s.subjectByName(r.Types[0]); st != nil && s.isPlatformRoleSubject(st) {

				return []string{s.roleEnumSQL(obj, rs, st.Anchor, presetLevels[st.Anchor], st.Name, "write")}, nil
			}
		}
		objLevel := obj.Scoped[len(obj.Scoped)-1]
		keys := presetLevels[objLevel]
		if repr.HasRank {
			keys = atOrAbove(keys, repr.RankMin, rankIdx)
		}
		return []string{s.roleEnumSQL(obj, rs, objLevel, keys, "role", "read")}, nil
	case ViaMemberIn:

		return []string{s.memberinEnumSQL(obj, rs, repr.Level)}, nil
	}
	return nil, nil
}

func (s *Spec) roleEnumSQL(obj *Object, rs *RoleStore, level string, presets []string, source, access string) string {
	chain, _ := s.Topology.Chain()
	var nonVirtual []string
	for _, l := range chain {
		if !l.Virtual {
			nonVirtual = append(nonVirtual, l.Name)
		}
	}
	onPath := map[string]bool{}
	if path, err := s.Topology.AncestorPath(level); err == nil {
		for _, l := range path {
			onPath[l.Name] = true
		}
	}
	var conds []string
	for i, lvl := range nonVirtual {
		if i >= len(rs.ScopeCols) {
			break
		}
		raCol := rs.ScopeCols[i]
		if onPath[lvl] {
			conds = append(conds, fmt.Sprintf("ra.%s = e.%s", raCol, s.scopeCol(obj, lvl)))
		} else {
			conds = append(conds, fmt.Sprintf("ra.%s IS NULL", raCol))
		}
	}
	join := ""
	if len(presets) > 0 {
		ks := append([]string(nil), presets...)
		sort.Strings(ks)
		q := make([]string, len(ks))
		for i, p := range ks {
			q[i] = "'" + p + "'"
		}
		join = fmt.Sprintf(" JOIN %s rr ON rr.%s = ra.%s AND rr.%s IN (%s)",
			rs.RolesTable, rs.RolesID, rs.RoleCol, rs.KeyCol, strings.Join(q, ", "))
	}
	return fmt.Sprintf(
		"SELECT '%s'::text AS source, '%s'::text AS principal_kind, ra.%s AS principal_id, '%s'::text AS access\n    FROM %s e JOIN %s ra ON ra.%s = '%s' AND ra.%s IS NULL AND %s%s\n    WHERE e.%s = p_id",
		source, rs.KindVal, rs.SubjectCol, access, obj.Table, rs.Assignments,
		rs.KindCol, rs.KindVal, rs.RevokedCol, strings.Join(conds, " AND "), join, obj.pk())
}

func (s *Spec) memberinEnumSQL(obj *Object, rs *RoleStore, level string) string {
	return fmt.Sprintf(
		"SELECT 'role'::text, '%s'::text, ra.%s, 'read'::text\n    FROM %s e JOIN %s ra ON ra.%s = '%s' AND ra.%s IS NULL AND ra.%s = e.%s\n    WHERE e.%s = p_id",
		rs.KindVal, rs.SubjectCol, obj.Table, rs.Assignments, rs.KindCol, rs.KindVal,
		rs.RevokedCol, s.scopeColForLevel(rs, level), s.scopeCol(obj, level), obj.pk())
}

func (s *Spec) impersonationEnumSQL(obj *Object, g *Grant) string {
	conds := []string{fmt.Sprintf("ig.%s = e.%s", g.LevelCol, s.scopeCol(obj, g.Level))}
	if g.ActiveCol != "" {
		conds = append(conds, fmt.Sprintf("ig.%s IS NULL", g.ActiveCol))
	}
	if g.ExpiresCol != "" {
		conds = append(conds, fmt.Sprintf("ig.%s > now()", g.ExpiresCol))
	}

	kind := g.Name
	if rs := roleStoreByName(s); rs != nil {
		kind = rs.KindVal
	}
	return fmt.Sprintf(
		"SELECT '%s'::text, '%s'::text, ig.%s, 'write'::text\n    FROM %s e JOIN %s ig ON %s\n    WHERE e.%s = p_id",
		g.Name, kind, g.GranteeCol, obj.Table, g.Table, strings.Join(conds, " AND "), obj.pk())
}

func (s *Spec) levelOnObjectPath(obj *Object, level string) bool {
	for _, l := range obj.Scoped {
		if l == level {
			return true
		}
	}
	return false
}

func (s *Spec) kernelDefiner(obj *Object) (GenFn, error) {
	var ownerVC *ViaColumn
	for _, r := range obj.Relations {
		if r.Name == "owner" {
			if vc, ok := r.Repr.(ViaColumn); ok {
				vc := vc
				ownerVC = &vc
			}
		}
	}
	if ownerVC == nil {
		return GenFn{}, fmt.Errorf("object %q has a @kernel perm but no owner column", obj.Name)
	}
	principal := s.ownerPrincipalName(obj)
	ownerMatch := fmt.Sprintf("r.%s = p_%s_id", ownerVC.Column, principal)

	if ownerVC.DiscrimCol != "" {
		ownerMatch = fmt.Sprintf("%s AND r.%s = '%s'", ownerMatch, ownerVC.DiscrimCol, ownerVC.DiscrimVal)
	}
	body := fmt.Sprintf("EXISTS (SELECT 1 FROM %s r WHERE r.%s = p_%s_id AND %s)", obj.Table, obj.pk(), obj.Name, ownerMatch)
	return GenFn{
		Name: fmt.Sprintf("%s_can_access_%s", principal, obj.Name),
		Sig:  fmt.Sprintf("p_%s_id text, p_%s_id text, p_access text", principal, obj.Name),
		Body: body,
	}, nil
}

func (s *Spec) scopeColForLevel(rs *RoleStore, level string) string {
	chain, _ := s.Topology.Chain()
	i := 0
	for _, l := range chain {
		if l.Virtual {
			continue
		}
		if l.Name == level {
			if i < len(rs.ScopeCols) {
				return rs.ScopeCols[i]
			}
			break
		}
		i++
	}
	return level + "_id"
}

func roleStoreByName(s *Spec) *RoleStore {
	if len(s.RoleStores) > 0 {
		return s.RoleStores[0]
	}
	return nil
}

func rankIndex(s *Spec) map[string]int {
	for _, v := range s.Vocabs {
		if len(v.Rank) > 0 {
			m := map[string]int{}
			for i, r := range v.Rank {
				m[r] = i
			}
			return m
		}
	}
	return map[string]int{}
}

func presetLevelMap(s *Spec) map[string][]string {
	out := map[string][]string{}
	for _, v := range s.Vocabs {
		for _, p := range v.Presets {
			if p.Level != "" {
				out[p.Level] = append(out[p.Level], p.Name)
			}
		}
	}
	return out
}

func atOrAbove(keys []string, threshold string, rankIdx map[string]int) []string {
	tIdx, ok := rankIdx[threshold]
	if !ok {
		return keys
	}
	var out []string
	for _, k := range keys {
		if ki, ok := rankIdx[k]; ok && ki <= tIdx {
			out = append(out, k)
		}
	}
	return out
}
