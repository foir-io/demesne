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
	presetLevels := presetLevelMap(s)
	seen := map[string]bool{}

	if err := s.defEmitRoleDefiners(&out, seen, rs, presetLevels); err != nil {
		return nil, err
	}
	s.defEmitPlatformRoles(&out, seen, rs, presetLevels)
	s.defEmitScopedMemberin(&out, seen, rs, presetLevels)
	if err := s.defEmitHoldsPerm(&out, seen); err != nil {
		return nil, err
	}
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
	if err := s.defEmitPermissionExports(&out, virtual); err != nil {
		return nil, err
	}

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
		*out = append(*out, GenFn{Name: m.FlagCol, Sig: "user_id " + s.idType(), Body: body})
	}
	return nil
}

func (s *Spec) defEmitGrantReach(out *[]GenFn) {
	gseen := map[string]bool{}
	for _, g := range s.Grants {
		if g.ClaimKey != "" {
			continue
		}
		name := g.definerBase() + "_reach"
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
		scoped := append(append([]string(nil), conj...), s.grantSessionScopeConjuncts(g)...)
		*out = append(*out, GenFn{Name: name, Sig: fmt.Sprintf("user_id %s, check_%s_id %s", s.idType(), g.Level, s.idType()), Body: grantEdgeExists(g.Table, scoped...)})

		// THE SET FORM, and why both are emitted.
		//
		// The scalar above answers "does this grantee reach THIS value" and is
		// what another definer's body wants, where the value is a parameter and
		// the call happens once. It is the wrong shape for an RLS predicate: a
		// SECURITY DEFINER carrying a SET clause cannot be inlined — each blocks
		// it independently — so spliced into a policy it is re-entered once per
		// candidate row.
		//
		// The set form answers "what does this grantee reach" and is spliced as
		// `<col> IN (SELECT …)`, which the planner resolves ONCE as a hashed
		// subplan. The two are semantically identical —
		//
		//	EXISTS (SELECT 1 FROM T WHERE grantee = $1 AND level = row)
		//	  ≡  row IN (SELECT level FROM T WHERE grantee = $1)
		//
		// — so this is an emission choice and not a change of meaning.
		//
		// MEASURED, on a 200k-row table behind a 425-node closure: an ordered
		// page cost 683ms under the scalar probe and 58ms under this, because
		// the filter runs on every row a sort has to consider and `LIMIT` cannot
		// short-circuit it. The cost is linear in rows examined, so it grows with
		// the data rather than with the grant.
		//
		// It is unconditional because a grant edge is an access-control list: it
		// maps ONE grantee to what it may reach, and that set is small by
		// construction in any domain. Nothing here assumes a hierarchy.
		setConj := []string{fmt.Sprintf("%s = user_id", g.GranteeCol)}
		setConj = append(setConj, scoped[2:]...)
		*out = append(*out, GenFn{
			Name:    name + "_set",
			Sig:     fmt.Sprintf("user_id %s", s.idType()),
			Returns: "SETOF " + s.idType(),
			Body:    fmt.Sprintf("%s FROM %s WHERE %s", g.LevelCol, g.Table, strings.Join(setConj, " AND ")),
		})
		*out = append(*out, s.grantScopeDefiners(g, conj)...)
	}
}

func (s *Spec) defEmitRoleDefiners(out *[]GenFn, seen map[string]bool, rs *RoleStore, presetLevels map[string][]string) error {
	for _, obj := range s.Objects {
		rels := map[string]*Relation{}
		for _, r := range obj.Relations {
			rels[r.Name] = r
		}
		for _, pm := range obj.Perms {
			for _, t := range pm.Expr {
				d, ok, err := s.roleDefinerForTerm(obj, pm, t, rels, rs, presetLevels)
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

func (s *Spec) defEmitScopedMemberin(out *[]GenFn, seen map[string]bool, rs *RoleStore, presetLevels map[string][]string) {
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			mi, ok := r.Repr.(ViaMemberIn)
			if !ok || rs == nil {
				continue
			}
			name := fmt.Sprintf("%s_memberin_%s", s.adminName(), mi.Level)
			if !seen[name] {
				seen[name] = true
				sCol := s.scopeColForLevel(rs, mi.Level)
				conds := []string{
					fmt.Sprintf("%s = p_principal", rs.SubjectCol),
					fmt.Sprintf("%s = p_%s", sCol, mi.Level),
				}
				conds = append(conds, rs.kindCond("")...)
				conds = append(conds, rs.revokedCond("")...)
				body := fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s)",
					rs.Assignments, strings.Join(conds, " AND "))
				*out = append(*out, GenFn{Name: name, Sig: fmt.Sprintf("p_principal %s, p_%s %s", s.idType(), mi.Level, s.idType()), Body: body})
			}
			if mi.ReachedBy && !mi.ReachMember {
				s.defEmitReachChain(out, seen, rs, presetLevels, mi.Level)
			}
		}
	}
}

func (s *Spec) defEmitHoldsPerm(out *[]GenFn, seen map[string]bool) error {
	for _, obj := range s.Objects {
		for _, pm := range obj.Perms {
			for _, t := range pm.Expr {
				if t == nil || t.Builtin != "holds" {
					continue
				}
				if err := s.defAddHoldsPerm(out, seen, obj, pm, t); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Spec) defAddHoldsPerm(out *[]GenFn, seen map[string]bool, obj *Object, pm *Perm, t *Term) error {
	rs, err := s.holdsRoleStore(t.HoldsPerm)
	if err != nil {
		return fmt.Errorf("object %q permission %q uses @holds(%q): %w", obj.Name, pm.Verb, t.HoldsPerm, err)
	}
	if rs.PermsCol == "" {
		return fmt.Errorf("object %q permission %q uses @holds(%q) but rolestore %q declares no `permissions` column", obj.Name, pm.Verb, t.HoldsPerm, rs.Name)
	}
	name := s.holdsPermFn(rs)
	if seen[name] {
		return nil
	}
	seen[name] = true
	impliedBy := ""
	if vocab, verr := s.rolestoreVocab(rs); verr == nil && len(vocab.Implications) > 0 {
		fn, ferr := s.permImpliedByDefiner(rs, vocab)
		if ferr != nil {
			return ferr
		}
		impliedBy = fn.schema() + "." + fn.Name
		*out = append(*out, fn)
	}
	*out = append(*out, s.holdsPermDefiner(name, rs, impliedBy))
	return nil
}

func (s *Spec) holdsPermDefiner(name string, rs *RoleStore, impliedByFn string) GenFn {
	chain, _ := s.Topology.Chain()
	planeDepth := s.rolestorePlaneDepth(rs)
	args := []string{"user_id " + s.idType()}
	var scope []string
	i := 0
	for _, l := range chain {
		if l.Virtual {
			continue
		}
		if i >= len(rs.ScopeCols) {
			break
		}
		col := rs.ScopeCols[i]
		if i < planeDepth {
			arg := "check_" + l.Name + "_id"
			args = append(args, arg+" "+s.idType())
			scope = append(scope, fmt.Sprintf("(ra.%s IS NULL OR ra.%s = %s)", col, col, arg))
		} else {
			scope = append(scope, fmt.Sprintf("ra.%s IS NULL", col))
		}
		i++
	}
	args = append(args, "p_perm text")
	conds := rs.kindCond("ra.")
	conds = append(conds, fmt.Sprintf("ra.%s = user_id", rs.SubjectCol))
	conds = append(conds, scope...)
	conds = append(conds, rs.revokedCond("ra.")...)
	conds = append(conds, holdsPermCond(rs.PermsCol, impliedByFn))
	body := fmt.Sprintf(
		"EXISTS (SELECT 1 FROM %s ra JOIN %s r ON r.%s = ra.%s WHERE %s)",
		rs.Assignments, rs.RolesTable, rs.RolesID, rs.RoleCol, strings.Join(conds, " AND "))
	return GenFn{Name: name, Sig: strings.Join(args, ", "), Body: body}
}

func holdsPermCond(permsCol, impliedByFn string) string {
	if impliedByFn == "" {
		return fmt.Sprintf("p_perm = ANY(r.%s)", permsCol)
	}
	return fmt.Sprintf("r.%s::text[] && %s(p_perm)", permsCol, impliedByFn)
}

func (s *Spec) permImpliedByDefiner(rs *RoleStore, vocab *Vocabulary) (GenFn, error) {
	impliers := map[string][]string{}
	for _, p := range vocab.Permissions {
		implied, err := vocab.ImpliedPermissions(p)
		if err != nil {
			return GenFn{}, err
		}
		for _, target := range implied {
			impliers[target] = append(impliers[target], p)
		}
	}
	rows := make([]string, 0, len(vocab.Permissions))
	for _, p := range vocab.Permissions {
		set := impliers[p]
		sort.Strings(set)
		lits := make([]string, 0, len(set))
		for _, q := range set {
			lits = append(lits, "'"+q+"'")
		}
		rows = append(rows, fmt.Sprintf("('%s', ARRAY[%s]::text[])", p, strings.Join(lits, ", ")))
	}
	body := fmt.Sprintf(
		"COALESCE((SELECT m.impliers FROM (VALUES %s) AS m(perm, impliers) WHERE m.perm = p_perm), ARRAY[p_perm]::text[])",
		strings.Join(rows, ", "))
	return GenFn{
		Name:    s.permImpliedByFn(rs),
		Sig:     "p_perm text",
		Returns: "text[]",
		Body:    body,
	}, nil
}

func (s *Spec) defEmitReachChain(out *[]GenFn, seen map[string]bool, rs *RoleStore, presetLevels map[string][]string, level string) {
	path, err := s.Topology.AncestorPath(level)
	if err != nil {
		return
	}
	for _, lvl := range path {
		if lvl.Virtual {
			continue
		}
		fn := fmt.Sprintf("is_%s_%s", lvl.Name, s.adminName())
		if seen[fn] {
			continue
		}
		seen[fn] = true
		*out = append(*out, s.roleDefiner(fn, rs, lvl.Name, presetLevels[lvl.Name], s.operatorReach(lvl.Name)))
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
			body := grantEdgeExists(vg.Table, conjuncts...)
			// The membership hop: a grant row naming a GROUP admits everyone
			// the closure lists as its member. ORed into every kind's definer
			// rather than gated per kind, because membership itself is the
			// restriction — the closure's member column decides who is in.
			if vg.GroupClosure != "" {
				body += " OR " + grantGroupExists(vg, obj, param)
			}
			*out = append(*out, GenFn{
				Name: name,
				Sig:  fmt.Sprintf("p_%s_id text, p_%s_id text, p_access text", param, obj.Name),
				Body: body,
			})
		}
	}
}

func (s *Spec) defEmitAccessors(out *[]GenFn, seen map[string]bool) error {
	for _, obj := range s.Objects {
		if _, vg := grantRelation(obj); vg == nil {
			continue
		}
		cond := s.conditionalAccessors(obj)
		name := obj.Table + "_accessors"
		if len(cond) > 0 {
			name = obj.Table + "_accessors_conditional"
		}
		if seen[name] {
			continue
		}

		if ok, reason := s.accessorCoverage(obj); !ok {
			return fmt.Errorf("object %q: cannot soundly enumerate accessors (auth.%s would under-report) — %s", obj.Name, name, reason)
		}
		seen[name] = true
		*out = append(*out, s.accessorDefiners(obj, cond)...)
	}
	return nil
}

func accessorReprCovered(r Repr) bool {
	switch repr := r.(type) {
	case ViaClosure:
		return repr.Claim == ""
	case ViaColumn, ViaGrant, ViaRole, ViaGroup, ViaComposition:
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

		if _, err := s.accessorTreeSQL(obj, sel.Tree, rels); err != nil {
			return false, err.Error()
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
	// The borrow is compiled as a LATERAL call to the other object's plain
	// enumerator. An object that admits readers by a claim does not have one,
	// and its conditional enumerator cannot stand in: the claim would have to
	// travel outwards as a condition on THIS object's listing, which is a
	// different function signature and a different question. Refuse instead of
	// borrowing the identity half and losing the rest.
	if cond := s.conditionalAccessors(other); len(cond) > 0 {
		return false, fmt.Sprintf("borrowed object %q admits readers its enumeration cannot name (%s), so it enumerates conditionally and has no plain accessor to borrow", vo.Object, admissionNames(cond))
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
		switch repr := r.Repr.(type) {
		case ViaRole:
		case ViaMemberIn:
			if repr.ReachedBy {
				return false, fmt.Sprintf("relation %q is `memberin ... reachedby` — the caller-reach gate is not expressible in the structural enumerator, so reverse queries over it are unsupported (the RLS floor still enforces it)", t.Ident)
			}
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
			name := vo.functionName()
			if seen[name] {
				continue
			}
			seen[name] = true
			other := s.objectByName(vo.Object)
			if other == nil {
				return fmt.Errorf("relation %q references unknown object %q", r.Name, vo.Object)
			}
			pred, err := s.objectVerbPredicateFor(other, vo.Verb, vo.Op, virtual)
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
			return s.permPredicate(obj, pm, cust, virtual)
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
			Sig:  "p_type text, p_id " + s.idType(),
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
				Sig:  "p_id " + s.idType(),
				Body: fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s.%s = p_id AND (%s))", o.Table, o.Table, o.pk(), pred),
			})
		}
		whens = append(whens, fmt.Sprintf("WHEN '%s' THEN %s.%s(p_id)", objectGrantEdge(o).DiscrimVal, s.definerSchema(), canEdit))
	}
	return whens, nil
}

func (s *Spec) roleDefinerForTerm(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, rs *RoleStore, presetLevels map[string][]string) (GenFn, bool, error) {
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
	if _, ok := r.Repr.(ViaRole); !ok {
		return GenFn{}, false, nil
	}

	if len(r.Types) > 0 {
		if st := s.subjectByName(r.Types[0]); st != nil && s.isPlatformRoleSubject(st) {
			return GenFn{}, false, nil
		}
	}
	objLevel := obj.Scoped[len(obj.Scoped)-1]
	keys := presetLevels[objLevel]
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

	args := []string{"user_id " + s.idType()}
	var scope []string
	for i, lvl := range nonVirtual {
		if i >= len(rs.ScopeCols) {
			break
		}
		col := rs.ScopeCols[i]
		if onPath[lvl] {
			arg := "check_" + lvl + "_id"
			args = append(args, arg+" "+s.idType())
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
	conds := rs.kindCond("ra.")
	conds = append(conds, fmt.Sprintf("ra.%s = user_id", rs.SubjectCol))
	conds = append(conds, scope...)
	conds = append(conds, rs.revokedCond("ra.")...)
	conds = append(conds, fmt.Sprintf("r.%s IN (%s)", rs.KeyCol, strings.Join(quoted, ", ")))
	exists := fmt.Sprintf(
		"EXISTS (SELECT 1 FROM %s ra JOIN %s r ON r.%s = ra.%s WHERE %s)",
		rs.Assignments, rs.RolesTable, rs.RolesID, rs.RoleCol, strings.Join(conds, " AND "))
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
				return fmt.Sprintf("%s_reach(user_id, check_%s_id)", g.definerBase(), g.Level)
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

	// ONE PATH, TWO SHAPES OF THE SAME WALK.
	//
	// A permission carrying `and`/`not` composes into a single SQL expression
	// (intersections and subtractions cannot be a union of independent
	// branches); a pure `+` chain is a union of per-relation branches. That much
	// is irreducible. What is NOT irreducible is what used to follow: the tree
	// shape returned here and skipped everything below, so an object with one
	// `and` anywhere in its read silently lost its ROLE branch and could not
	// carry a COMPOSITION relation at all.
	//
	// Neither of those is a property of the permission's shape. The role branch
	// is gated on the object's rolestore and its use of @app_scope; composition
	// needs the direct/full split whatever the rest of the permission looks
	// like. They belong to the tail both shapes share, which is where they are
	// now — so the two shapes differ only in how the relational terms compose,
	// and in nothing else.
	var branches []string
	var adminExcl string
	composedTree := false

	if sel != nil && accessorTreeOp(sel.Tree) != "" {
		if composed, err := s.accessorTreeSQL(obj, sel.Tree, rels); err == nil {
			branches = append(branches, composed)
			composedTree = true
		}
	}

	if sel != nil {
		adminExcl = defAdminExclCond(sel, rels)
		// The composed expression already carries every relational term, so the
		// per-relation builders would union them in a second time.
		if !composedTree {
			branches = append(branches, defOwnerAccessorBranches(obj, sel, rels)...)
		}
	}

	if !composedTree {
		if _, vg := grantRelation(obj); vg != nil {
			branches = append(branches, grantAccessorBranch(vg))
		}
	}

	// Shared by both shapes from here down.
	if rb, ok := s.roleAccessorBranch(obj, adminExcl); ok {
		branches = append(branches, rb)
	}

	if !composedTree {
		branches = append(branches, s.defGroupAccessorBranches(obj, sel, rels)...)
		branches = append(branches, defClosureAccessorBranches(obj, sel, rels)...)
		branches = append(branches, s.defObjectAccessorBranches(obj, sel, rels)...)
	}

	comp := s.defCompositionAccessorBranches(obj, sel, rels)
	if len(comp) == 0 {
		return []GenFn{accessorGenFn(obj.Table, s.idType(), branches)}
	}
	direct := accessorGenFnNamed(obj.Table+"_direct_accessors", s.idType(), branches)
	full := accessorGenFn(obj.Table, s.idType(), append(
		[]string{fmt.Sprintf("SELECT d.source, d.principal_kind, d.principal_id, d.access FROM %s.%s_direct_accessors(p_id) d", s.definerSchema(), obj.Table)},
		comp...))
	return []GenFn{direct, full}
}

func admissionNames(adms []conditionalAdmission) string {
	seen := map[string]bool{}
	var out []string
	for _, a := range adms {
		n := a.Source
		if a.ClaimKey != "" {
			n += " " + a.ClaimKey
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return strings.Join(out, ", ")
}

func sqlTextOrNull(v string) string {
	if v == "" {
		return "NULL::text"
	}
	return "'" + v + "'::text"
}

// accessorDefiners wraps the enumerator in its conditional form when the
// object's read admits a claim, and otherwise returns it unchanged.
func (s *Spec) accessorDefiners(obj *Object, cond []conditionalAdmission) []GenFn {
	fns := s.pureAccessorDefiners(obj)
	if len(cond) == 0 || len(fns) == 0 {
		return fns
	}
	// pureAccessorDefiners returns either one function or a _direct_accessors
	// pair whose second element is the composed whole. The conditional shape
	// belongs on whichever one callers name, which is the last.
	fns[len(fns)-1] = s.conditionalAccessorGenFn(obj, fns[len(fns)-1], cond)
	return fns
}

// conditionalAccessorGenFn rebuilds the enumerator as
// auth.<table>_accessors_conditional: the identity rows it already produced,
// widened with two null columns, then one row per admitting claim.
//
// A claim row carries a NULL principal on purpose. The alternatives were worse.
// A sentinel principal ("everyone", a nil UUID) renders as a person in any
// caller that does not know to look for it, which is the failure this is meant
// to prevent, dressed up as a feature. Leaving the claim out and adding a
// boolean beside the function is something a caller can ignore without ever
// writing a line of code acknowledging it. A NULL principal cannot be rendered
// as a person or ignored: it is missing data in the column the caller reads,
// and the two claim columns say exactly what is missing and why.
func (s *Spec) conditionalAccessorGenFn(obj *Object, base GenFn, adms []conditionalAdmission) GenFn {
	idT := s.idType()
	branches := []string{fmt.Sprintf(
		"SELECT b.source, b.principal_kind, b.principal_id, b.access, NULL::text AS via_claim_key, NULL::text AS via_claim_value\n    FROM (\n%s\n    ) b(source, principal_kind, principal_id, access)",
		base.Body)}
	for _, a := range adms {
		// FROM the table, so an id that names no row still enumerates to
		// nothing — the plain enumerator's behaviour, which callers rely on to
		// tell "no readers" from "no such row" the same way they always have.
		// A term with a row-side test adds it here, so its row appears only
		// when the row really does admit that way.
		//
		// 'read' is not a guess: conditionalAccessors only ever looks at the
		// permission that maps to SELECT.
		where := obj.pk() + " = p_id"
		if a.RowCond != "" {
			where += " AND " + a.RowCond
		}
		branches = append(branches, fmt.Sprintf(
			"SELECT '%s'::text, %s, NULL::%s, 'read'::text, %s, %s\n    FROM %s WHERE %s",
			a.Source, sqlTextOrNull(a.PrincipalKind), idT,
			sqlTextOrNull(a.ClaimKey), sqlTextOrNull(a.ClaimVal),
			obj.Table, where))
	}
	return GenFn{
		Name:    obj.Table + "_accessors_conditional",
		Sig:     "p_id " + idT,
		Returns: "TABLE(source text, principal_kind text, principal_id " + idT + ", access text, via_claim_key text, via_claim_value text)",
		RawBody: true,
		Body:    "  " + strings.Join(branches, "\n  UNION ALL\n  "),
	}
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

func (s *Spec) accessorBranchForTerm(obj *Object, t *Term, rels map[string]*Relation) (string, error) {
	if t == nil {
		return "", fmt.Errorf("empty term in the SELECT permission tree")
	}
	if t.Builtin == "claim" {
		return "", fmt.Errorf("term %q is a condition on the request, not a subject, so it cannot be a branch of an accessor union; a claim can only narrow a conjunction or widen a disjunct (which makes the object enumerate conditionally) — it cannot be negated or nested where neither applies", t.String())
	}
	if t.Ident == "" {
		return "", fmt.Errorf("term %q has no accessor branch (only owner/grant/group/closure/object relation leaves enumerate)", t.String())
	}

	name := t.Ident
	if rn, _, ok := grantSelector(t.Ident, rels); ok {
		name = rn
	}
	r := rels[name]
	if r == nil {
		return "", fmt.Errorf("term %q names no relation the accessor enumerator can reverse", t.Ident)
	}
	kind := ""
	if len(r.Types) > 0 {
		kind = r.Types[0]
	}
	switch repr := r.Repr.(type) {
	case ViaColumn:
		return ownerAccessorBranch(obj.Table, obj.pk(), kind, repr, false), nil
	case ViaGrant:
		return grantAccessorBranch(&repr), nil
	case ViaGroup:
		return groupAccessorBranch(obj.Table, obj.pk(), kind, repr, s.groupFlatName(obj, r, repr)), nil
	case ViaClosure:
		if repr.Claim != "" {
			return "", fmt.Errorf("relation %q is confined by the caller's %q claim, which names no principal to enumerate", name, repr.Claim)
		}
		return closureAccessorBranch(obj.Table, obj.pk(), kind, repr), nil
	case ViaObject:
		if ok, reason := s.viaObjectCovered(repr, map[string]bool{}); !ok {
			return "", fmt.Errorf("relation %q borrows %s->%s, not soundly enumerable (%s)", name, repr.Object, repr.Verb, reason)
		}
		other := s.objectByName(repr.Object)
		if other == nil {
			return "", fmt.Errorf("relation %q borrows unknown object %q", name, repr.Object)
		}
		return objectAccessorBranch(obj.Table, obj.pk(), repr, other.Table, s.definerSchema()), nil
	}
	return "", fmt.Errorf("relation %q (%T) has no accessor branch (only owner/grant/group/closure/object leaves compose)", name, r.Repr)
}

func (s *Spec) accessorTreeSQL(obj *Object, n *PermNode, rels map[string]*Relation) (string, error) {
	if n == nil {
		return "", fmt.Errorf("empty permission tree")
	}
	switch n.Op {
	case "leaf":
		return s.accessorBranchForTerm(obj, n.Term, rels)
	case "or":
		var parts []string
		for _, k := range n.Kids {
			// A conditional disjunct is not a branch of this union — it names
			// no principal to select. It is not being dropped either:
			// conditionalAccessors reports it and the object emits the
			// conditional enumerator, which carries it as its own row.
			if s.isConditionalLeaf(obj, k, rels) {
				continue
			}
			if _, ok := s.conditionalConjunction(obj, k, rels); ok {
				continue
			}
			if isCompositionLeaf(k, rels) {
				continue
			}
			sql, err := s.accessorTreeSQL(obj, k, rels)
			if err != nil {
				return "", err
			}
			parts = append(parts, "("+sql+")")
		}
		if len(parts) == 0 {
			return "", fmt.Errorf("empty union in the SELECT permission tree")
		}
		return strings.Join(parts, "\n  UNION ALL\n  "), nil
	case "and":
		return s.accessorAndSQL(obj, n, rels)
	}
	return "", fmt.Errorf("permission node %q is not enumerable", n.Op)
}

// A claim-side builtin conjunct is enforced by the forward RLS predicate;
// dropping it from the reverse enumeration can only over-report, never
// under-report, so the accessor stays sound.
//
// The direction is the whole argument, and it is worth stating plainly because
// the same term in the other position is the one case this engine cannot
// enumerate at all. A conjunct NARROWS: drop it and the listing grows, which
// costs precision and nothing else. A disjunct WIDENS: drop it and the listing
// misses people who can read the row. See conditionalAccessors for what happens
// to a claim that arrives on the widening side.
// narrowingAccessorLeaf is a conjunct the reverse enumeration may drop: the
// claim-side builtins, and a mode leaf, which tests the ROW rather than the
// request but narrows just the same. Dropping either over-reports and never
// under-reports.
func narrowingAccessorLeaf(n *PermNode) bool {
	if claimNeutralAccessorLeaf(n) {
		return true
	}
	return n != nil && n.Op == "leaf" && n.Term != nil && n.Term.ModeCol != ""
}

func claimNeutralAccessorLeaf(n *PermNode) bool {
	if n == nil || n.Op != "leaf" || n.Term == nil {
		return false
	}
	switch n.Term.Builtin {
	case "kind", "app_scope", "session", "within", "scoped", "holds", "claim":
		return true
	}
	return false
}

// isClaimLeaf is the bare question "is this node a @claim?", with none of the
// object context isConditionalLeaf needs. Used where the answer does not depend
// on where the claim sits — a negated claim is unreversible wherever it is.
func isClaimLeaf(n *PermNode) bool {
	return n != nil && n.Op == "leaf" && n.Term != nil && n.Term.Builtin == "claim"
}

// conditionalAdmission is a disjunct admitting readers the enumeration cannot
// name: it becomes one row of <table>_accessors_conditional.
type conditionalAdmission struct {
	// Source is the row's `source` label — 'claim', 'app_scope', 'mode'.
	Source string
	// PrincipalKind is filled when the term narrows to one kind of caller and
	// left empty when it admits any. Only the ID is ever unknowable.
	PrincipalKind string
	// ClaimKey/ClaimVal are populated for @claim and empty otherwise.
	ClaimKey, ClaimVal string
	// RowCond is the part of the term that tests the ROW rather than the
	// request, so the row only appears when it actually holds. A mode term is
	// entirely row-side; @app_scope is row-side only in its exclusion.
	RowCond string
}

// conditionalTerm classifies one disjunct. ok is false for a term the
// enumeration already covers with a branch of its own.
func (s *Spec) conditionalTerm(obj *Object, t *Term, rels map[string]*Relation) (conditionalAdmission, bool) {
	if t == nil {
		return conditionalAdmission{}, false
	}
	switch {
	case t.Builtin == "claim":
		return conditionalAdmission{Source: "claim", ClaimKey: t.ClaimKey, ClaimVal: t.ClaimVal}, true

	case t.ModeCol != "":
		// A mode term is a pure row test plus, with `for <subject>`, a plane.
		// The row test anchors the row; the plane names the kind.
		return conditionalAdmission{
			Source:        "mode",
			PrincipalKind: t.ModeScope,
			RowCond:       fmt.Sprintf("%s = '%s'", t.ModeCol, t.ModeVal),
		}, true

	case t.Builtin == "app_scope":
		// @app_scope admits every caller presenting no subject claim. Some of
		// them are nameable and are already listed — roleAccessorBranch is
		// gated on this very term and enumerates the role assignments. The rest
		// are not: a trusted caller with no assignment anywhere satisfies the
		// term and appears in no table. This row is that remainder, which is
		// why it stands beside the role branch rather than replacing it.
		a := conditionalAdmission{Source: "app_scope"}
		var conds []string
		for _, ex := range t.ExcludeRels {
			r := rels[ex]
			if r == nil {
				continue
			}
			vc, ok := r.Repr.(ViaColumn)
			if !ok {
				continue
			}
			if vc.DiscrimCol != "" {
				conds = append(conds, fmt.Sprintf("%s IS DISTINCT FROM '%s'", vc.DiscrimCol, vc.DiscrimVal))
			} else {
				conds = append(conds, fmt.Sprintf("%s IS NULL", vc.Column))
			}
		}
		// Every exclusion, not just the first: the row this contributes is the
		// remainder the plane admits, so an anchor that dropped one would put a
		// row in the listing for a row the plane does not in fact admit.
		a.RowCond = strings.Join(conds, " AND ")
		return a, true
	}
	return conditionalAdmission{}, false
}

// conditionalConjunction reports whether n is an `and` that admits readers the
// enumeration cannot name, and folds it into the single row that says so.
//
// v0.85.0 handled a conditional term standing alone on a disjunct. A conjunction
// of ONLY such terms — `(@app_scope and @kind("service"))`, `(@app_scope and not
// @claim(...))` — fell through to accessorAndSQL, which looks for a relational
// term to enumerate from, finds none, and refuses. That refusal is wrong: the
// conjunction is a perfectly ordinary admission, it simply names no subject, and
// "names no subject" is the case the conditional enumerator exists for.
//
// The fold: the SOURCE comes from the term that admits, since the others only
// narrow it, and every row-side condition is ANDed into the anchor so the row
// appears exactly where the conjunction does. A `not` kid contributes no anchor
// — it subtracts on the request side, which is the part no query can express,
// and that is precisely why the row is conditional rather than enumerated.
func (s *Spec) conditionalConjunction(obj *Object, n *PermNode, rels map[string]*Relation) (conditionalAdmission, bool) {
	if n == nil || n.Op != "and" || len(n.Kids) == 0 {
		return conditionalAdmission{}, false
	}
	var admit conditionalAdmission
	var conds []string
	found := false

	for _, k := range n.Kids {
		// A negated narrowing or conditional kid subtracts on the REQUEST side.
		// There is nothing to anchor on, and that is exactly why the row this
		// produces is conditional rather than enumerated.
		if k.Op == "not" && len(k.Kids) == 1 &&
			(narrowingAccessorLeaf(k.Kids[0]) || s.isConditionalLeaf(obj, k.Kids[0], rels)) {
			continue
		}
		if k.Op != "leaf" {
			return conditionalAdmission{}, false
		}
		if a, ok := s.conditionalTerm(obj, k.Term, rels); ok {
			// The first admitting term names the row. A second one only adds
			// its anchor: two admissions ANDed are one admission narrowed.
			if !found {
				admit, found = a, true
			} else if a.RowCond != "" {
				conds = append(conds, a.RowCond)
			}
			continue
		}
		// A narrowing leaf qualifies the admission and contributes no branch.
		// Anything else is relational, which means the conjunction IS
		// enumerable and must not be folded away.
		if !narrowingAccessorLeaf(k) {
			return conditionalAdmission{}, false
		}
	}

	if !found {
		return conditionalAdmission{}, false
	}
	if admit.RowCond != "" {
		conds = append([]string{admit.RowCond}, conds...)
	}
	admit.RowCond = strings.Join(conds, " AND ")
	return admit, true
}

// isCompositionLeaf reports whether n names a composition relation.
//
// Composition is emitted by the TAIL both permission shapes share, because it
// needs the <table>_direct_accessors split to stay free of recursion — a
// property of the relation, not of the permission it appears in. So the tree
// walk skips it on a DISJUNCT and lets the tail add its arm, exactly as the
// flat shape does.
//
// Only on a disjunct. Inside an `and` the tail cannot reproduce the semantics —
// a union arm added afterwards is not an intersection — so it still refuses
// there, which is the honest answer rather than a quietly wrong one.
func isCompositionLeaf(n *PermNode, rels map[string]*Relation) bool {
	if n == nil || n.Op != "leaf" || n.Term == nil || n.Term.Ident == "" {
		return false
	}
	r := rels[n.Term.Ident]
	if r == nil {
		return false
	}
	_, ok := r.Repr.(ViaComposition)
	return ok
}

func (s *Spec) isConditionalLeaf(obj *Object, n *PermNode, rels map[string]*Relation) bool {
	if n == nil || n.Op != "leaf" {
		return false
	}
	_, ok := s.conditionalTerm(obj, n.Term, rels)
	return ok
}

// conditionalAccessors reports the @claim terms in obj's SELECT permission that
// ADD authority: the ones sitting on a disjunct, where they admit callers no
// other branch admits.
//
// Such a term is why an object cannot have a plain accessor enumerator. Every
// other leaf names a SUBJECT and so can be read backwards off a row — an
// owner column, a grant table, a membership, a borrowed object. A claim names
// a CONDITION on the request. Nothing in the database records who satisfies it,
// so no query over the row can list them, and a listing that quietly leaves
// them out is not a smaller truth but a wrong answer: it says "these are the
// people who can read this" when the real answer is "these, plus anyone whose
// request carries this claim".
//
// An object with one of these emits auth.<table>_accessors_conditional instead
// of auth.<table>_accessors, so the caller has to look at the claim columns and
// decide what to do about them. A caller that has not been updated asks for a
// function that is not there, which is a loud failure rather than a plausible
// and incomplete list.
func (s *Spec) conditionalAccessors(obj *Object) []conditionalAdmission {
	sel := objectSelectPerm(obj)
	if sel == nil {
		return nil
	}
	rels := map[string]*Relation{}
	for _, r := range obj.Relations {
		rels[r.Name] = r
	}
	// Mirror how pureAccessorDefiners chooses its path, so the two cannot
	// disagree about which disjuncts the emitted union already accounts for.
	if accessorTreeOp(sel.Tree) != "" {
		return s.addingConditionalTerms(obj, sel.Tree, rels)
	}
	var out []conditionalAdmission
	for _, t := range sel.Expr {
		if a, ok := s.conditionalTerm(obj, t, rels); ok {
			out = append(out, a)
		}
	}
	return out
}

func (s *Spec) addingConditionalTerms(obj *Object, n *PermNode, rels map[string]*Relation) []conditionalAdmission {
	if n == nil {
		return nil
	}
	switch n.Op {
	case "leaf":
		if a, ok := s.conditionalTerm(obj, n.Term, rels); ok {
			return []conditionalAdmission{a}
		}
		return nil
	case "not":
		// A negated subtree subtracts authority, so nothing inside it widens
		// the accessor set.
		return nil
	case "and":
		// A conjunction of only conditional terms is ONE admission that names
		// nobody, not a refusal — see conditionalConjunction.
		if a, ok := s.conditionalConjunction(obj, n, rels); ok {
			return []conditionalAdmission{a}
		}
		// Otherwise a conjunct narrows, and a narrowing leaf is simply dropped —
		// that can only add names to the listing, which is the safe direction.
		// But a conjunct may itself contain a disjunction, and a conditional
		// term inside THAT still widens, so the rest of the kids are walked.
		var out []conditionalAdmission
		for _, k := range n.Kids {
			if narrowingAccessorLeaf(k) {
				continue
			}
			out = append(out, s.addingConditionalTerms(obj, k, rels)...)
		}
		return out
	}
	var out []conditionalAdmission
	for _, k := range n.Kids {
		out = append(out, s.addingConditionalTerms(obj, k, rels)...)
	}
	return out
}

func objectSelectPerm(obj *Object) *Perm {
	for _, pm := range obj.Perms {
		if pm.Maps == "select" {
			return pm
		}
	}
	return nil
}

func (s *Spec) accessorAndSQL(obj *Object, n *PermNode, rels map[string]*Relation) (string, error) {
	var positives, negatives []*PermNode
	var dropped []string
	for _, k := range n.Kids {
		switch {
		case k.Op == "not":
			if len(k.Kids) != 1 {
				return "", fmt.Errorf("malformed negation in the SELECT permission tree")
			}
			// A negated CLAIM is dropped rather than reversed. Dropping any
			// conjunct over-reports and never under-reports, and reversing this
			// one is not merely hard but meaningless: a claim names a condition
			// on the request, so "everyone who does NOT satisfy it" is no more
			// enumerable than everyone who does.
			//
			// DELIBERATELY ONLY A CLAIM, though the over-report argument would
			// cover every narrowing leaf. The other members of that set are
			// coupled to branch generation in a way a claim is not — the role
			// branch exists only because @app_scope is present
			// (roleAccessorBranch is gated on selectUsesAppScope), so negating
			// it is not a conjunct that can simply be lifted out. A claim
			// generates no branch at all, so nothing downstream changes shape
			// when it goes. Widening this to the rest would also turn an
			// existing refusal into an emission for specs that rely on it.
			if isClaimLeaf(k.Kids[0]) {
				dropped = append(dropped, "not "+k.Kids[0].Term.String())
				continue
			}
			negatives = append(negatives, k.Kids[0])
		case narrowingAccessorLeaf(k):
			dropped = append(dropped, k.Term.String())
		default:
			positives = append(positives, k)
		}
	}
	if len(positives) == 0 {
		if len(dropped) > 0 {
			return "", fmt.Errorf("a conjunction of only narrowing terms (%s) leaves no relational term to enumerate", strings.Join(dropped, ", "))
		}
		return "", fmt.Errorf("a conjunction needs a positive relational term to enumerate")
	}
	base, err := s.accessorTreeSQL(obj, positives[0], rels)
	if err != nil {
		return "", err
	}
	idIn := func(sub string) string {
		return fmt.Sprintf("(a.principal_kind, a.principal_id) IN (SELECT b.principal_kind, b.principal_id FROM (%s) b(source, principal_kind, principal_id, access))", sub)
	}
	idNotIn := func(sub string) string {
		return fmt.Sprintf("(a.principal_kind, a.principal_id) NOT IN (SELECT b.principal_kind, b.principal_id FROM (%s) b(source, principal_kind, principal_id, access))", sub)
	}
	var filters []string
	for _, p := range positives[1:] {
		sub, err := s.accessorTreeSQL(obj, p, rels)
		if err != nil {
			return "", err
		}
		filters = append(filters, idIn(sub))
	}
	for _, ng := range negatives {
		sub, err := s.accessorTreeSQL(obj, ng, rels)
		if err != nil {
			return "", err
		}
		filters = append(filters, idNotIn(sub))
	}
	if len(filters) == 0 {
		return base, nil
	}
	return fmt.Sprintf("SELECT a.* FROM (%s) a(source, principal_kind, principal_id, access)\n    WHERE %s", base, strings.Join(filters, "\n      AND ")), nil
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
	// Every exclusion the term names, ANDed, so the role branch is narrowed by
	// the same set the plane is. Taking only the first would leave the branch
	// wider than the policy it is meant to mirror.
	for _, t := range sel.Expr {
		if t == nil || t.Builtin != "app_scope" {
			continue
		}
		var conds []string
		for _, ex := range t.ExcludeRels {
			if r := rels[ex]; r != nil {
				if vc, ok := r.Repr.(ViaColumn); ok {
					conds = append(conds, ownerExclCond(vc))
				}
			}
		}
		if len(conds) > 0 {
			return strings.Join(conds, " AND ")
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
		if i == min(len(obj.Scoped), len(rs.ScopeCols))-1 {
			scopeConds = append(scopeConds, fmt.Sprintf("(ra.%s IS NULL OR ra.%s = r.%s)", rsCol, rsCol, rowCol))
		} else {
			scopeConds = append(scopeConds, fmt.Sprintf("ra.%s = r.%s", rsCol, rowCol))
		}
	}
	where := []string{"r." + obj.pk() + " = p_id"}
	if adminExcl != "" {
		where = append(where, adminExcl)
	}
	on := rs.kindCond("ra.")
	on = append(on, rs.revokedCond("ra.")...)
	on = append(on, scopeConds...)
	return fmt.Sprintf(
		"SELECT 'role'::text, '%s'::text, ra.%s, 'read'::text\n    FROM %s r\n    JOIN %s ra ON %s\n    WHERE %s",
		rs.KindVal, rs.SubjectCol, obj.Table, rs.Assignments,
		strings.Join(on, " AND "),
		strings.Join(where, " AND ")), true
}

func accessorGenFn(table, idT string, branches []string) GenFn {
	return accessorGenFnNamed(table+"_accessors", idT, branches)
}

func accessorGenFnNamed(name, idT string, branches []string) GenFn {
	return GenFn{
		Name:    name,
		Sig:     "p_id " + idT,
		Returns: "TABLE(source text, principal_kind text, principal_id " + idT + ", access text)",
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
	var branches []string
	for _, t := range sel.Expr {
		b, err := s.structuralTermEnum(obj, t, rels, rs, presetLevels)
		if err != nil {
			return GenFn{}, false, err
		}
		branches = append(branches, b...)
	}

	for _, g := range s.Grants {
		if e := s.enumeratedGrant(obj, g); e != nil {
			branches = append(branches, s.grantEnumSQL(obj, e))
		}
	}
	if len(branches) == 0 {
		return GenFn{}, false, nil
	}
	return GenFn{
		Name:    obj.Table + "_accessors",
		Sig:     "p_id " + s.idType(),
		Returns: "TABLE(source text, principal_kind text, principal_id " + s.idType() + ", access text)",
		RawBody: true,
		Body:    "  " + strings.Join(branches, "\n  UNION\n  "),
	}, true, nil
}

func (s *Spec) structuralTermEnum(obj *Object, t *Term, rels map[string]*Relation, rs *RoleStore, presetLevels map[string][]string) ([]string, error) {
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
		return []string{s.roleEnumSQL(obj, rs, objLevel, presetLevels[objLevel], "role", "read")}, nil
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
	on := rs.kindCond("ra.")
	on = append(on, rs.revokedCond("ra.")...)
	on = append(on, conds...)
	return fmt.Sprintf(
		"SELECT '%s'::text AS source, '%s'::text AS principal_kind, ra.%s AS principal_id, '%s'::text AS access\n    FROM %s e JOIN %s ra ON %s%s\n    WHERE e.%s = p_id",
		source, rs.KindVal, rs.SubjectCol, access, obj.Table, rs.Assignments,
		strings.Join(on, " AND "), join, obj.pk())
}

func (s *Spec) memberinEnumSQL(obj *Object, rs *RoleStore, level string) string {
	on := rs.kindCond("ra.")
	on = append(on, rs.revokedCond("ra.")...)
	on = append(on, fmt.Sprintf("ra.%s = e.%s", s.scopeColForLevel(rs, level), s.scopeCol(obj, level)))
	return fmt.Sprintf(
		"SELECT 'role'::text, '%s'::text, ra.%s, 'read'::text\n    FROM %s e JOIN %s ra ON %s\n    WHERE e.%s = p_id",
		rs.KindVal, rs.SubjectCol, obj.Table, rs.Assignments,
		strings.Join(on, " AND "), obj.pk())
}

// grantEnumSQL enumerates the holders of a grant as accessors of an object the
// grant reaches.
func (s *Spec) grantEnumSQL(obj *Object, g *Grant) string {
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
		"SELECT '%s'::text, '%s'::text, ig.%s, '%s'::text\n    FROM %s e JOIN %s ig ON %s\n    WHERE e.%s = p_id",
		g.Name, kind, g.GranteeCol, grantAccess(g), obj.Table, g.Table, strings.Join(conds, " AND "), obj.pk())
}

// grantAccess reports the access an enumeration should attribute to a grant's
// holders. It follows the ops the grant confers, so a reach bounded to select
// is enumerated as a reader rather than as a writer.
//
// A grant naming no ops confers all of them and so confers write, which is what
// every grant reported before the clause existed. Where a grant names several,
// the strongest wins: an enumeration answers "what can this principal do here",
// and the weakest answer would understate it.
func grantAccess(g *Grant) string {
	if len(g.Verbs) == 0 {
		return "write"
	}
	for _, op := range []string{"update", "insert", "delete", "select"} {
		if contains(g.Verbs, op) {
			return accessFor(op)
		}
	}
	return "read"
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

func (rs *RoleStore) kindCond(alias string) []string {
	if rs.KindCol == "" {
		return nil
	}
	return []string{fmt.Sprintf("%s%s = '%s'", alias, rs.KindCol, rs.KindVal)}
}

func (rs *RoleStore) revokedCond(alias string) []string {
	if rs.RevokedCol == "" {
		return nil
	}
	return []string{fmt.Sprintf("%s%s IS NULL", alias, rs.RevokedCol)}
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
