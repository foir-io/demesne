package demesne

import (
	"fmt"
	"sort"
	"strings"
)

// RLS emitter (RFC §7) — compiles an object's @rls permissions to Postgres
// policy predicates. The output is SEMANTICALLY the live hand-written policy
// (the oracle compares pg_policies, which Postgres re-renders canonically, so
// exact whitespace/cast form is irrelevant — only the parsed expression must
// match). The cheap inline sargable axes are emitted FIRST so the planner picks
// the index and the customer-caller short-circuits before the definer tail.
//
// Bounded-emitter discipline (§6.2): the emitter never emits weaker SQL. A
// permission it cannot yet compile (a role-walk term — the project/role plane)
// is reported in Unsupported, NOT approximated. The oracle then flags any live
// policy left unreproduced.

// Policy is one emitted RLS policy.
type Policy struct {
	Object string // the spec object it came from
	Table  string
	Name   string // <table>_<op>
	Cmd    string // SELECT | INSERT | UPDATE | DELETE
	Using  string // USING predicate; "" if none (INSERT)
	Check  string // WITH CHECK predicate; "" if none (SELECT/DELETE)
}

// RLSResult is the emitter output: the policies plus an explicit list of
// permissions left unreproduced (so nothing is silently dropped).
type RLSResult struct {
	Policies    []Policy
	Unsupported []string
}

// claim renders the claim accessor for a key — the SQL that reads a claim from
// the request context. The accessor is spec-declared (the `claims` block); when
// omitted it defaults to Foir's JSON-GUC form, so existing specs emit
// byte-identically. Postgres normalizes this and the verbose
// `((current_setting('…'::text, true))::json ->> 'k'::text)` form to the same
// pg_policies expression.
func (s *Spec) claim(key string) string {
	setting, cast := "request.jwt.claims", "json"
	if s.Claims != nil {
		setting, cast = s.Claims.Setting, s.Claims.Cast
	}
	return fmt.Sprintf("(current_setting('%s', true)::%s ->> '%s')", setting, cast, key)
}

// accessFor maps a table op to the access level a parameterised relation
// resolves at (§8.2 mapref note): select→read, update/insert→write, delete→delete.
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

// EmitRLS compiles every @rls permission across the spec's objects.
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

	res := &RLSResult{}
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

// ownerSubject returns the per-record owner-plane subject for an object's leaf
// level — the subject EXPLICITLY bound with `binds owner` at that anchor (EID-265
// WS2). This is a declared binding, not a shape heuristic (formerly "the unique
// reach-self + roles subject at the leaf", which silently disambiguated `customer`
// from a no-claim `service`). nil if the spec binds no owner at this level.
func (s *Spec) ownerSubject(leafLevel string) *Subject {
	for _, sub := range s.Subjects {
		if sub.Binds == "owner" && sub.Anchor == leafLevel {
			return sub
		}
	}
	return nil
}

// adminIdentify returns the claim key of the role-resolution (admin) plane — the
// subject EXPLICITLY bound with `binds admin` (EID-265 WS2), not the formerly
// inferred "reach descendants + roles, non-membership" subject. Falls back to
// "sub" when the spec declares no admin plane.
func (s *Spec) adminIdentify() string {
	for _, sub := range s.Subjects {
		if sub.Binds == "admin" {
			return sub.Identifies
		}
	}
	return "sub"
}

// adminName returns the NAME of the role-resolution (admin) plane subject — the
// `binds admin` subject (EID-265 WS2). It supplies the role-definer affix
// (is_<level>_<adminName> / <adminName>_has_<obj>_role) so the generated names
// reflect the spec's own admin plane, not a baked "admin". Defaults to "admin"
// (Foir's admin subject IS named "admin", so its definer names are unchanged).
func (s *Spec) adminName() string {
	for _, sub := range s.Subjects {
		if sub.Binds == "admin" {
			return sub.Name
		}
	}
	return "admin"
}

// scopeCol returns the physical column for a topology level on this object: a
// level-entity object uses its own `id` for its level (it IS that node);
// everything else carries the `<level>_id` FK column.
func scopeCol(obj *Object, lvl string) string {
	if obj.IsLevelEntity() && lvl == obj.Level {
		return "id"
	}
	return lvl + "_id"
}

// reqClaim fails closed when an owner / customer-plane term needs the per-record
// owner claim but no owner subject resolved one. Without this guard the emitter
// would substitute an empty claim key and produce `(... ->> '')`, which is
// silently NULL and would match (or fail to constrain) every row — a soundness
// hole. The spec must declare a `reach self` subject (with roles) at the
// object's leaf level for any object whose policy references the owner axis.
func reqClaim(custClaim string, obj *Object, what string) error {
	if custClaim == "" {
		return fmt.Errorf("object %q: %s references the owner axis, but no owner subject (a subject `binds owner` at level %q) resolves a claim — refusing to emit an empty-claim predicate",
			obj.Name, what, obj.Scoped[len(obj.Scoped)-1])
	}
	return nil
}

// guardSQL renders the bounded ABAC guard, null-safe for `<>`.
func guardSQL(g *Guard) string {
	if g.Op == "<>" {
		return fmt.Sprintf("(%s IS NULL OR %s <> '%s')", g.Col, g.Col, g.Val)
	}
	return fmt.Sprintf("%s = '%s'", g.Col, g.Val)
}

// rlsPredicate builds the full policy predicate under the uniform invariant: a
// subject acts within its session scope. The OPERATOR (a virtual-root membership
// subject) is the only containment-independent branch; every other grant lives
// inside the containment block. For a sub-row object the containment pins the
// full scoped chain; for a LEVEL-ENTITY object it pins the ANCESTOR levels — the
// entity's own node identity is a grant axis (@session, role-on-self), not
// containment. The bounded guard rides node-level grants (a same-level via-role
// + @session), not ancestor walks or the operator.
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

	var top []string
	for _, sub := range s.Subjects {
		switch {
		case sub.Membership != nil && virtual[sub.Anchor]:
			// Legacy unconditional membership operator (a god-flag): reaches every
			// row, gated only by `<leaf>_id IS NULL` (no scope selected).
			fn := fmt.Sprintf("%s.%s(%s)", s.definerSchema(), membershipFn(sub.Membership), s.claim(sub.Identifies))
			if obj.IsLevelEntity() {
				top = append(top, fn)
			} else {
				top = append(top, fmt.Sprintf("(%s AND %s IS NULL)", fn, s.claim(objLeaf+"_id")))
			}
		case sub.Reach == "grant":
			// Scoped grant operator (the general replacement for the god-flag):
			// reach is gated by an ACTIVE grant edge at the grant's level — not
			// unconditional — and cascades to the whole subtree via the object's
			// level-scope column. No `<leaf>_id IS NULL` ambient view.
			if g := s.grantByName(sub.ReachGrant); g != nil {
				top = append(top, fmt.Sprintf("%s.%s_reach(%s, %s)", s.definerSchema(), g.Table, s.claim(sub.Identifies), scopeCol(obj, g.Level)))
			}
		}
	}

	// @scoped (containment alone grants — the admin-config plane) is a flag on the
	// permission, not a boolean operand; detect it across the leaves.
	scopedGrant := false
	for _, t := range pm.Expr {
		if t.Builtin == "scoped" {
			scopedGrant = true
		}
	}
	// The grant block: the permission's boolean expression (union / intersection /
	// negation) over the leaf-term fragments. A union-only tree flattens to the
	// historical `f1 OR f2 …`.
	blockTerms, err := s.nodeFrags(obj, pm, pm.Tree, rels, custClaim)
	if err != nil {
		return "", err
	}

	// Containment: pin every ancestor scope column along the object's root→leaf
	// path(s). A single-parent leaf has ONE path → a plain AND-chain (identical to
	// the chain/tree case). A multi-parent leaf (WS3 Phase B) has one path per
	// lineage → an OR of per-path AND-chains (column-backed, sargable). A
	// level-entity object excludes its own node column (that is a grant axis, not
	// containment); virtual levels carry no column.
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
			cols = append(cols, fmt.Sprintf("%s = %s", scopeCol(obj, lvl.Name), s.claim(lvl.Name+"_id")))
		}
		pathPreds = append(pathPreds, strings.Join(cols, " AND "))
	}
	var block string
	if len(pathPreds) == 1 {
		block = pathPreds[0]
	} else {
		for i := range pathPreds {
			pathPreds[i] = "(" + pathPreds[i] + ")"
		}
		block = strings.Join(pathPreds, " OR ")
	}
	if len(blockTerms) > 0 {
		if block != "" {
			block += " AND (" + strings.Join(blockTerms, " OR ") + ")"
		} else {
			block = strings.Join(blockTerms, " OR ")
		}
	}

	if len(top) == 0 && len(blockTerms) == 0 && !scopedGrant {
		return "", fmt.Errorf("no emittable grant terms")
	}
	branches := append(top, "("+block+")")
	return strings.Join(branches, " OR "), nil
}

// guardable reports whether the bounded guard rides this term — a node-level
// grant (a same-level via-role or @session), never an ancestor walk or the
// operator.
func guardable(t *Term, rels map[string]*Relation) bool {
	if t.Builtin == "session" {
		return true
	}
	if t.WalkVerb != "" {
		return false
	}
	if r := rels[t.Ident]; r != nil {
		if _, ok := r.Repr.(ViaRole); ok {
			return true
		}
	}
	return false
}

// nodeFrags compiles a permission boolean node into the OR-composable predicate
// fragments of the grant block (v3 WS1). For a leaf it is the term's fragments
// (guard-wrapped); for `or` it FLATTENS the children's fragments (so a union-only
// tree reproduces the historical flat `f1 OR f2 …` exactly — byte-identical); for
// `and` it returns a single fragment `(A) AND (B)` (each side its own fragments
// OR'd); for `not` a single fail-closed `NOT COALESCE(<pred>, true)` (an
// indeterminate exclusion denies). The `@scoped` flag is not a predicate and
// contributes nothing here.
func (s *Spec) nodeFrags(obj *Object, pm *Perm, n *PermNode, rels map[string]*Relation, custClaim string) ([]string, error) {
	if n == nil {
		return nil, nil
	}
	switch n.Op {
	case "leaf":
		if n.Term.Builtin == "scoped" {
			return nil, nil
		}
		frags, err := s.emitTerm(obj, pm, n.Term, rels, custClaim)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, f := range frags {
			if pm.Guard != nil && guardable(n.Term, rels) {
				f = fmt.Sprintf("(%s AND %s)", f, guardSQL(pm.Guard))
			}
			out = append(out, f)
		}
		return out, nil
	case "or":
		var out []string
		for _, k := range n.Kids {
			kf, err := s.nodeFrags(obj, pm, k, rels, custClaim)
			if err != nil {
				return nil, err
			}
			out = append(out, kf...) // flatten — no per-child parens
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
		return []string{fmt.Sprintf("NOT COALESCE(%s, true)", strings.Join(kf, " OR "))}, nil
	}
	return nil, fmt.Errorf("unknown permission node op %q", n.Op)
}

// emitTerm compiles one union term to one or more predicate fragments.
func (s *Spec) emitTerm(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, custClaim string) ([]string, error) {
	if t.WalkVerb != "" {
		// A role-walk into a parent relation (e.g. `tenant->owner`): the admin
		// owns/administers the parent node → a tenant/ancestor-admin definer
		// call. Convention reproduces the live names: walk into relation R (to
		// object/level X via column C) → auth.is_<X>_admin(<admin sub claim>, C).
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
	switch {
	case t.Builtin == "app_scope":
		if err := reqClaim(custClaim, obj, "@app_scope"); err != nil {
			return nil, err
		}
		return []string{s.claim(custClaim) + " IS NULL"}, nil
	case t.Builtin == "descriptor":
		return s.emitDescriptor(obj, pm, custClaim)
	case t.Builtin == "session":
		// The caller's session-selected node: the entity's own column = the
		// leaf claim. `@session(<rel>)` gates it by a role (e.g. project-admin
		// of your selected project).
		leaf := obj.Scoped[len(obj.Scoped)-1]
		self := fmt.Sprintf("%s = %s", scopeCol(obj, leaf), s.claim(leaf+"_id"))
		if t.SessionRel == "" {
			return []string{self}, nil
		}
		roleFrag, err := s.emitTerm(obj, pm, &Term{Ident: t.SessionRel}, rels, custClaim)
		if err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("%s AND %s", self, roleFrag[0])}, nil
	case t.Builtin != "":
		return nil, fmt.Errorf("builtin @%s is not emittable in RLS", t.Builtin)
	case isPermKeyLit(t.Ident):
		return nil, fmt.Errorf("capability term %q belongs to the PDP, not RLS", t.Ident)
	}

	r := rels[t.Ident]
	if r == nil {
		return nil, fmt.Errorf("unknown relation %q", t.Ident)
	}
	access := accessFor(pm.Maps)
	pk := obj.Table + ".id"
	switch repr := r.Repr.(type) {
	case ViaColumn:
		// Inline owner axis: column equals the customer claim.
		if err := reqClaim(custClaim, obj, "owner relation "+t.Ident); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("%s = %s", repr.Column, s.claim(custClaim))}, nil
	case ViaEdge:
		// Definer tail: the compiler owns auth.<edgeTable>(...).
		if err := reqClaim(custClaim, obj, "edge relation "+t.Ident); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("%s.%s(%s, %s, '%s')", s.definerSchema(), repr.Table, s.claim(custClaim), pk, access)}, nil
	case ViaComposition:
		if err := reqClaim(custClaim, obj, "composition relation "+t.Ident); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("%s.%s_composition_%s(%s, %s, '%s')", s.definerSchema(), obj.Name, r.Name, s.claim(custClaim), pk, access)}, nil
	case ViaClosure:
		// Unbounded-depth reachability (WS3 Phase C): the row's hierarchy node
		// (repr.Col) is reachable from the subject's granted ancestor (its claim)
		// iff a closure pair exists. An indexed read over the trigger-maintained
		// closure — the compiler owns both the lookup definer and the maintenance.
		if err := reqClaim(custClaim, obj, "closure relation "+t.Ident); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("%s.%s_reachable(%s, %s)", s.definerSchema(), repr.Closure, s.claim(custClaim), repr.Col)}, nil
	case ViaRole:
		// A role membership on this object → a project-role definer call over
		// the object's scope columns. Convention: auth.admin_has_<obj>_role(
		// <admin sub claim>, <scope cols>). A rank threshold narrows the fn.
		var cols []string
		for _, lvl := range obj.Scoped {
			cols = append(cols, scopeCol(obj, lvl))
		}
		// No rank → "has any role" (auth.<admin>_has_<obj>_role); a rank threshold
		// → the named rank predicate (auth.is_<rank>, e.g. is_project_admin).
		fn := fmt.Sprintf("%s_has_%s_role", s.adminName(), obj.Name)
		if repr.HasRank {
			fn = "is_" + repr.RankMin
		}
		return []string{fmt.Sprintf("%s.%s(%s, %s)", s.definerSchema(), fn, s.claim(s.adminIdentify()), strings.Join(cols, ", "))}, nil
	default:
		return nil, fmt.Errorf("relation %q has an unknown representation", r.Name)
	}
}

// emitDescriptor expands @descriptor into the customer-plane predicate fragments
// (§5.3): the inline owner + public-mode column checks first, then the
// record_acl definer tail. private/admins are the admin plane (not customer
// terms).
func (s *Spec) emitDescriptor(obj *Object, pm *Perm, custClaim string) ([]string, error) {
	d := obj.Descriptor
	if d == nil {
		return nil, fmt.Errorf("@descriptor used but object has no descriptor")
	}
	if err := reqClaim(custClaim, obj, "@descriptor"); err != nil {
		return nil, err
	}
	var frags []string
	owner, _ := d.Owner.Repr.(ViaColumn)
	frags = append(frags, fmt.Sprintf("%s = %s", owner.Column, s.claim(custClaim)))

	// Column read-gate modes are READ-only disjuncts: a row whose ModeCol equals
	// the declared sentinel may be VIEWed by any in-scope reader, never written.
	// They contribute only to the select policy.
	if pm.Maps == "select" {
		for _, m := range d.Modes {
			if m.Kind == "read" {
				frags = append(frags, fmt.Sprintf("%s = '%s'", d.ModeCol, m.Value))
			}
		}
	}
	// The explicit grant list applies to read/write/delete at the perm's access
	// class — never to insert (you create your own rows, you aren't "granted" it).
	if d.Grants != nil && descriptorHasList(d) && pm.Maps != "insert" {
		frags = append(frags, fmt.Sprintf("%s.%s_grants(%s, %s, '%s')", s.definerSchema(), d.Grants.Table, s.claim(custClaim), obj.Table+".id", accessFor(pm.Maps)))
	}
	return frags, nil
}

// GovernedTables returns the sorted, de-duplicated set of tables the emitted
// policies govern.
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

// EnablementSQL renders `ALTER TABLE … ENABLE/FORCE ROW LEVEL SECURITY` for every
// governed table, sorted. This is part of the moat's owned surface: a generated
// policy is INERT unless RLS is both ENABLED and FORCED on its table — a
// non-enabled table ignores the policy entirely, and a non-FORCED table lets the
// table owner (and any BYPASSRLS role) read past it. FORCE subjects even the
// table owner to the policy. Both statements are idempotent (a no-op on a table
// already in that state), so applying this to a live database only tightens
// tables that were missing it.
func (r *RLSResult) EnablementSQL() string {
	var b strings.Builder
	for _, t := range r.GovernedTables() {
		fmt.Fprintf(&b, "ALTER TABLE public.%s ENABLE ROW LEVEL SECURITY;\n", t)
		fmt.Fprintf(&b, "ALTER TABLE public.%s FORCE ROW LEVEL SECURITY;\n", t)
	}
	return b.String()
}

// PolicySQL renders the idempotent DROP + CREATE statement for every emitted
// policy, all granted to `role`, sorted by (table, name) for deterministic
// output. This is the Phase-B source-of-truth SQL: a goose migration re-creates
// the live policies from this, and because every USING/WITH CHECK is the same
// expression the oracle verified against pg_policies, the re-creation is a no-op
// on a live database. The emitter never emits a policy for an Unsupported
// permission, so callers should treat a non-empty RLSResult.Unsupported as fatal
// before rendering (Validate's V11 already does).
func (r *RLSResult) PolicySQL(role string) string {
	pols := append([]Policy(nil), r.Policies...)
	sort.Slice(pols, func(i, j int) bool {
		if pols[i].Table != pols[j].Table {
			return pols[i].Table < pols[j].Table
		}
		return pols[i].Name < pols[j].Name
	})
	var b strings.Builder
	for _, p := range pols {
		fmt.Fprintf(&b, "DROP POLICY IF EXISTS %s ON public.%s;\n", p.Name, p.Table)
		fmt.Fprintf(&b, "CREATE POLICY %s ON public.%s FOR %s TO %s", p.Name, p.Table, p.Cmd, role)
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

// DefinerNames returns the sorted set of SECURITY DEFINER functions the emitted
// policies reference — the surface the compiler must own (V9) and the kernel
// emitter generates.
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

// descriptorHasList reports whether the descriptor declares any `list` mode (an
// explicit record_acl grant list).
func descriptorHasList(d *Descriptor) bool { return descriptorListKind(d) != "" }

// descriptorListKind returns the principal kind of the descriptor's list mode
// (the value the record_acl grant definer filters on), or "" if there is none.
func descriptorListKind(d *Descriptor) string {
	for _, m := range d.Modes {
		if m.Kind == "list" {
			return m.Value
		}
	}
	return ""
}

// scanDefiners extracts `<schema>.<name>(` references from a predicate.
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
