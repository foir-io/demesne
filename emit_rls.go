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
	// TableSchema qualifies the governed tables in the emitted DDL ("" ⇒ "public",
	// the EmitRLS default). Set from the spec's `tables schema` block.
	TableSchema string
}

// tableSchema returns the governed-table schema (default "public").
func (r *RLSResult) tableSchema() string {
	if r.TableSchema != "" {
		return r.TableSchema
	}
	return "public"
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
// level-entity object uses its own PRIMARY KEY for its own level (it IS that
// node); everything else carries the level's scope column (its declared `col`,
// else the `<level>_id` FK convention). Both the PK and the scope column are
// spec-declarable, so the emitter assumes no `id` / `<level>_id` naming (EID-278).
func (s *Spec) scopeCol(obj *Object, lvl string) string {
	if obj.IsLevelEntity() && lvl == obj.Level {
		return obj.pk()
	}
	if l := s.Topology.LevelByName(lvl); l != nil {
		return l.scopeColumn()
	}
	return lvl + "_id"
}

// claimKeyForLevel returns the JWT claim key carrying a topology level's id (its
// declared `claim`, else the `<level>_id` convention) — the RHS every containment
// equality reads. Decoupled from the scope column so a column and the claim that
// selects it may be named differently (EID-278).
func (s *Spec) claimKeyForLevel(level string) string {
	if l := s.Topology.LevelByName(level); l != nil {
		return l.claimKey()
	}
	return level + "_id"
}

// reqClaim fails closed when an owner / customer-plane term needs the per-record
// owner claim but no owner subject resolved one. Without this guard the emitter
// would substitute an empty claim key and produce `(... ->> ”)`, which is
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

	objIsGlobal := virtual[objLeaf] // a virtual-leaf object lives above tenancy
	objHasStaffTerm := s.objectReferencesStaff(obj)

	// Subject-derived top branches, plus grant reaches to fold INTO the containment
	// block at a given ancestor level (keyed by level name).
	top, grantInject := s.rlsSubjectBranches(obj, virtual, objLeaf, objIsGlobal, objHasStaffTerm)

	// Permission-expression top branches (@scoped flag, `via grant`, @public).
	top, scopedGrant, err := s.rlsExprTopBranches(obj, pm, top)
	if err != nil {
		return "", err
	}

	// The grant block: the permission's boolean expression (union / intersection /
	// negation) over the leaf-term fragments. A union-only tree flattens to the
	// historical `f1 OR f2 …`.
	blockTerms, err := s.nodeFrags(obj, pm, pm.Tree, rels, custClaim)
	if err != nil {
		return "", err
	}

	// Containment: pin every ancestor scope column along the object's root→leaf path(s).
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

	// Containment is a GRANT branch only when the permission has a containment-bearing
	// term (@scoped, or any owner/role/grant-acl/mode block term). A permission whose
	// only grant is `via grant <name>` is NOT containment-bearing → the containment
	// block is emitted as neither a grant nor a scope (the grant reach alone governs).
	// Every pre-existing permission has such a term, so this is byte-identical for them.
	containmentBearing := scopedGrant || len(blockTerms) > 0
	if len(top) == 0 && !containmentBearing {
		return "", fmt.Errorf("no emittable grant terms")
	}
	// A GLOBAL object (virtual leaf) carries no containment columns, so its block is
	// empty; its only grant is the platform-role top branch. Emit just that branch —
	// never a bare `OR ()`, which is a syntax error. Every non-global object always
	// has a non-empty containment block, so this is byte-identical for them.
	branches := top
	if block != "" && containmentBearing {
		branches = append(branches, "("+block+")")
	}
	if len(branches) == 0 {
		return "", fmt.Errorf("object %q permission %q: no emittable grant — a global object needs a platform-role subject", obj.Name, pm.Verb)
	}
	return strings.Join(branches, " OR "), nil
}

// rlsSubjectBranches derives the subject-level top branches and the grant reaches
// to fold into containment. The OPERATOR (a virtual-root membership subject) is the
// only containment-independent branch; a scoped-grant operator either rides a
// top-level reach (object at/above the grant's level) or folds into the grant-level
// containment column (a deeper sub-row object), keyed in grantInject by level name.
func (s *Spec) rlsSubjectBranches(obj *Object, virtual map[string]bool, objLeaf string, objIsGlobal, objHasStaffTerm bool) ([]string, map[string][]string) {
	var top []string
	grantInject := map[string][]string{}
	for _, sub := range s.Subjects {
		switch {
		case sub.Membership != nil && virtual[sub.Anchor]:
			// Legacy unconditional membership operator (a god-flag): reaches every
			// row, gated only by `<leaf>_id IS NULL` (no scope selected).
			fn := fmt.Sprintf("%s.%s(%s)", s.definerSchema(), membershipFn(sub.Membership), s.claim(sub.Identifies))
			if obj.IsLevelEntity() || objIsGlobal {
				top = append(top, fn)
			} else {
				top = append(top, fmt.Sprintf("(%s AND %s IS NULL)", fn, s.claim(s.claimKeyForLevel(objLeaf))))
			}
		case s.isPlatformRoleSubject(sub) && (objHasStaffTerm || (objIsGlobal && sub.Anchor == objLeaf)):
			// Platform-anchored ROLE subject on a PURE-GLOBAL object (the `platform
			// <table>` shorthand, v3 WS6): a table above tenancy whose ONLY grant is
			// the platform plane. The platform-role definer is the whole top branch —
			// has_<anchor>_role(<claim>) over role_assignments with NULL scope. The
			// general retirement of the is_platform_admin god-flag. Skipped when the
			// object references the staff plane EXPLICITLY (a composable `staff` term,
			// for objects that mix staff with self/role/session) — that term emits the
			// same call, so auto-adding here too would duplicate it.
			top = append(top, fmt.Sprintf("%s.%s(%s)", s.definerSchema(), platformRoleFn(sub.Anchor), s.claim(sub.Identifies)))
		case sub.Reach == "grant":
			// Scoped grant operator (the general replacement for the god-flag):
			// reach is gated by an ACTIVE grant edge at the grant's level — not
			// unconditional — and cascades to the whole subtree via the object's
			// level-scope column. No `<leaf>_id IS NULL` ambient view. A grant
			// reaches DOWN into its level's subtree, so it contributes nothing to a
			// GLOBAL object above that level (which carries no such scope column).
			top, grantInject = s.rlsApplyGrantReach(obj, sub, objLeaf, objIsGlobal, top, grantInject)
		}
	}
	return top, grantInject
}

// rlsApplyGrantReach routes a scoped-grant subject's reach either to a top-level
// branch (object AT the grant's level — a level-entity selector — or a global
// object) or, for a deeper sub-row object, folds it into the grant-level containment
// column so the selected deeper scope still constrains the operator's view.
func (s *Spec) rlsApplyGrantReach(obj *Object, sub *Subject, objLeaf string, objIsGlobal bool, top []string, grantInject map[string][]string) ([]string, map[string][]string) {
	g := s.grantByName(sub.ReachGrant)
	if g == nil || !contains(obj.Scoped, g.Level) {
		return top, grantInject
	}
	reach := fmt.Sprintf("%s.%s_reach(%s, %s)", s.definerSchema(), g.Table, s.claim(sub.Identifies), s.scopeCol(obj, g.Level))
	if g.Level != objLeaf && !obj.IsLevelEntity() && !objIsGlobal {
		// Sub-row object deeper than the grant's level: fold the grant into
		// the grant-level containment column so the deeper scope (the
		// selected project) still constrains the operator's view. An
		// operator reaches OTHER projects in the granted tenant by selecting
		// them, exactly like a normal admin — never tenant-wide at once.
		grantInject[g.Level] = append(grantInject[g.Level], reach)
	} else {
		// Object AT the grant's level (a level-entity selector, e.g. the
		// project/tenant lists) or a global object: the grant is a top-level
		// reach so the operator can see — and pick — every node in the
		// granted level's subtree.
		top = append(top, reach)
	}
	return top, grantInject
}

// rlsExprTopBranches appends the permission-expression top branches to top and
// reports whether @scoped is present. `via grant <name>` terms emit a TOP-level
// reach (deduped against the auto-added subject reach); @public emits a `true`
// branch (a world-readable catalog). When a permission's only grant is
// grant-references, the containment block is suppressed in rlsPredicate.
func (s *Spec) rlsExprTopBranches(obj *Object, pm *Perm, top []string) ([]string, bool, error) {
	// @scoped (containment alone grants — the admin-config plane) is a flag on the
	// permission, not a boolean operand; detect it across the leaves.
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

// rlsContainmentBlock builds the containment predicate: pin every ancestor scope
// column along the object's root→leaf path(s). A single-parent leaf has ONE path →
// a plain AND-chain (identical to the chain/tree case). A multi-parent leaf (WS3
// Phase B) has one path per lineage → an OR of per-path AND-chains (column-backed,
// sargable). A level-entity object excludes its own node column (that is a grant
// axis, not containment); virtual levels carry no column.
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
				// (<col> = <claim> OR grant_reach(...)) — the grant admits the operator
				// at this level; deeper levels still AND in, keeping it scoped.
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

// grantRefReach renders the reach predicate for a `via grant <name>` permission
// term: the grant's SECURITY DEFINER reach (auth.<edge>_reach) over the object's
// column for the grant's level, read against the claim of the subject that reaches
// via that grant. The object must be scoped under the grant's level (else the level
// column is absent). This is the GENERIC mechanism for "a permission conferred by a
// named grant" — the grant + its subject are app-defined (no framework domain word).
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

// objectVerbPredicate returns the full RLS predicate of an object's @rls
// permission verb — the predicate a cross-object reference (ViaObject) borrows
// and runs at the related row.
func (s *Spec) objectVerbPredicate(obj *Object, verb string, virtual map[string]bool) (string, error) {
	for _, pm := range obj.Perms {
		if pm.Verb == verb && contains(pm.Layers, "rls") {
			cust := s.ownerSubject(obj.Scoped[len(obj.Scoped)-1])
			return s.rlsPredicate(obj, pm, cust, virtual)
		}
	}
	return "", fmt.Errorf("object %q has no @rls permission %q for a cross-object reference", obj.Name, verb)
}

// argSrcSQL renders a ViaMemberIn argument: a claim accessor for `@<key>`, or the
// bare row column for a column source.
func (s *Spec) argSrcSQL(a ArgSrc) string {
	if a.Claim != "" {
		return s.claim(a.Claim)
	}
	return a.Col
}

// relationClaim returns the claim key an inline relation matches its column
// against: the relation's first declared type subject's `identifies`, or the
// supplied fallback (the object's leaf owner-plane claim) when the type names no
// claim-bearing subject. This is what lets an owner axis resolve on a global
// object, where there is no leaf owner subject to fall back to.
func (s *Spec) relationClaim(r *Relation, fallback string) string {
	if r != nil && len(r.Types) > 0 {
		if sub := s.subjectByName(r.Types[0]); sub != nil && sub.Identifies != "" {
			return sub.Identifies
		}
	}
	return fallback
}

// modePlaneScope renders the plane predicate for an actor-scoped public read mode
// (`read "<sentinel>" for <subject>`). The scope confines the sentinel to a
// principal PLANE expressed against the customer-plane discriminator (custClaim):
// a subject that itself identifies the customer claim (the owner plane) requires
// the claim to be PRESENT; any other subject (operator/admin/service plane)
// requires it ABSENT. So `for admin` → `<customer claim> IS NULL` (operators
// only), the project-wide-operator-visible-but-customer-invisible shape.
func (s *Spec) modePlaneScope(scope, custClaim string) string {
	if sub := s.subjectByName(scope); sub != nil && sub.Identifies == custClaim {
		return s.claim(custClaim) + " IS NOT NULL"
	}
	return s.claim(custClaim) + " IS NULL"
}

// objectReferencesStaff reports whether the object declares a relation targeting
// a virtual-anchored role subject — the COMPOSABLE platform-staff plane. When it
// does, rlsPredicate does NOT also auto-add the staff top branch (that would
// duplicate the term's emitted call). Pure-global objects (the `platform <table>`
// shorthand) have no such relation, so they get the auto-branch.
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

// guardable reports whether the bounded guard rides this term — a node-level
// grant (a same-level via-role or @session), never an ancestor walk, the
// operator, or the platform-staff plane (staff sees guarded rows like CHURNED
// tenants, exactly as the impersonation operator does).
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
			// The platform-staff plane (a via-role targeting a virtual-anchored role
			// subject) is the operator plane, not a node-level grant — not guardable.
			if len(r.Types) > 0 {
				if st := s.subjectByName(r.Types[0]); st != nil && s.isPlatformRoleSubject(st) {
					return false
				}
			}
			return true
		case ViaMemberIn:
			// A scoped role-membership grant (the tenant picker) — the CHURNED guard
			// rides it, exactly as the live tenants policy AND's it with status.
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
// rlsLeafFrags compiles a leaf permission node into its guard-wrapped fragments.
// The `@scoped` flag, `via grant <name>` terms and `@public` are emitted as
// top-level branches in rlsPredicate, not as containment block fragments — so they
// contribute nothing here.
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
		// Exclusion: the row passes iff the excluded condition is NOT definitely
		// true — `(P) IS NOT TRUE` (false or NULL → not excluded). A NULL means the
		// condition doesn't apply (e.g. an empty ban column), NOT "deny": that
		// would wrongly exclude every row with no ban. Fail-closed is enforced
		// STRUCTURALLY instead (validatePermPolarity): a `not` may only appear AND'd
		// with a positive grant, so a NULL claim can never satisfy a bare negation.
		return []string{fmt.Sprintf("(%s) IS NOT TRUE", strings.Join(kf, " OR "))}, nil
	}
	return nil, fmt.Errorf("unknown permission node op %q", n.Op)
}

// emitTerm compiles one union term to one or more predicate fragments.
func (s *Spec) emitTerm(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, custClaim string) ([]string, error) {
	if t.ModeCol != "" {
		return s.rlsEmitMode(t, custClaim), nil
	}
	if t.WalkVerb != "" {
		return s.rlsEmitWalk(t, rels)
	}
	// A grant relation referenced with an access class (`grantee:read`) lexes as a
	// single permkey; resolve it before the capability/relation handling below. The
	// access class names the acl `access` value (read|write|delete — but the engine
	// does not bake a vocabulary; it is the app's).
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

// rlsEmitMode compiles a column-condition (visibility) term: `mode <col> = "<v>"
// [for <subject>]`. A row whose ModeCol equals the sentinel is admitted; an
// actor-scoped form confines it to a principal plane (operators-only for `for
// admin`). This is the de-prescribed form of emitDescriptor's read-mode disjuncts.
func (s *Spec) rlsEmitMode(t *Term, custClaim string) []string {
	frag := fmt.Sprintf("%s = '%s'", t.ModeCol, t.ModeVal)
	if t.ModeScope != "" {
		frag = fmt.Sprintf("%s AND %s", frag, s.modePlaneScope(t.ModeScope, custClaim))
	}
	return []string{frag}
}

// rlsEmitWalk compiles a role-walk into a parent relation (e.g. `tenant->owner`):
// the admin owns/administers the parent node → a tenant/ancestor-admin definer
// call. Convention reproduces the live names: walk into relation R (to object/level
// X via column C) → auth.is_<X>_admin(<admin sub claim>, C).
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

// rlsEmitBuiltin compiles a builtin term (@open / @app_scope / @store_manage /
// @session / @kind). The handled flag is false (and frags/err nil) when the term is
// not a builtin and not a capability literal — the caller then resolves it as a
// relation.
func (s *Spec) rlsEmitBuiltin(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, custClaim string) ([]string, bool, error) {
	switch {
	case t.Builtin == "open":
		// @open (v3 WS6): an op deliberately unrestricted at the RLS layer (`true`).
		// The sanctioned use is a bootstrap INSERT the row engine cannot gate — a
		// login session / credential row written before any session claim exists
		// (the trusted auth code sets the owner column). Validation confines @open to
		// @rls insert; it is never a read/update/delete grant.
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
		// Typed-subject match: the caller's principal-kind claim equals the declared
		// value (the RLS form of a typed wildcard, e.g. `serviceaccount:*`). A
		// containment-scoped grant — `kind = '<value>'` over the request claims.
		return []string{fmt.Sprintf("%s = '%s'", s.claim("kind"), t.KindVal)}, true, nil
	case t.Builtin != "":
		return nil, true, fmt.Errorf("builtin @%s is not emittable in RLS", t.Builtin)
	case isPermKeyLit(t.Ident):
		return nil, true, fmt.Errorf("capability term %q belongs to the PDP, not RLS", t.Ident)
	}
	return nil, false, nil
}

// rlsEmitAppScope compiles @app_scope: the broad app/service reach
// (`<owner claim> IS NULL`), which may EXCLUDE rows owned via an owner axis
// (`@app_scope(exclude admin_owner)`), so an admin-owned row stays reachable only by
// its owning admin + grants (operator-private). The excluded axis is an owner
// ViaColumn whose PRESENCE is excluded — emitted as existence-negation (NOT
// principal-match), the soundness invariant: one operator never sees another's
// admin-owned rows.
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
		// "Not owned via this axis": a discriminated owner excludes the kind column
		// distinct from the value (NULL kind = unowned, passes); a plain column
		// excludes the column being non-NULL.
		if vc.DiscrimCol != "" {
			base = fmt.Sprintf("(%s AND %s IS DISTINCT FROM '%s')", base, vc.DiscrimCol, vc.DiscrimVal)
		} else {
			base = fmt.Sprintf("(%s AND %s IS NULL)", base, vc.Column)
		}
	}
	return []string{base}, nil
}

// rlsEmitStoreManage compiles @store_manage: the write-moat for a discriminated
// grant store (v0.28.0). The caller may write/list/revoke a row iff it can EDIT the
// resource the row points at. Emits auth.<store>_manage(<discrim>, <record>) over the
// row's own columns; the generated dispatch CASEs the discriminator to the kind's
// can-edit.
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

// rlsEmitSession compiles @session: the caller's session-selected node (the entity's
// own column = the leaf claim). `@session(<rel>)` gates it by a role (e.g.
// project-admin of your selected project).
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

// rlsEmitRelation compiles a relation term to its predicate fragments, dispatching
// on the relation's representation.
func (s *Spec) rlsEmitRelation(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, custClaim string) ([]string, error) {
	r := rels[t.Ident]
	if r == nil {
		return nil, fmt.Errorf("unknown relation %q", t.Ident)
	}
	access := accessFor(pm.Maps)
	pk := obj.Table + "." + obj.pk()
	switch repr := r.Repr.(type) {
	case ViaColumn:
		// Inline owner axis: the FK column equals the owner's claim. The claim key
		// comes from the relation's DECLARED TYPE subject (e.g. `owner: admin via
		// admin_user_id` → the admin's `sub`), falling back to the object's owner
		// plane. Resolving from the relation's type — not only the leaf owner subject
		// — lets a GLOBAL object (above tenancy, no owner plane at its virtual leaf)
		// still carry an owner axis (admin_user_id = sub). Byte-identical for Foir,
		// whose owner relations' first type IS the leaf owner subject.
		claimKey := s.relationClaim(r, custClaim)
		if err := reqClaim(claimKey, obj, "owner relation "+t.Ident); err != nil {
			return nil, err
		}
		base := fmt.Sprintf("%s = %s", repr.Column, s.claim(claimKey))
		// A discriminated owner (`via owner_id where owner_kind = "customer"`) gates
		// the id match by the kind column — the unified (owner_id, owner_kind) shape.
		if repr.DiscrimCol != "" {
			base = fmt.Sprintf("(%s AND %s = '%s')", base, repr.DiscrimCol, repr.DiscrimVal)
		}
		return []string{base}, nil
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
	case ViaGroup:
		// Nested groups (v3 WS2): the caller's claim is a transitive member of the
		// group named by the row's repr.Col — an indexed read over the
		// trigger-maintained membership closure. Note the argument order is
		// (group, member): the group is the row's column, the member is the claim.
		if err := reqClaim(custClaim, obj, "group relation "+t.Ident); err != nil {
			return nil, err
		}
		if repr.Materialized {
			// WS3 step 2: the floor probes the trigger-maintained flat by (resource,
			// principal) instead of walking the closure — an O(1) index lookup, the
			// grant-dominant-list win. Through the SECURITY DEFINER <flat>_member so the
			// flat stays private (never granted to the querying role), like every other
			// auth read. flat == walk is the WS3 oracle's leak-critical invariant.
			return []string{fmt.Sprintf("%s_member(%s, %s)", s.groupFlatName(obj, r, repr), pk, s.claim(custClaim))}, nil
		}
		return []string{fmt.Sprintf("%s.%s_member(%s, %s)", s.definerSchema(), repr.Closure, repr.Col, s.claim(custClaim))}, nil
	case ViaMemberIn:
		// Scoped role-membership (v3 WS6): admin_memberin_<level>(principal, scope) —
		// the principal holds an admin role at the scope level. Each arg is a claim
		// (@<key>) or a row column. Guard-ridden (see guardable): the tenant picker's
		// membership branch carries the CHURNED guard, like the live policy.
		name := fmt.Sprintf("%s_memberin_%s", s.adminName(), repr.Level)
		return []string{fmt.Sprintf("%s.%s(%s, %s)", s.definerSchema(), name, s.argSrcSQL(repr.Principal), s.argSrcSQL(repr.Scope))}, nil
	case ViaObject:
		// Cross-object permission reference (v3 WS3 — tuple_to_userset): the caller
		// passes the other object's <verb> for the related row named by repr.Col. The
		// generated definer runs that object's full predicate (claims read from the
		// GUC inside it), so no claim is threaded through the call here.
		return []string{fmt.Sprintf("%s.%s_can_%s(%s)", s.definerSchema(), repr.Object, repr.Verb, repr.Col)}, nil
	case ViaGrant:
		// A bare grant relation (`grantee`, no access class): the access defaults to
		// the op's class (select→read, update/insert→write, delete→delete) — the same
		// rule the descriptor uses. An explicit selector (`grantee:read`) is handled
		// above; a bare reference on a create perm would emit a write-grant branch on
		// insert, so omit it there (matching the descriptor, which never grants insert).
		return s.emitGrantFrags(obj, r, &repr, accessFor(pm.Maps))
	case ViaRole:
		return s.rlsEmitRole(obj, r, repr)
	default:
		return nil, fmt.Errorf("relation %q has an unknown representation", r.Name)
	}
}

// rlsEmitRole compiles a ViaRole relation. A `via role` relation whose TYPE is the
// virtual-anchored role subject resolves to the platform-staff plane (the root-plane
// role definer has_<anchor>_role(<claim>) — no scope columns, NOT guard-ridden);
// otherwise it is a role membership on this object → a project-role definer call over
// the object's scope columns (a rank threshold narrows the fn).
func (s *Spec) rlsEmitRole(obj *Object, r *Relation, repr ViaRole) ([]string, error) {
	// Platform-staff plane (v3 WS6): a `via role` relation whose TYPE is the
	// virtual-anchored role subject resolves to the root-plane role definer,
	// has_<anchor>_role(<claim>) — no scope columns (a platform role pins none).
	// This is the COMPOSABLE form of the staff plane: a mixed object (tenants,
	// admin_users) lists `staff` alongside self/role/session, and it OR-composes
	// like any other term. It is NOT guard-ridden (see guardable): staff is the
	// operator plane, so it sees a CHURNED tenant just like the impersonation
	// operator does.
	if st := s.subjectByName(r.Types[0]); st != nil && s.isPlatformRoleSubject(st) {
		return []string{fmt.Sprintf("%s.%s(%s)", s.definerSchema(), platformRoleFn(st.Anchor), s.claim(st.Identifies))}, nil
	}
	// A role membership on this object → a project-role definer call over
	// the object's scope columns. Convention: auth.admin_has_<obj>_role(
	// <admin sub claim>, <scope cols>). A rank threshold narrows the fn.
	var cols []string
	for _, lvl := range obj.Scoped {
		cols = append(cols, s.scopeCol(obj, lvl))
	}
	// No rank → "has any role" (auth.<admin>_has_<obj>_role); a rank threshold
	// → the named rank predicate (auth.is_<rank>, e.g. is_project_admin).
	fn := fmt.Sprintf("%s_has_%s_role", s.adminName(), obj.Name)
	if repr.HasRank {
		fn = "is_" + repr.RankMin
	}
	return []string{fmt.Sprintf("%s.%s(%s, %s)", s.definerSchema(), fn, s.claim(s.adminIdentify()), strings.Join(cols, ", "))}, nil
}

// emitGrantFrags renders a grant relation's RLS fragments at a given access class:
// one auth.<store>_grants[_<kind>](<principal claim>, <table>.<pk>, '<access>') EXISTS
// per declared grantee kind, read against that kind's own claim. This is the
// de-prescribed form of emitDescriptor's grant-list disjuncts (same definer names,
// same args), so a pure-relation object reproduces the descriptor's grant SQL.
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

// ownerColPresent renders "this row is owned via this axis": `<col> IS NOT NULL`,
// or `<col> IS NOT NULL AND <kindCol> = '<kindVal>'` for a discriminated owner.
func ownerColPresent(vc ViaColumn) string {
	base := vc.Column + " IS NOT NULL"
	if vc.DiscrimCol == "" {
		return base
	}
	return fmt.Sprintf("%s AND %s = '%s'", base, vc.DiscrimCol, vc.DiscrimVal)
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
	sch := r.tableSchema()
	for _, t := range r.GovernedTables() {
		fmt.Fprintf(&b, "ALTER TABLE %s.%s ENABLE ROW LEVEL SECURITY;\n", sch, t)
		fmt.Fprintf(&b, "ALTER TABLE %s.%s FORCE ROW LEVEL SECURITY;\n", sch, t)
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
