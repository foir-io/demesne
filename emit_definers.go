package demesne

import (
	"fmt"
	"sort"
	"strings"
)

// Definer kernel (RFC §8.2 V9): the compiler owns 100% of the SECURITY DEFINER
// surface — it GENERATES every trusted function the emitted policies call, so
// there are no opaque hand-written functions the isolation proof must trust.
// Bodies are canonical `sql` EXISTS over the declared stores (membership table,
// role-assignment store, the object's own table for the realtime gate).
//
// Generated functions for the Foir admin role model:
//   - <flag>(user_id)                       — membership (is_platform_admin)
//   - is_tenant_admin(user_id, t)           — tenant-level role, recurses ↑
//   - admin_has_<obj>_role(user_id, t, p)   — any project-level role
//   - is_<rank>(user_id, t, p)              — project-level role ≥ rank, recurses ↑
//   - <kernelfn>(customer, record, access)  — realtime gate (owner reachability)

// GenFn is a generated SECURITY DEFINER function.
type GenFn struct {
	Name   string // unqualified function name
	Schema string // the schema the function lives in ("" → "auth")
	Sig    string // argument signature, e.g. "user_id text, check_tenant_id text"
	Body   string // the SELECT expression (a boolean), or a full query when RawBody
	// Returns is the function's return type. Empty means "boolean" — the
	// canonical predicate definer (the body is a boolean SELECT expression). A
	// non-empty value (e.g. "TABLE(source text, principal_id text)") makes the
	// function set-returning; the body is then a complete query (RawBody), not a
	// scalar expression. Used by the accessor-enumerator (Expand): the read-side
	// dual that lists WHO can access a row, generated from the same descriptor the
	// RLS predicate compiles from.
	Returns string
	// RawBody renders Body verbatim inside the $$ … $$ (a complete SELECT / UNION
	// query) instead of wrapping it as `SELECT <Body>;`. Set for set-returning
	// definers whose body is a multi-branch query.
	RawBody bool
}

// schema returns the function's schema, defaulting to "auth".
func (d GenFn) schema() string {
	if d.Schema != "" {
		return d.Schema
	}
	return "auth"
}

// ArgTypes returns the comma-joined argument types of the signature (for a
// regprocedure lookup), e.g. "text, text, text".
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

// CreateSQL renders the full CREATE OR REPLACE FUNCTION statement.
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
		"CREATE OR REPLACE FUNCTION %s.%s(%s)\nRETURNS %s\nLANGUAGE sql\nSTABLE\nSECURITY DEFINER\nSET search_path = public\nAS $$\n%s\n$$;",
		d.schema(), d.Name, d.Sig, returns, body)
}

// DefinersSQL renders the full CREATE OR REPLACE FUNCTION set for the generated
// definers in dependency order (callee before caller), each via CreateSQL().
// CREATE OR REPLACE bodies round-trip byte-identical through pg_get_functiondef
// (the definer oracle proves it), so applying this to a live database is a no-op.
func DefinersSQL(defs []GenFn) string {
	var b strings.Builder
	for _, d := range defs {
		b.WriteString(d.CreateSQL())
		b.WriteString("\n\n")
	}
	return b.String()
}

// EmitDefiners generates every definer the spec's policies reference, in
// dependency order (a fn appears after the fns it calls).
func (s *Spec) EmitDefiners() ([]GenFn, error) {
	var out []GenFn

	// The virtual-level set, for re-deriving an object's predicate (cross-object
	// references below).
	vchain, _ := s.Topology.Chain()
	virtual := map[string]bool{}
	for _, l := range vchain {
		if l.Virtual {
			virtual[l.Name] = true
		}
	}

	// Membership operator fn (e.g. is_platform_admin) — a LEGACY unconditional
	// god-flag. The general, scoped form is a `grant` (below); a spec uses at most
	// one of the two as its operator.
	for _, sub := range s.Subjects {
		m := sub.Membership
		if m == nil {
			continue
		}
		if m.IDCol == "" || m.FlagCol == "" {
			return nil, fmt.Errorf("subject %q membership needs (idcol, flagcol)", sub.Name)
		}
		body := fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s = user_id AND %s", m.Table, m.IDCol, m.FlagCol)
		if m.ActiveCol != "" {
			body += fmt.Sprintf(" AND %s = '%s'", m.ActiveCol, m.ActiveVal)
		}
		body += ")"
		out = append(out, GenFn{Name: m.FlagCol, Sig: "user_id text", Body: body})
	}

	// Level-scoped grant-reach fns: an active grant edge confers reach into a
	// topology level. auth.<table>_reach(user_id, check_<level>_id) EXISTS over
	// the grant store. These are BOTH a disjunct of the level's role definer AND a
	// top-level OR branch on objects scoped under that level, so they are emitted
	// before the role definers that call them (callee before caller).
	gseen := map[string]bool{}
	for _, g := range s.Grants {
		name := g.Table + "_reach"
		if gseen[name] {
			continue
		}
		gseen[name] = true
		// Shared reachability-grant shape; conjuncts are this grant's own: grantee
		// match, the level-subtree target, then the validity gates.
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
		out = append(out, GenFn{Name: name, Sig: fmt.Sprintf("user_id text, check_%s_id text", g.Level), Body: grantEdgeExists(g.Table, conj...)})
	}

	// Role-resolution fns, derived from each object's role relations + walks.
	rs := roleStoreByName(s)
	rankIdx := rankIndex(s)
	presetLevels := presetLevelMap(s)

	seen := map[string]bool{}
	for _, obj := range s.Objects {
		rels := map[string]*Relation{}
		for _, r := range obj.Relations {
			rels[r.Name] = r
		}
		for _, pm := range obj.Perms {
			for _, t := range pm.Expr {
				d, ok, err := s.roleDefinerForTerm(obj, pm, t, rels, rs, rankIdx, presetLevels)
				if err != nil {
					return nil, err
				}
				if ok && !seen[d.Name] {
					seen[d.Name] = true
					out = append(out, d)
				}
			}
		}
	}

	// Platform-anchored role definers (v3 WS6 — the platform plane). A role-bearing
	// subject anchored at the VIRTUAL root governs the global objects (the tables
	// above tenancy). Its definer is the SAME role-resolution EXISTS every other
	// role uses, lifted to the schema root: has_<anchor>_role(user_id) over the role
	// store with every scope column NULL. The name is DELIBERATELY not the legacy
	// `is_platform_admin` — the god-flag retires in full, so the policy text itself
	// must read as a revocable role check (a `role_assignments` row), not a renamed
	// standing boolean. No bespoke hand-written function: same primitive as every
	// tenant/project role, lifted to the platform root.
	for _, sub := range s.Subjects {
		if !s.isPlatformRoleSubject(sub) || rs == nil {
			continue
		}
		name := platformRoleFn(sub.Anchor)
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, s.roleDefiner(name, rs, sub.Anchor, presetLevels[sub.Anchor], ""))
	}

	// Scoped role-membership definers (v3 WS6): admin_memberin_<level>(principal,
	// scope) = does the principal hold ANY admin role assignment at that scope
	// level (not revoked)? One definer per (adminName, level); the RLS term supplies
	// the principal/scope args (claim or row column). Powers the tenant picker
	// ("tenants I administer") and admin_users co-tenant visibility from one shape.
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
			scopeCol := s.scopeColForLevel(rs, mi.Level)
			body := fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s = p_principal AND %s = p_%s AND %s = '%s' AND %s IS NULL)",
				rs.Assignments, rs.SubjectCol, scopeCol, mi.Level, rs.KindCol, rs.KindVal, rs.RevokedCol)
			out = append(out, GenFn{Name: name, Sig: fmt.Sprintf("p_principal text, p_%s text", mi.Level), Body: body})
		}
	}

	// Realtime gate fn(s): an object with a @kernel permission gets a
	// reachability function over its own table (owner axis).
	for _, obj := range s.Objects {
		for _, pm := range obj.Perms {
			if !contains(pm.Layers, "kernel") {
				continue
			}
			d, err := s.kernelDefiner(obj)
			if err != nil {
				return nil, err
			}
			if !seen[d.Name] {
				seen[d.Name] = true
				out = append(out, d)
			}
		}
	}

	// Access-descriptor grant fns: an object with a descriptor grant store gets
	// auth.<store>_grants(<principal>, record, access) — EXISTS over the record_acl
	// store for the spec-declared principal kind at the requested access.
	for _, obj := range s.Objects {
		if obj.Descriptor == nil || obj.Descriptor.Grants == nil {
			continue
		}
		// The principal kinds the grant list filters on are spec-declared by the
		// descriptor's `list` modes (EID-265 WS2 was single-kind; Increment 2C lets
		// one resource be granted to SEVERAL kinds — e.g. a record to both customers
		// and admins). One definer per kind: same reachability-grant shape, keyed on
		// the kind's own grantee param + principal-kind gate.
		g := obj.Descriptor.Grants
		for i, kind := range descriptorListKinds(obj.Descriptor) {
			name, param, _ := s.grantKindBinding(obj, kind, i == 0)
			if seen[name] {
				continue
			}
			seen[name] = true
			// This grant's conjuncts are the row target, the principal-kind gate, the
			// grantee match, and the access — plus a constant discriminator when
			// several descriptors share this store.
			conjuncts := []string{fmt.Sprintf("%s = p_%s_id", g.RecordCol, obj.Name)}
			if g.DiscrimCol != "" {
				conjuncts = append(conjuncts, fmt.Sprintf("%s = '%s'", g.DiscrimCol, g.DiscrimVal))
			}
			conjuncts = append(conjuncts,
				fmt.Sprintf("%s = '%s'", g.KindCol, kind),
				fmt.Sprintf("%s = p_%s_id", g.PrincipalCol, param),
				fmt.Sprintf("%s = p_access", g.AccessCol),
			)
			body := grantEdgeExists(g.Table, conjuncts...)
			out = append(out, GenFn{
				Name: name,
				Sig:  fmt.Sprintf("p_%s_id text, p_%s_id text, p_access text", param, obj.Name),
				Body: body,
			})
		}
	}

	// Accessor enumerators (Expand — the read-side dual of the RLS predicate): for
	// every descriptor object with a grant store, auth.<table>_accessors(p_id)
	// returns the rows (source, principal_kind, principal_id, access) of every
	// NAMED accessor the SELECT predicate admits — owner column(s), the explicit
	// grant rows, and the role plane (role-bearing admins reachable via @app_scope).
	// "Public = everyone" is a category (the row's mode), not enumerated, so it is
	// folded in by the caller as a flag, not a row. Built from the SAME descriptor
	// the predicate compiles from (owner axes + grant edge + admin-owner gate + the
	// role store), so Expand agrees with <table>_select by construction — no second
	// evaluator. SECURITY DEFINER + set-returning; the handler calls it under the
	// caller's claims.
	for _, obj := range s.Objects {
		if obj.Descriptor == nil || obj.Descriptor.Grants == nil {
			continue
		}
		name := obj.Table + "_accessors"
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, s.accessorDefiner(obj))
	}

	// Structural accessor enumerators (Expand over the role/staff CONTROL plane):
	// for every level-entity object (project, tenant, …), auth.<table>_accessors(p_id)
	// enumerates who can administer the node — role-holders (ROLE), platform staff
	// (STAFF), and the impersonation operators (IMPERSONATION). The control plane has
	// no owner/grant/visibility axes; every accessor is a NAMED principal (no
	// "everyone" category) read from the role store + impersonation grant the SELECT
	// predicate compiles from. Settings tables defer to their containing project/
	// tenant (containment-only access = the level's accessors), so only the level
	// entities get an enumerator.
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
			return nil, err
		}
		if ok {
			seen[name] = true
			out = append(out, d)
		}
	}

	// Closure-reachability lookups (WS3 Phase C): an indexed EXISTS over a
	// trigger-maintained transitive-closure table — the row's node is reachable
	// from the subject's granted ancestor. The maintenance trigger is generated
	// separately (EmitTriggers); this is the read side the RLS term calls.
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
			out = append(out, GenFn{
				Name: name,
				Sig:  "p_ancestor text, p_descendant text",
				Body: fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s = p_ancestor AND %s = p_descendant)", c.Closure, c.AncestorCol, c.DescendantCol),
			})
		}
	}

	// Nested-group membership lookups (v3 WS2): is a principal a transitive member
	// of a group? An indexed EXISTS over the membership closure (group, member).
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
			out = append(out, GenFn{
				Name: name,
				Sig:  "p_group text, p_member text",
				Body: fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s = p_group AND %s = p_member)", g.Closure, g.GroupCol, g.MemberCol),
			})
		}
	}

	// Cross-object permission references (v3 WS3): `auth.<Other>_can_<verb>(id)` runs
	// the OTHER object's full <verb> predicate for the related row — so a comment's
	// reader can be "the parent document's reader", borrowing whatever roles / ACLs
	// / groups / boolean that object's policy uses, evaluated at the related row.
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
				return nil, fmt.Errorf("relation %q references unknown object %q", r.Name, vo.Object)
			}
			pred, err := s.objectVerbPredicate(other, vo.Verb, virtual)
			if err != nil {
				return nil, err
			}
			out = append(out, GenFn{
				Name: name,
				Sig:  fmt.Sprintf("p_%s_id text", vo.Object),
				Body: fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s.id = p_%s_id AND (%s))", other.Table, other.Table, vo.Object, pred),
			})
		}
	}

	// Write-moat dispatch (v0.28.0): for every discriminated grant store named by a
	// @store_manage write-governance object, auth.<store>_manage(p_type, p_id) CASEs
	// the discriminator to the matching KIND's can-edit predicate — fail-closed
	// (ELSE false). Each kind's auth.<O>_can_edit(p_id) runs that object's full edit
	// predicate AT the row (the same EXISTS-over-table shape as a cross-object
	// borrow). The set of kinds is the spec's descriptor objects on the store
	// (compile-time platform STRUCTURE); per-model access config is a runtime-data
	// layer the edit predicate reads, never baked here.
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
		var whens []string
		for _, o := range s.storeDescriptors(store) {
			canEdit := o.Name + "_can_edit"
			if !seen[canEdit] {
				seen[canEdit] = true
				pred, err := s.objectVerbPredicate(o, "edit", virtual)
				if err != nil {
					return nil, fmt.Errorf("@store_manage dispatch for %q: %w", store, err)
				}
				out = append(out, GenFn{
					Name: canEdit,
					Sig:  "p_id text",
					Body: fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s.id = p_id AND (%s))", o.Table, o.Table, pred),
				})
			}
			whens = append(whens, fmt.Sprintf("WHEN '%s' THEN %s.%s(p_id)", o.Descriptor.Grants.DiscrimVal, s.definerSchema(), canEdit))
		}
		name := storeManageName(store)
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, GenFn{
			Name: name,
			Sig:  "p_type text, p_id text",
			Body: fmt.Sprintf("(CASE p_type %s ELSE false END)", strings.Join(whens, " ")),
		})
	}

	// Stamp the configured definer schema on every generated function so CreateSQL
	// qualifies them consistently (default "auth" keeps Foir's SQL byte-identical).
	for i := range out {
		out[i].Schema = s.definerSchema()
	}
	return out, nil
}

// roleDefinerForTerm returns the definer a role-bearing term needs (a walk into
// a parent level, or a via-role relation), or ok=false for non-role terms.
func (s *Spec) roleDefinerForTerm(obj *Object, pm *Perm, t *Term, rels map[string]*Relation, rs *RoleStore, rankIdx map[string]int, presetLevels map[string][]string) (GenFn, bool, error) {
	if rs == nil {
		return GenFn{}, false, nil
	}
	// Ancestor walk: `<rel>-><verb>` → is_<level>_admin, role at that ancestor
	// level (deeper scope cols pinned NULL), OR'd with the operator's reach AT
	// that level (an unconditional god-flag, or a scoped grant — see operatorReach).
	if t.WalkVerb != "" {
		parent := rels[t.Ident]
		if parent == nil {
			return GenFn{}, false, fmt.Errorf("walk references unknown relation %q", t.Ident)
		}
		lvl := parent.Types[0] // the level the walk targets (e.g. tenant)
		fn := fmt.Sprintf("is_%s_%s", lvl, s.adminName())
		keys := presetLevels[lvl] // all presets bound at that level
		return s.roleDefiner(fn, rs, lvl, keys, s.operatorReach(lvl)), true, nil
	}
	// A via-role relation on this object — referenced directly, or session-gated
	// via `@session(<rel>)`.
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
	// The platform-staff plane (a via-role targeting a virtual-anchored role
	// subject) is NOT an object-scoped role — it resolves to has_<anchor>_role,
	// generated by the dedicated platform-role loop. Skip it here so we don't also
	// emit a spurious (unreferenced) <admin>_has_<obj>_role for it.
	if len(r.Types) > 0 {
		if st := s.subjectByName(r.Types[0]); st != nil && s.isPlatformRoleSubject(st) {
			return GenFn{}, false, nil
		}
	}
	objLevel := obj.Scoped[len(obj.Scoped)-1]
	keys := presetLevels[objLevel]
	if vr.HasRank {
		// is_<rank>: project-level presets at or above the rank threshold,
		// recursing to the parent-level admin fn (is_<ancestor>_admin).
		keys = atOrAbove(keys, vr.RankMin, rankIdx)
		recurse := s.parentLevelRecurse(obj)
		return s.roleDefiner("is_"+vr.RankMin, rs, objLevel, keys, recurse), true, nil
	}
	// <admin>_has_<obj>_role: any role at the object's level, no recursion.
	return s.roleDefiner(fmt.Sprintf("%s_has_%s_role", s.adminName(), obj.Name), rs, objLevel, keys, ""), true, nil
}

// roleDefiner builds a role-resolution EXISTS over the role store at the given
// level (pinning ancestor scope cols, the level col, and NULLing deeper cols),
// optionally OR'd with a recursion call.
func (s *Spec) roleDefiner(name string, rs *RoleStore, level string, keys []string, recurse string) GenFn {
	// The role store's scope columns are a fixed ordered set; pin root..level to
	// args and NULL the columns BELOW level. This needs the full nonVirtual level
	// sequence the scope columns map to (the topological order), not just the
	// ancestor path — a tenant-level role must NULL project_id. (WS3: a branching
	// tree whose roles span multiple branches needs per-branch scope columns, out
	// of scope here; single-branch role stays identical to the chain case.)
	chain, _ := s.Topology.Chain()
	var nonVirtual []string
	for _, l := range chain {
		if !l.Virtual {
			nonVirtual = append(nonVirtual, l.Name)
		}
	}
	// A non-virtual level is PINNED to an arg iff it is on the role-anchor's
	// root→level path (root..level inclusive); every level below is NULL'd. This is
	// the path-aware form of the chain-era "pin root..level, NULL below" — and it
	// handles a VIRTUAL anchor (the platform root) for free: the virtual root has
	// NO non-virtual ancestor, so every scope column is NULL and the signature is
	// just (user_id) — `is_platform_<role>(user_id)`, a role at the schema root
	// (v3 WS6, the general retirement of the is_platform_admin god-flag).
	onPath := map[string]bool{}
	if path, err := s.Topology.AncestorPath(level); err == nil {
		for _, l := range path {
			onPath[l.Name] = true
		}
	}
	// Build the per-scope-column predicate: pin the anchor's ancestry to args, NULL
	// every level below it.
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

// parentLevelRecurse returns the recursion call a project-level rank fn makes —
// the ancestor-level admin fn (is_<parent>_admin(user_id, check_<parent>_id)),
// or, when the object is already at the top non-virtual level, the operator's
// reach at that level (a god-flag or a scoped grant; "" if no operator).
func (s *Spec) parentLevelRecurse(obj *Object) string {
	if len(obj.Scoped) < 2 {
		return s.operatorReach(obj.Scoped[len(obj.Scoped)-1])
	}
	parent := obj.Scoped[len(obj.Scoped)-2]
	return fmt.Sprintf("is_%s_%s(user_id, check_%s_id)", parent, s.adminName(), parent)
}

// operatorReach returns the recursion predicate the privileged ("operator")
// subject contributes to a role-resolution definer AT a given level — the
// disjunct by which an operator satisfies that level's admin authority:
//   - a LEGACY membership operator → its unconditional flag fn, level-independent
//     (e.g. `is_platform_admin(user_id)`);
//   - a SCOPED grant operator whose grant is at this level → the grant-reach call
//     (`<table>_reach(user_id, check_<level>_id)`), gated by an active grant edge;
//   - "" if no operator contributes here (the role definer is then the bare role
//     EXISTS — no ambient cross-tenant authority).
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

// platformRoleFn is the generated name of a platform-anchored role definer:
// has_<anchor>_role (e.g. has_platform_role). Centralised so the kernel emitter
// and the RLS emitter agree on the one name. Deliberately distinct from the
// legacy is_platform_admin god-flag — the policy must read as a revocable role.
func platformRoleFn(anchor string) string { return "has_" + anchor + "_role" }

// isPlatformRoleSubject reports whether a subject is the platform-plane role
// subject (v3 WS6): a role-bearing subject (configurable roles, not `roles none`)
// anchored at a VIRTUAL level, and NOT an operator (no membership god-flag, no
// grant-conferred reach). Such a subject contributes the platform-role branch on
// global objects and drives the generated is_<anchor>_<adminName> definer. The
// virtual anchor is what distinguishes it from an ordinary tenant/project role
// subject (which pins scope columns); V7 already requires an empty-pin subject to
// anchor virtually, so this is the sanctioned root-plane authority.
func (s *Spec) isPlatformRoleSubject(sub *Subject) bool {
	return sub.Roles != "" && !sub.RolesNone && sub.Membership == nil &&
		sub.Reach != "grant" && s.levelIsVirtual(sub.Anchor)
}

// descriptorPrincipal returns the name of the claim-bearing owner principal for
// an object's descriptor / owner axis — the `reach self` + roles subject at the
// object's leaf level (EID-265 WS2). It drives the generated grant + realtime-gate
// signatures so they name the spec's ACTUAL principal (Foir: "customer"; the
// worked example: "member"), instead of assuming a customer principal. Falls back
// to the first declared owner type — a descriptor with no claim-bearing subject is
// rejected by reqClaim before any claim-bearing predicate is emitted.
func (s *Spec) descriptorPrincipal(obj *Object) string {
	if sub := s.ownerSubject(obj.Scoped[len(obj.Scoped)-1]); sub != nil {
		return sub.Name
	}
	if obj.Descriptor != nil && obj.Descriptor.Owner != nil && len(obj.Descriptor.Owner.Types) > 0 {
		return obj.Descriptor.Owner.Types[0]
	}
	return "principal"
}

// accessorDefiner builds the Expand enumerator auth.<table>_accessors(p_id) for a
// descriptor object: a set-returning SECURITY DEFINER listing every NAMED
// accessor the SELECT predicate admits, each tagged with its source. It is the
// read-side inverse of emitDescriptor — owner column(s) → OWNER rows, the grant
// edge → GRANT rows, the role store (gated by the admin-owner exclusion, exactly
// as @app_scope is) → ROLE rows — so the enumerated set equals who <table>_select
// admits (modulo the `public` category, surfaced as a flag, not a member list).
// Owners report 'write' (full control), role-reachers 'read' (the category floor;
// the grant rows carry their own revocable access verbatim).
func (s *Spec) accessorDefiner(obj *Object) GenFn {
	d := obj.Descriptor
	owner, _ := d.Owner.Repr.(ViaColumn)
	ownerKind := s.descriptorPrincipal(obj)

	var branches []string
	// OWNER — the customer-plane owner column.
	branches = append(branches, fmt.Sprintf(
		"SELECT 'owner'::text AS source, '%s'::text AS principal_kind, %s AS principal_id, 'write'::text AS access\n    FROM %s WHERE id = p_id AND %s IS NOT NULL",
		ownerKind, owner.Column, obj.Table, owner.Column))

	// OWNER — the optional admin-plane owner column (operator-private rows).
	var adminOwnerCol string
	if d.AdminOwner != nil {
		if ac, ok := d.AdminOwner.Repr.(ViaColumn); ok {
			adminOwnerCol = ac.Column
			adminKind := "admin"
			if len(d.AdminOwner.Types) > 0 {
				adminKind = d.AdminOwner.Types[0]
			}
			branches = append(branches, fmt.Sprintf(
				"SELECT 'owner'::text, '%s'::text, %s, 'write'::text\n    FROM %s WHERE id = p_id AND %s IS NOT NULL",
				adminKind, adminOwnerCol, obj.Table, adminOwnerCol))
		}
	}

	// GRANT — the explicit resource_acl rows (the only revocable accessors),
	// filtered by the descriptor's discriminator when the store is shared.
	g := d.Grants
	grantConds := []string{fmt.Sprintf("%s = p_id", g.RecordCol)}
	if g.DiscrimCol != "" {
		grantConds = append(grantConds, fmt.Sprintf("%s = '%s'", g.DiscrimCol, g.DiscrimVal))
	}
	branches = append(branches, fmt.Sprintf(
		"SELECT 'grant'::text, %s, %s, %s\n    FROM %s WHERE %s",
		g.KindCol, g.PrincipalCol, g.AccessCol, g.Table, strings.Join(grantConds, " AND ")))

	// ROLE — the role plane: admins holding a role that reaches the row's scope
	// (ancestor-or-equal: every scope level above the leaf pinned to equality —
	// which excludes platform roles whose scope is NULL — and the leaf NULL-or-equal
	// so a tenant-level role reaches a project row). Gated by the admin-owner
	// exclusion, mirroring @app_scope: an admin-owned row is operator-private, so it
	// has no role accessors. This is the only branch over current+future holders;
	// the handler/UI may collapse it into a single "via role" category.
	if rs := roleStoreByName(s); rs != nil {
		var scopeConds []string
		for i, lvl := range obj.Scoped {
			if i >= len(rs.ScopeCols) {
				break
			}
			rsCol := rs.ScopeCols[i]
			rowCol := scopeCol(obj, lvl)
			if i == len(obj.Scoped)-1 {
				scopeConds = append(scopeConds, fmt.Sprintf("(ra.%s IS NULL OR ra.%s = r.%s)", rsCol, rsCol, rowCol))
			} else {
				scopeConds = append(scopeConds, fmt.Sprintf("ra.%s = r.%s", rsCol, rowCol))
			}
		}
		where := []string{"r.id = p_id"}
		if adminOwnerCol != "" {
			where = append(where, fmt.Sprintf("r.%s IS NULL", adminOwnerCol))
		}
		branches = append(branches, fmt.Sprintf(
			"SELECT 'role'::text, '%s'::text, ra.%s, 'read'::text\n    FROM %s r\n    JOIN %s ra ON ra.%s = '%s' AND ra.%s IS NULL AND %s\n    WHERE %s",
			rs.KindVal, rs.SubjectCol, obj.Table, rs.Assignments,
			rs.KindCol, rs.KindVal, rs.RevokedCol, strings.Join(scopeConds, " AND "),
			strings.Join(where, " AND ")))
	}

	return GenFn{
		Name:    obj.Table + "_accessors",
		Sig:     "p_id text",
		Returns: "TABLE(source text, principal_kind text, principal_id text, access text)",
		RawBody: true,
		Body:    "  " + strings.Join(branches, "\n  UNION ALL\n  "),
	}
}

// structuralAccessorDefiner builds auth.<table>_accessors(p_id) for a level-entity
// (control-plane) object — the Expand enumerator over the role/staff plane. It
// walks the object's SELECT permission terms, mapping each to a principal
// enumeration: a platform-staff via-role → STAFF; a role-walk into a parent level,
// a via-role, or a via-memberin → ROLE at the matching scope; and (for a level
// entity reachable by the operator grant) the active impersonation grants →
// IMPERSONATION. @session / containment builtins add no NEW principals (they are
// the mechanism by which the enumerated role-holders' claims match) and are
// skipped. UNION (not UNION ALL) so a principal reachable two ways lists once per
// distinct (source, principal). Returns ok=false if there are no enumerable terms.
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
	// The operator (impersonation) grant auto-applies to a level entity reachable
	// at the grant's level — enumerate the active grants for the row's scope.
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

// structuralTermEnum maps one SELECT-permission term of a control-plane object to
// its principal-enumeration branch(es). Mirrors roleDefinerForTerm, but emits the
// enumeration (who satisfies the term) instead of the boolean check.
func (s *Spec) structuralTermEnum(obj *Object, t *Term, rels map[string]*Relation, rs *RoleStore, presetLevels map[string][]string, rankIdx map[string]int) ([]string, error) {
	if t.WalkVerb != "" {
		// Role-walk into a parent level (e.g. tenant->owner): the parent level's
		// admin roles. The parent's operator reach is covered by the impersonation
		// branch (added once per object), so this stays roles-only.
		parent := rels[t.Ident]
		if parent == nil {
			return nil, fmt.Errorf("structural accessors: walk references unknown relation %q", t.Ident)
		}
		lvl := parent.Types[0]
		return []string{s.roleEnumSQL(obj, rs, lvl, presetLevels[lvl], "role", "read")}, nil
	}
	if t.Builtin != "" {
		// @session / @app_scope / @open contribute no NEW enumerable principals.
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
				// The platform-staff plane: has_<anchor>_role holders (NULL scope).
				return []string{s.roleEnumSQL(obj, rs, st.Anchor, presetLevels[st.Anchor], "staff", "write")}, nil
			}
		}
		objLevel := obj.Scoped[len(obj.Scoped)-1]
		keys := presetLevels[objLevel]
		if repr.HasRank {
			keys = atOrAbove(keys, repr.RankMin, rankIdx)
		}
		return []string{s.roleEnumSQL(obj, rs, objLevel, keys, "role", "read")}, nil
	case ViaMemberIn:
		// Any admin role at the named level scope (no preset filter, descendants of
		// that scope included — the memberin shape).
		return []string{s.memberinEnumSQL(obj, rs, repr.Level)}, nil
	}
	return nil, nil
}

// roleEnumSQL enumerates the role store's admins holding a role at `level` that
// reaches this row's scope — pinning the level's root→level scope columns to the
// row's columns, NULLing the deeper ones (the inverse of roleDefiner's claim
// pinning), filtered to `presets` when non-empty. Tagged with `source` / `access`.
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
			conds = append(conds, fmt.Sprintf("ra.%s = e.%s", raCol, scopeCol(obj, lvl)))
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
		"SELECT '%s'::text AS source, '%s'::text AS principal_kind, ra.%s AS principal_id, '%s'::text AS access\n    FROM %s e JOIN %s ra ON ra.%s = '%s' AND ra.%s IS NULL AND %s%s\n    WHERE e.id = p_id",
		source, rs.KindVal, rs.SubjectCol, access, obj.Table, rs.Assignments,
		rs.KindCol, rs.KindVal, rs.RevokedCol, strings.Join(conds, " AND "), join)
}

// memberinEnumSQL enumerates admins with ANY role at the given level's scope (the
// via-memberin shape: a tenant member is anyone with a role anywhere in the
// tenant, regardless of project) — so the deeper scope columns are NOT NULL-pinned.
func (s *Spec) memberinEnumSQL(obj *Object, rs *RoleStore, level string) string {
	return fmt.Sprintf(
		"SELECT 'role'::text, '%s'::text, ra.%s, 'read'::text\n    FROM %s e JOIN %s ra ON ra.%s = '%s' AND ra.%s IS NULL AND ra.%s = e.%s\n    WHERE e.id = p_id",
		rs.KindVal, rs.SubjectCol, obj.Table, rs.Assignments, rs.KindCol, rs.KindVal,
		rs.RevokedCol, s.scopeColForLevel(rs, level), scopeCol(obj, level))
}

// impersonationEnumSQL enumerates the operators holding an ACTIVE impersonation
// grant reaching this row's grant-level scope (e.g. the tenant) — the IMPERSONATION
// plane, the same active-grant gate impersonation_grants_reach checks.
func (s *Spec) impersonationEnumSQL(obj *Object, g *Grant) string {
	conds := []string{fmt.Sprintf("ig.%s = e.%s", g.LevelCol, scopeCol(obj, g.Level))}
	if g.ActiveCol != "" {
		conds = append(conds, fmt.Sprintf("ig.%s IS NULL", g.ActiveCol))
	}
	if g.ExpiresCol != "" {
		conds = append(conds, fmt.Sprintf("ig.%s > now()", g.ExpiresCol))
	}
	return fmt.Sprintf(
		"SELECT 'impersonation'::text, 'admin'::text, ig.%s, 'write'::text\n    FROM %s e JOIN %s ig ON %s\n    WHERE e.id = p_id",
		g.GranteeCol, obj.Table, g.Table, strings.Join(conds, " AND "))
}

// levelOnObjectPath reports whether a topology level is on the object's scope path
// (so an operator grant at that level reaches the object's rows).
func (s *Spec) levelOnObjectPath(obj *Object, level string) bool {
	for _, l := range obj.Scoped {
		if l == level {
			return true
		}
	}
	return false
}

// kernelDefiner builds the realtime/collab reachability gate over an object's
// own table: the owner axis (the owner principal owns the row).
func (s *Spec) kernelDefiner(obj *Object) (GenFn, error) {
	var ownerCol string
	for _, r := range obj.Relations {
		if r.Name == "owner" {
			if vc, ok := r.Repr.(ViaColumn); ok {
				ownerCol = vc.Column
			}
		}
	}
	if ownerCol == "" && obj.Descriptor != nil && obj.Descriptor.Owner != nil {
		if vc, ok := obj.Descriptor.Owner.Repr.(ViaColumn); ok {
			ownerCol = vc.Column
		}
	}
	if ownerCol == "" {
		return GenFn{}, fmt.Errorf("object %q has a @kernel perm but no owner column", obj.Name)
	}
	principal := s.descriptorPrincipal(obj)
	body := fmt.Sprintf("EXISTS (SELECT 1 FROM %s r WHERE r.id = p_%s_id AND r.%s = p_%s_id)", obj.Table, obj.Name, ownerCol, principal)
	return GenFn{
		Name: fmt.Sprintf("%s_can_access_%s", principal, obj.Name),
		Sig:  fmt.Sprintf("p_%s_id text, p_%s_id text, p_access text", principal, obj.Name),
		Body: body,
	}, nil
}

// scopeColForLevel returns the role store's scope column for a topology level
// (the rolestore's ScopeCols are ordered by the non-virtual chain). Falls back to
// "<level>_id" if the level is past the declared scope columns.
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

// rankIndex maps a preset to its position in the rank ladder (0 = highest).
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

// presetLevelMap groups preset names by their @level annotation.
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

// atOrAbove returns the presets in `keys` whose rank is >= threshold (lower or
// equal index in the ladder).
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
