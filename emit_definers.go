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
	Body   string // the SELECT expression (a boolean)
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
	return fmt.Sprintf(
		"CREATE OR REPLACE FUNCTION %s.%s(%s)\nRETURNS boolean\nLANGUAGE sql\nSTABLE\nSECURITY DEFINER\nSET search_path = public\nAS $$\n  SELECT %s;\n$$;",
		d.schema(), d.Name, d.Sig, d.Body)
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
		body := fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE %s = user_id AND %s = check_%s_id", g.Table, g.GranteeCol, g.LevelCol, g.Level)
		if g.ActiveCol != "" {
			body += fmt.Sprintf(" AND %s IS NULL", g.ActiveCol)
		}
		if g.ExpiresCol != "" {
			body += fmt.Sprintf(" AND %s > now()", g.ExpiresCol)
		}
		body += ")"
		out = append(out, GenFn{Name: name, Sig: fmt.Sprintf("user_id text, check_%s_id text", g.Level), Body: body})
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
	// auth.<store>_grants(customer, record, access) — EXISTS over the record_acl
	// store for a customer principal at the requested access.
	for _, obj := range s.Objects {
		if obj.Descriptor == nil || obj.Descriptor.Grants == nil {
			continue
		}
		// The principal kind the grant list filters on is spec-declared by the
		// descriptor's `list` mode (EID-265 WS2) — no list mode, no grants definer.
		kind := descriptorListKind(obj.Descriptor)
		if kind == "" {
			continue
		}
		g := obj.Descriptor.Grants
		name := g.Table + "_grants"
		if seen[name] {
			continue
		}
		seen[name] = true
		body := fmt.Sprintf(
			"EXISTS (SELECT 1 FROM %s WHERE %s = p_%s_id AND %s = '%s' AND %s = p_customer_id AND %s = p_access)",
			g.Table, g.RecordCol, obj.Name, g.KindCol, kind, g.PrincipalCol, g.AccessCol)
		out = append(out, GenFn{
			Name: name,
			Sig:  fmt.Sprintf("p_customer_id text, p_%s_id text, p_access text", obj.Name),
			Body: body,
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
		fn := fmt.Sprintf("is_%s_admin", lvl)
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
	objLevel := obj.Scoped[len(obj.Scoped)-1]
	keys := presetLevels[objLevel]
	if vr.HasRank {
		// is_<rank>: project-level presets at or above the rank threshold,
		// recursing to the parent-level admin fn (is_<ancestor>_admin).
		keys = atOrAbove(keys, vr.RankMin, rankIdx)
		recurse := s.parentLevelRecurse(obj)
		return s.roleDefiner("is_"+vr.RankMin, rs, objLevel, keys, recurse), true, nil
	}
	// admin_has_<obj>_role: any role at the object's level, no recursion.
	return s.roleDefiner(fmt.Sprintf("admin_has_%s_role", obj.Name), rs, objLevel, keys, ""), true, nil
}

// roleDefiner builds a role-resolution EXISTS over the role store at the given
// level (pinning ancestor scope cols, the level col, and NULLing deeper cols),
// optionally OR'd with a recursion call.
func (s *Spec) roleDefiner(name string, rs *RoleStore, level string, keys []string, recurse string) GenFn {
	chain, _ := s.Topology.Chain()
	var nonVirtual []string
	for _, l := range chain {
		if !l.Virtual {
			nonVirtual = append(nonVirtual, l.Name)
		}
	}
	// Build the per-scope-column predicate: pin root..level to args, NULL below.
	args := []string{"user_id text"}
	var scope []string
	hitLevel := false
	for i, lvl := range nonVirtual {
		if i >= len(rs.ScopeCols) {
			break
		}
		col := rs.ScopeCols[i]
		if !hitLevel {
			arg := "check_" + lvl + "_id"
			args = append(args, arg+" text")
			scope = append(scope, fmt.Sprintf("ra.%s = %s", col, arg))
			if lvl == level {
				hitLevel = true
			}
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
	return fmt.Sprintf("is_%s_admin(user_id, check_%s_id)", parent, parent)
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

// kernelDefiner builds the realtime/collab reachability gate over an object's
// own table: the owner axis (the customer owns the row).
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
	body := fmt.Sprintf("EXISTS (SELECT 1 FROM %s r WHERE r.id = p_%s_id AND r.%s = p_customer_id)", obj.Table, obj.Name, ownerCol)
	return GenFn{
		Name: fmt.Sprintf("customer_can_access_%s", obj.Name),
		Sig:  "p_customer_id text, p_" + obj.Name + "_id text, p_access text",
		Body: body,
	}, nil
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
