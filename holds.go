package demesne

import (
	"fmt"
	"sort"
	"strings"
)

// Holds-resolver (Layer 2, EID-334) — the load-bearing runtime-glue piece the
// engine compiled enforcement for but never computed. The emitted PDP map and
// PDP.Authorize(proc, holds) take a `holds(perm) -> bool` callback; nothing told
// an adopter how to PRODUCE it. So every adopter hand-writes "given a principal +
// scope, what permission set do they hold?" — Foir wrote it TWICE (a session-cached
// resolver and a DB-backed one), each re-implementing the rolestore read, the scope
// match, and the preset/rank expansion. Demesne already owns the rolestore schema
// (it generates the role-resolution definers from it) and the vocabulary (presets +
// rank), so this operation is mechanically derivable from the spec. This file
// derives it.
//
// The read/compute split mirrors access_runtime.go (the shipped grant template):
//
//   - READ (the database) — HoldsResolver.AssignmentsSQL() BUILDS a query the
//     CALLER executes (under the principal's own claims for the self case, or as a
//     trusted internal read for another subject). The engine never runs it; the
//     database returns the rows. Like every other runtime helper this keeps the
//     moat: authorization state lives in the DB, the engine only shapes the
//     statement. It is the GENERIC active-assignment read derived from the
//     rolestore; an adopter whose admission policy excludes further rows composes
//     those filters itself (see AssignmentsSQL — Demesne does not bake adopter
//     policy into the engine).
//   - COMPUTE (this engine) — HoldsResolver.Resolve(rows, scope) applies the
//     scope-containment match (derived from the rolestore's scope columns) and
//     unions the matched assignments' permissions into the effective set, returning
//     an EffectivePerms whose Holds(perm) method IS the PDP.Authorize callback. Pure
//     stdlib, no policy re-evaluation: it folds rows the DB already returned. This
//     compute reproduces the hand-written effective-permission resolver exactly.
//   - EXPAND (this engine) — Vocabulary.PresetPermissions(name) turns a role preset
//     into its flat permission set (the preset/rank vocabulary logic), so a caller
//     never re-implements it. It is the seed/validation source for a materialized
//     permissions column AND the resolve-time expansion when no such column exists.
//
// Target-neutral by construction. The SQL build and the MATERIALIZED-column compute
// (Foir's actual path) are a small pure transform over the HoldsResolver projection
// — exported, plain-data string/[]string fields — plus RoleAssignment rows, so a
// TypeScript emitter reproduces them from the same projection, not a rewrite. The
// EXPAND path additionally reads the vocabulary (presets/permissions/rank); a
// non-Go target reproducing it must also project the vocabulary as plain data and
// re-host PresetPermissions over that projection. Sorted outputs use Go byte order;
// a cross-target port should pin the same (code-point) comparator for ASCII-plus
// permission keys. Nothing here names a tenant/project/customer/role: every part
// derives from the spec's declared rolestore, scope columns, and vocabulary
// (EID-267 / EID-315).

// --- vocabulary expansion (preset -> permissions, rank) ---------------------

// vocabByName returns the named vocabulary, or nil.
func (s *Spec) vocabByName(name string) *Vocabulary {
	for _, v := range s.Vocabs {
		if v.Name == name {
			return v
		}
	}
	return nil
}

// presetByName returns the named preset within this vocabulary, or nil.
func (v *Vocabulary) presetByName(name string) *Preset {
	for _, p := range v.Presets {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// PresetPermissions expands a preset to its FLAT effective permission set: the
// vocabulary's whole permission list for a `*` (star) preset, otherwise the union
// of the preset's own permission keys and the recursive expansion of every preset
// it references. The result is deduplicated and sorted (deterministic). Errors on
// an unknown preset, a preset referencing a name that is neither a permission nor a
// preset, or a reference cycle (fail-closed — a cyclic preset resolves to no
// answer, never silently to a partial one). This is the single source the engine
// (and an adopter) uses to seed / validate a materialized permissions column and to
// resolve a role key when no such column exists — nobody re-implements preset/rank
// math.
func (v *Vocabulary) PresetPermissions(name string) ([]string, error) {
	into := map[string]bool{}
	if err := v.expandPreset(name, into, map[string]bool{}); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(into))
	for p := range into {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// expandPreset accumulates a preset's permissions into `into`, guarding against
// reference cycles via the `onStack` set.
func (v *Vocabulary) expandPreset(name string, into, onStack map[string]bool) error {
	if onStack[name] {
		return fmt.Errorf("vocabulary %q: preset %q is cyclic (a preset cannot reference itself, directly or transitively)", v.Name, name)
	}
	p := v.presetByName(name)
	if p == nil {
		return fmt.Errorf("vocabulary %q: no preset %q", v.Name, name)
	}
	if p.Star {
		for _, perm := range v.Permissions {
			into[perm] = true
		}
		return nil
	}
	perms := map[string]bool{}
	for _, perm := range v.Permissions {
		perms[perm] = true
	}
	onStack[name] = true
	defer delete(onStack, name)
	for _, item := range p.Set {
		switch {
		case perms[item]:
			into[item] = true
		case v.presetByName(item) != nil:
			if err := v.expandPreset(item, into, onStack); err != nil {
				return err
			}
		default:
			return fmt.Errorf("vocabulary %q: preset %q references %q, which is neither a permission nor a preset in this vocabulary", v.Name, name, item)
		}
	}
	return nil
}

// RankOf returns a preset's position in the vocabulary's rank ladder (0 = highest
// authority) and whether the preset is ranked. An unranked vocabulary or an
// unranked preset returns (0, false).
func (v *Vocabulary) RankOf(preset string) (int, bool) {
	for i, r := range v.Rank {
		if r == preset {
			return i, true
		}
	}
	return 0, false
}

// PresetsAtOrAbove returns the ranked presets whose authority is >= the threshold
// preset — the threshold and everything above it in the ladder, in ladder order
// (highest first). This is the delegation / keyset primitive ("the roles that
// satisfy rank >= threshold"); an unranked threshold returns nil.
func (v *Vocabulary) PresetsAtOrAbove(threshold string) []string {
	ti, ok := v.RankOf(threshold)
	if !ok {
		return nil
	}
	var out []string
	for i, r := range v.Rank {
		if i <= ti {
			out = append(out, r)
		}
	}
	return out
}

// --- the holds-resolver (read SQL + compute) --------------------------------

// HoldsResolver projects a rolestore (+ the vocabulary its roles draw from) into
// the "principal + scope -> effective permission set" operation. The exported
// fields are the read layout — one source of truth a handler builds the read from
// without re-deriving it (and a second-target TS emitter reads the same shape).
type HoldsResolver struct {
	// Assignment store.
	Assignments string   // the role-assignment table
	KindCol     string   // principal-kind column
	KindVal     string   // its required value (the assignment is for this kind)
	SubjectCol  string   // principal-id column (matched against $1)
	ScopeCols   []string // scope columns root->leaf (the containment chain)
	RevokedCol  string   // active filter; an active assignment has it NULL
	// Roles join.
	RoleCol    string // assignment FK -> RolesTable
	RolesTable string // the roles table
	RolesID    string // its primary-key column
	KeyCol     string // the role-key column
	// PermsCol is the roles-table column holding a role's MATERIALIZED effective
	// permission set, or "" when the rolestore declares none. When set, Resolve reads
	// it (so a CUSTOM role — an operator-configured set that is not a vocabulary
	// preset — resolves correctly); when "", Resolve expands each assignment's role
	// key through the vocabulary instead.
	PermsCol string

	vocab *Vocabulary
}

// HoldsResolver builds the resolver for a named rolestore (pass "" for the spec's
// sole rolestore). It pairs the rolestore with the vocabulary its roles draw from:
// the vocabulary named identically to the rolestore (the convention — `rolestore
// admin` <-> `vocabulary admin`), else the one named by the admin-plane subject's
// `roles`. Errors when the spec has no such rolestore or no resolvable vocabulary.
func (s *Spec) HoldsResolver(rolestore string) (*HoldsResolver, error) {
	var rs *RoleStore
	if rolestore == "" {
		rs = roleStoreByName(s)
	} else {
		for _, r := range s.RoleStores {
			if r.Name == rolestore {
				rs = r
				break
			}
		}
	}
	if rs == nil {
		if rolestore == "" {
			return nil, fmt.Errorf("HoldsResolver: the spec declares no rolestore")
		}
		return nil, fmt.Errorf("HoldsResolver: no rolestore %q in the spec", rolestore)
	}
	vocab, err := s.rolestoreVocab(rs)
	if err != nil {
		return nil, err
	}
	return &HoldsResolver{
		Assignments: rs.Assignments,
		KindCol:     rs.KindCol,
		KindVal:     rs.KindVal,
		SubjectCol:  rs.SubjectCol,
		ScopeCols:   append([]string(nil), rs.ScopeCols...),
		RevokedCol:  rs.RevokedCol,
		RoleCol:     rs.RoleCol,
		RolesTable:  rs.RolesTable,
		RolesID:     rs.RolesID,
		KeyCol:      rs.KeyCol,
		PermsCol:    rs.PermsCol,
		vocab:       vocab,
	}, nil
}

// rolestoreVocab resolves the vocabulary a rolestore's roles draw from.
func (s *Spec) rolestoreVocab(rs *RoleStore) (*Vocabulary, error) {
	if v := s.vocabByName(rs.Name); v != nil {
		return v, nil
	}
	for _, sub := range s.Subjects {
		if sub.Binds == "admin" && sub.Roles != "" {
			if v := s.vocabByName(sub.Roles); v != nil {
				return v, nil
			}
		}
	}
	return nil, fmt.Errorf("HoldsResolver: rolestore %q has no vocabulary (expected a vocabulary named %q, or a `binds admin` subject naming one via `roles`)", rs.Name, rs.Name)
}

// Vocabulary returns the vocabulary the resolver expands role keys through (the
// source of PresetPermissions). Exposed so a caller can seed / validate a
// materialized permissions column from the same expansion the resolver uses.
func (r *HoldsResolver) Vocabulary() *Vocabulary { return r.vocab }

// AssignmentsSQL renders the read: every ACTIVE role assignment a principal holds,
// across ALL scopes, projected as the scope columns (root->leaf) then the role key,
// then — when the rolestore declares one — the materialized permissions column.
// $1 binds the principal id. The CALLER executes it (the engine never does): under
// the principal's own claims for a self lookup, or as a trusted internal read when
// resolving another subject. The result is scope-UNFILTERED on purpose — one read
// answers every (Resolve at scope) the caller asks, matching the session path's
// "load the grants once, decide many scopes" shape. Mirrors access_runtime.go's
// ListGrantsSQL: a built statement plus a known column order, fed into Resolve.
//
// This is the GENERIC active-assignment read the rolestore implies: kind + subject
// + not-revoked, joined to the role. It deliberately does NOT encode adopter-
// specific ADMISSION policy — e.g. excluding a disabled role, an RP/client-scoped
// assignment, or an allowlist of role keys. Those are the adopter's policy, not
// part of the rolestore grammar (baking them in would violate the engine's "no
// policy" rule), so a caller whose effective-permission read must exclude such rows
// composes those predicates itself before / around this read. Otherwise the read
// returns a SUPERSET of such an adopter's rows and Resolve would union their
// permissions. (Foir's session read adds exactly these adopter filters; see the
// consumer parity test's documented read-filter delta.)
//
// KindVal is interpolated as a SQL string literal (not a bound parameter): it is a
// compile-time spec constant — the subject id is the only runtime value and binds
// to $1 — and this matches the inlined kind literal the emitted role-resolution
// definers already use (`ra.<KindCol> = '<KindVal>'`).
//
// Scan order: ScopeCols (in declared order), KeyCol, then PermsCol if PermsCol != ""
// — so a caller scans len(ScopeCols) scope values, the role key, and (if present)
// the permissions array into a RoleAssignment.
func (r *HoldsResolver) AssignmentsSQL() string {
	cols := make([]string, 0, len(r.ScopeCols)+2)
	for _, c := range r.ScopeCols {
		cols = append(cols, "ra."+c)
	}
	cols = append(cols, "r."+r.KeyCol)
	if r.PermsCol != "" {
		cols = append(cols, "r."+r.PermsCol)
	}
	return fmt.Sprintf(
		"SELECT %s FROM %s ra JOIN %s r ON r.%s = ra.%s WHERE ra.%s = '%s' AND ra.%s = $1 AND ra.%s IS NULL",
		strings.Join(cols, ", "),
		r.Assignments, r.RolesTable, r.RolesID, r.RoleCol,
		r.KindCol, r.KindVal, r.SubjectCol, r.RevokedCol)
}

// RoleAssignment is one row AssignmentsSQL returns: a principal's active role at a
// scope. Scope holds the scope-column values root->leaf (matching ScopeCols); an
// empty string is an UNPINNED (NULL) level. RoleKey is the assignment's role.
// Permissions is the role's materialized effective set; it is consulted only when
// the resolver's rolestore declares a permissions column (HoldsResolver.PermsCol !=
// ""), otherwise Resolve expands RoleKey through the vocabulary and ignores it.
type RoleAssignment struct {
	Scope       []string
	RoleKey     string
	Permissions []string
}

// EffectivePerms is a principal's resolved effective permission set at a scope.
type EffectivePerms struct {
	perms map[string]bool
}

// Holds reports whether the resolved set grants a permission — exactly the callback
// PDP.Authorize takes, so the full Layer-2 decision is
// `pdp.Authorize(proc, eff.Holds)`.
func (e EffectivePerms) Holds(perm string) bool { return e.perms[perm] }

// Permissions returns the resolved effective set, sorted (deterministic).
func (e EffectivePerms) Permissions() []string {
	out := make([]string, 0, len(e.perms))
	for p := range e.perms {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Resolve computes a principal's effective permission set at a query scope from the
// assignments AssignmentsSQL returned. It keeps every assignment whose scope
// CONTAINS the query scope (an ancestor-or-equal in the containment chain — see
// scopeContains) and unions their permissions. Each kept assignment contributes its
// MATERIALIZED permissions when the rolestore declares a permissions column
// (HoldsResolver.PermsCol != ""), otherwise its role key expanded through the
// vocabulary (preset -> permissions). The branch is per-RESOLVER (does this
// rolestore materialize permissions?), not per-row, so a role that legitimately
// grants nothing yields the empty set rather than triggering a key expansion.
// `scope` is the query's scope-column values root->leaf (matching ScopeCols); ""
// leaves a level unpinned (a tenant-wide query passes "" at the project level). The
// result is the canonical input to PDP.Authorize and reproduces the hand-written
// effective-permission resolver's scope match + union exactly.
func (r *HoldsResolver) Resolve(assignments []RoleAssignment, scope []string) (EffectivePerms, error) {
	eff := EffectivePerms{perms: map[string]bool{}}
	for _, a := range assignments {
		if !scopeContains(a.Scope, scope) {
			continue
		}
		var perms []string
		if r.PermsCol != "" {
			// Materialized: the role's effective set is the stored column (covers a
			// custom role whose set is not a vocabulary preset). Empty -> grants nothing.
			perms = a.Permissions
		} else {
			expanded, err := r.vocab.PresetPermissions(a.RoleKey)
			if err != nil {
				return EffectivePerms{}, fmt.Errorf("Resolve: assignment role %q: %w", a.RoleKey, err)
			}
			perms = expanded
		}
		for _, p := range perms {
			eff.perms[p] = true
		}
	}
	return eff, nil
}

// scopeContains reports whether an assignment scope contains (is an ancestor-or-
// equal of) a query scope. The match reproduces the hand-written resolver's
// semantics exactly:
//
//   - The ROOT scope column (index 0, the tenancy boundary) requires strict
//     equality — an assignment must NAME the root container it grants within, so an
//     unpinned/empty root matches ONLY an empty-root query, never a real one. An
//     assignment anchored ABOVE the root (every column empty — e.g. a platform-root
//     role) therefore does NOT flow through this tenancy resolver; that authority is
//     a separate plane (a platform-anchored role definer), not a cross-tenant grant.
//   - Every level BELOW the root is a wildcard when the assignment leaves it
//     unpinned (empty) — a grant pinned at level k covers k's whole subtree (a
//     tenant-wide grant answers every project query in that tenant). A pinned deeper
//     level must be pinned and equal in the query, so a deeper grant never answers a
//     shallower query (a project grant does not answer a tenant-wide query).
//
// Compared position by position over the shared root->leaf scope order; a query
// shorter than the assignment treats the missing tail as unpinned.
func scopeContains(assignment, query []string) bool {
	for i, a := range assignment {
		if i == 0 {
			// Root: strict equality, never wildcarded (the tenancy boundary).
			if i >= len(query) || query[i] != a {
				return false
			}
			continue
		}
		if a == "" {
			continue // a deeper unpinned level wildcards over its subtree
		}
		if i >= len(query) || query[i] != a {
			return false
		}
	}
	return true
}
