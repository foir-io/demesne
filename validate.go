package demesne

import (
	"errors"
	"fmt"
	"sort"
)

// Validate runs the semantic rules V1–V10 (RFC §8.2) over a parsed Spec and
// returns ALL violations joined (fail-loud, never emit weaker SQL). A nil error
// means the spec is inside the bounded-emitter envelope.
//
// Scope: the rules checkable from the spec alone live here in the pure engine.
// Two have a platform-side tail that needs the database / proto descriptors and
// runs in foir-platform under the oracle:
//   - V6 — the suffix/prefix nesting is checked here; asserting the physical
//     table actually carries those columns needs schema introspection.
//   - V8 — PDP coverage exhaustiveness needs reflecting each service's proto
//     descriptor; the engine checks block well-formedness, the oracle checks
//     "every write RPC is classified".
// V7 (generative isolation) is a property test (isolation_test.go), not a
// per-spec rule.
var tableOps = map[string]bool{"select": true, "insert": true, "update": true, "delete": true}
var knownLayers = map[string]bool{"rls": true, "pdp": true, "kernel": true}
var knownBuiltins = map[string]bool{"app_scope": true, "descriptor": true, "scoped": true, "session": true}
var knownModes = map[string]bool{"private": true, "public": true, "customers": true, "admins": true}

func Validate(s *Spec) error {
	var errs []error
	add := func(e error) {
		if e != nil {
			errs = append(errs, e)
		}
	}

	// V1 — linear topology (also surfaces unknown-parent / fork / cycle).
	chain, err := s.Topology.Chain()
	if err != nil {
		// Topology errors are foundational; report and stop (downstream rules
		// dereference the chain).
		return err
	}
	levelNames := map[string]bool{}
	for _, l := range chain {
		levelNames[l.Name] = true
	}
	vocabNames := map[string]bool{}
	for _, v := range s.Vocabs {
		if vocabNames[v.Name] {
			add(fmt.Errorf("line %d: duplicate vocabulary %q", v.Pos.Line, v.Name))
		}
		vocabNames[v.Name] = true
		add(validateVocabulary(v))
	}

	// Grant stores confer reach at a topology level — the level must resolve.
	for _, g := range s.Grants {
		if !levelNames[g.Level] {
			add(fmt.Errorf("line %d: grant %q confers reach at unknown level %q", g.Pos.Line, g.Name, g.Level))
		}
		if g.Table == "" || g.GranteeCol == "" || g.LevelCol == "" {
			add(fmt.Errorf("line %d: grant %q must name an edge table, grantee column and level column", g.Pos.Line, g.Name))
		}
	}

	for _, sub := range s.Subjects {
		add(validateSubject(s, sub, levelNames, vocabNames))
	}

	// V5 — claims contract is derivable (also validates anchors resolve).
	if _, err := s.ClaimsContract(); err != nil {
		add(err)
	}

	for _, o := range s.Objects {
		add(validateObject(s, o, chain))
	}

	// V10 — every PDP block targets a declared vocabulary (emit-site).
	for _, pr := range s.Procedures {
		if !vocabNames[pr.EmitSite] {
			add(fmt.Errorf("line %d: procedures block targets unknown vocabulary %q (V10)", pr.Pos.Line, pr.EmitSite))
		}
	}
	for _, u := range s.Ungoverned {
		if !vocabNames[u.EmitSite] {
			add(fmt.Errorf("line %d: ungoverned block targets unknown vocabulary %q (V10)", u.Pos.Line, u.EmitSite))
		}
	}

	// V11 — definer closure. The V9 promise is that the compiler owns 100% of the
	// SECURITY DEFINER surface: every auth.<fn>() the emitted RLS calls must be one
	// the kernel generates. Enforce it by construction so a dangling reference
	// (e.g. a `via edge` relation whose definer nothing emits) cannot ship — the
	// DB oracle would catch it only for the migrated subset, and never for a
	// third-party consumer of the engine.
	add(validateDefinerClosure(s))

	return errors.Join(errs...)
}

// validateDefinerClosure emits the RLS + the kernel and asserts the set of
// definers the policies reference is a subset of the set the kernel generates.
// A spec outside the bounded emitter (EmitRLS error) surfaces here too, so
// Validate is the single comprehensive gate.
func validateDefinerClosure(s *Spec) error {
	res, err := s.EmitRLS()
	if err != nil {
		return fmt.Errorf("definer closure (V11): RLS does not emit: %w", err)
	}
	// A declared @rls permission that the emitter could not compile is a spec
	// defect, not a silent no-op — fail loud (an uncompiled policy means the row
	// is unreachable, never weaker SQL). reqClaim failures land here.
	if len(res.Unsupported) > 0 {
		var errs []error
		for _, u := range res.Unsupported {
			errs = append(errs, fmt.Errorf("uncompilable @rls permission (V11): %s", u))
		}
		return errors.Join(errs...)
	}
	gen, err := s.EmitDefiners()
	if err != nil {
		return fmt.Errorf("definer closure (V11): kernel does not emit: %w", err)
	}
	generated := map[string]bool{}
	for _, g := range gen {
		generated["auth."+g.Name] = true
	}
	referenced := map[string]bool{}
	for _, p := range res.Policies {
		for _, body := range []string{p.Using, p.Check} {
			for _, fn := range scanDefiners(body) {
				referenced[fn] = true
			}
		}
	}
	var dangling []string
	for fn := range referenced {
		if !generated[fn] {
			dangling = append(dangling, fn)
		}
	}
	if len(dangling) == 0 {
		return nil
	}
	sort.Strings(dangling)
	var errs []error
	for _, fn := range dangling {
		errs = append(errs, fmt.Errorf("definer closure (V11): emitted RLS calls %s() but the kernel does not generate it — declare it so the compiler owns the whole definer surface", fn))
	}
	return errors.Join(errs...)
}

func validateVocabulary(v *Vocabulary) error {
	var errs []error
	perms := map[string]bool{}
	for _, p := range v.Permissions {
		perms[p] = true
	}
	presetNames := map[string]bool{}
	for _, pr := range v.Presets {
		presetNames[pr.Name] = true
	}
	// Preset members must be a declared permission of this vocab or another
	// preset in it.
	for _, pr := range v.Presets {
		if pr.Star {
			continue
		}
		for _, item := range pr.Set {
			if perms[item] || presetNames[item] {
				continue
			}
			errs = append(errs, fmt.Errorf("line %d: preset %q references unknown permission/preset %q in vocabulary %q",
				pr.Pos.Line, pr.Name, item, v.Name))
		}
	}
	// Rank ladder entries must be presets of this vocabulary.
	for _, r := range v.Rank {
		if !presetNames[r] {
			errs = append(errs, fmt.Errorf("line %d: rank ladder names %q which is not a preset of vocabulary %q",
				v.Pos.Line, r, v.Name))
		}
	}
	return errors.Join(errs...)
}

func validateSubject(s *Spec, sub *Subject, levels, vocabs map[string]bool) error {
	var errs []error

	// V2 — bounded reach + anchor resolves.
	if sub.Reach != "self" && sub.Reach != "descendants" && sub.Reach != "grant" {
		errs = append(errs, fmt.Errorf("line %d: subject %q has reach %q — only self|descendants|grant are emittable (V2)",
			sub.Pos.Line, sub.Name, sub.Reach))
	}
	if !levels[sub.Anchor] {
		errs = append(errs, fmt.Errorf("line %d: subject %q anchors at unknown level %q (V2)", sub.Pos.Line, sub.Name, sub.Anchor))
	}

	// A grant-reach subject's reach is conferred entirely by a declared Grant edge
	// (the scoped-operator form, replacing an unconditional membership god-flag);
	// it must name a declared grant.
	if sub.Reach == "grant" {
		if sub.ReachGrant == "" {
			errs = append(errs, fmt.Errorf("line %d: subject %q has `reach via grant` but names no grant", sub.Pos.Line, sub.Name))
		} else if g := s.grantByName(sub.ReachGrant); g == nil {
			errs = append(errs, fmt.Errorf("line %d: subject %q reaches via unknown grant %q", sub.Pos.Line, sub.Name, sub.ReachGrant))
		}
	}

	// roles vocabulary must exist when configurable.
	if sub.Roles != "" && !vocabs[sub.Roles] {
		errs = append(errs, fmt.Errorf("line %d: subject %q roles reference unknown vocabulary %q", sub.Pos.Line, sub.Name, sub.Roles))
	}

	// V7-precondition / safety: a subject that pins NO scope column has
	// unconditional reach and MUST anchor at a virtual level (the sanctioned
	// operator bypass). An accidental empty-pin subject is a cross-tenant leak.
	if levels[sub.Anchor] {
		cols, virtual, err := s.PinnedColumns(sub)
		if err != nil {
			errs = append(errs, err)
		} else if len(cols) == 0 && !virtual {
			errs = append(errs, fmt.Errorf("line %d: subject %q pins no scope column yet does not anchor at a virtual level — unconditional reach is only allowed for a virtual-anchored operator (V7)",
				sub.Pos.Line, sub.Name))
		}
	}

	// V9 — membership identity resolves through a compiler-owned table+flag
	// (the compiler generates the definer; the spec never names an external fn).
	if sub.Membership != nil && (sub.Membership.Table == "" || sub.Membership.IDCol == "" || sub.Membership.FlagCol == "") {
		errs = append(errs, fmt.Errorf("line %d: subject %q membership must name a table, id column and flag column (V9)", sub.Pos.Line, sub.Name))
	}
	return errors.Join(errs...)
}

func validateObject(s *Spec, o *Object, chain []*Level) error {
	var errs []error

	// V6 — scope-column nesting. The object's `scoped` chain must be the
	// root-anchored prefix of the NON-virtual topology chain down to the
	// object's level (the §6.2 scope-column path: pin every column from the top
	// real level down to L — a project table carries tenant_id AND project_id,
	// never project_id alone).
	nonVirtual := make([]*Level, 0, len(chain))
	for _, l := range chain {
		if !l.Virtual {
			nonVirtual = append(nonVirtual, l)
		}
	}
	if len(o.Scoped) == 0 || len(o.Scoped) > len(nonVirtual) {
		errs = append(errs, fmt.Errorf("line %d: object %q scoped chain has %d level(s); the non-virtual topology chain has %d (V6)",
			o.Pos.Line, o.Name, len(o.Scoped), len(nonVirtual)))
	} else {
		for i, name := range o.Scoped {
			if nonVirtual[i].Name != name {
				errs = append(errs, fmt.Errorf("line %d: object %q scoped[%d]=%q breaks the topology order (expected %q) (V6)",
					o.Pos.Line, o.Name, i, name, nonVirtual[i].Name))
				break
			}
		}
	}

	// Level-entity objects: the declared level must be a real topology level and
	// must be the object's deepest scoped level (the object IS that node).
	if o.Level != "" {
		known := false
		for _, l := range chain {
			if l.Name == o.Level {
				known = true
			}
		}
		if !known {
			errs = append(errs, fmt.Errorf("line %d: object %q declares level %q which is not a topology level", o.Pos.Line, o.Name, o.Level))
		}
		if len(o.Scoped) == 0 || o.Scoped[len(o.Scoped)-1] != o.Level {
			errs = append(errs, fmt.Errorf("line %d: object %q level %q must be its deepest scoped level", o.Pos.Line, o.Name, o.Level))
		}
	}

	relByName := map[string]*Relation{}
	for _, r := range o.Relations {
		if relByName[r.Name] != nil {
			errs = append(errs, fmt.Errorf("line %d: object %q has duplicate relation %q", r.Pos.Line, o.Name, r.Name))
		}
		relByName[r.Name] = r
		// V9 — every relation is backed by a compiler-owned representation
		// (guaranteed by the parser; assert defensively that none is nil).
		if r.Repr == nil {
			errs = append(errs, fmt.Errorf("line %d: object %q relation %q has no representation (V9)", r.Pos.Line, o.Name, r.Name))
		}
	}

	if o.Descriptor != nil {
		errs = append(errs, validateDescriptor(o))
	}

	for _, pm := range o.Perms {
		errs = append(errs, validatePerm(o, pm, relByName))
	}
	return errors.Join(errs...)
}

// validateDescriptor checks the access-descriptor primitive (§5.3).
func validateDescriptor(o *Object) error {
	var errs []error
	d := o.Descriptor

	// Owner-origination: a descriptor must name an owner, and the owner axis
	// must be inline (a FK column) so it short-circuits the hot path (§7).
	if d.Owner == nil {
		errs = append(errs, fmt.Errorf("line %d: object %q descriptor has no owner — there is no owner-origination for grants (§5.3)", d.Pos.Line, o.Name))
	} else if _, ok := d.Owner.Repr.(ViaColumn); !ok {
		errs = append(errs, fmt.Errorf("line %d: object %q descriptor owner must be an inline column axis", d.Pos.Line, o.Name))
	}

	hasListMode := false
	hasColumnMode := false
	for _, m := range d.Modes {
		if !knownModes[m.Name] {
			errs = append(errs, fmt.Errorf("line %d: object %q descriptor has unknown mode %q (private|public|customers|admins)", m.Pos.Line, o.Name, m.Name))
			continue
		}
		switch m.Name {
		case "public":
			if m.Scope != "project" && m.Scope != "world" {
				errs = append(errs, fmt.Errorf("line %d: object %q descriptor mode public(%s) — scope must be project|world", m.Pos.Line, o.Name, m.Scope))
			}
			hasColumnMode = true
		case "private":
			hasColumnMode = true
		case "customers", "admins":
			hasListMode = true
		}
		if m.Name != "public" && m.Scope != "" {
			errs = append(errs, fmt.Errorf("line %d: object %q descriptor mode %q takes no scope argument", m.Pos.Line, o.Name, m.Name))
		}
	}

	// The explicit-list modes need a record_acl edge to back them.
	if hasListMode && d.Grants == nil {
		errs = append(errs, fmt.Errorf("line %d: object %q descriptor declares customers/admins modes but no `grants via edge record_acl(...)` store", d.Pos.Line, o.Name))
	}
	// Column-driven modes (private/public) need a per-record mode column.
	if hasColumnMode && d.ModeCol == "" {
		errs = append(errs, fmt.Errorf("line %d: object %q descriptor uses private/public modes but declares no `mode via <column>`", d.Pos.Line, o.Name))
	}
	return errors.Join(errs...)
}

func validatePerm(o *Object, pm *Perm, rels map[string]*Relation) error {
	var errs []error

	// Layer values must be known.
	hasRLS, hasKernel, hasPDP := false, false, false
	for _, l := range pm.Layers {
		if !knownLayers[l] {
			errs = append(errs, fmt.Errorf("line %d: permission %s.%s has unknown layer %q", pm.Pos.Line, o.Name, pm.Verb, l))
		}
		switch l {
		case "rls":
			hasRLS = true
		case "kernel":
			hasKernel = true
		case "pdp":
			hasPDP = true
		}
	}
	if len(pm.Layers) == 0 {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s has no layer tag", pm.Pos.Line, o.Name, pm.Verb))
	}

	// The bounded ABAC guard: the only attribute predicate allowed (§8.2). It
	// rides RLS, so a guarded permission must be a row layer.
	if pm.Guard != nil {
		if pm.Guard.Op != "=" && pm.Guard.Op != "<>" {
			errs = append(errs, fmt.Errorf("line %d: permission %s.%s guard operator %q must be = or <>", pm.Pos.Line, o.Name, pm.Verb, pm.Guard.Op))
		}
		if !hasRLS {
			errs = append(errs, fmt.Errorf("line %d: permission %s.%s has a guard but is not @rls", pm.Pos.Line, o.Name, pm.Verb))
		}
	}

	// V4 — layer feasibility. A row layer (rls/kernel) can only enforce a table
	// op it can distinguish; it cannot see a capability verb. So:
	//   * if maps is a capability PERMKEY → must be pdp-only.
	//   * if a row layer is present and maps is set → maps must be a table op.
	mapsIsCapability := isPermKeyLit(pm.Maps)
	mapsIsTableOp := tableOps[pm.Maps]
	if mapsIsCapability && (hasRLS || hasKernel) {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s maps to capability %q but is tagged @rls/@kernel — a row layer cannot distinguish a verb; use @pdp (V4)",
			pm.Pos.Line, o.Name, pm.Verb, pm.Maps))
	}
	if hasRLS && pm.Maps != "" && !mapsIsTableOp {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s is @rls but maps to %q, not a table op (select|insert|update|delete) (V4)",
			pm.Pos.Line, o.Name, pm.Verb, pm.Maps))
	}

	// V3 — every term resolves and is classifiable. A relation term must name a
	// declared relation; a walk term's head must too; a @builtin is inline; a
	// PERMKEY term is only meaningful on a @pdp permission (a capability).
	for _, t := range pm.Expr {
		switch {
		case t.Builtin != "":
			if !knownBuiltins[t.Builtin] {
				errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses unknown builtin @%s (app_scope|descriptor)", pm.Pos.Line, o.Name, pm.Verb, t.Builtin))
			}
			if t.Builtin == "descriptor" && o.Descriptor == nil {
				errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses @descriptor but object %q has no descriptor block (§5.3)", pm.Pos.Line, o.Name, pm.Verb, o.Name))
			}
		case isPermKeyLit(t.Ident):
			if !hasPDP || hasRLS || hasKernel {
				errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses capability term %q outside a @pdp-only permission (V3/V4)",
					pm.Pos.Line, o.Name, pm.Verb, t.Ident))
			}
		default:
			r := rels[t.Ident]
			if r == nil {
				errs = append(errs, fmt.Errorf("line %d: permission %s.%s references unknown relation %q (V3)",
					pm.Pos.Line, o.Name, pm.Verb, t.Ident))
				continue
			}
			// A role-walk into a parent (`parent->verb`) is always a definer
			// traversal; a direct relation inherits its repr's class. Nothing to
			// reject here yet (no explicit @inline/@definer override syntax), but
			// the classification is what the emitter consumes.
			_ = r.CostClass()
		}
	}
	return errors.Join(errs...)
}

// isPermKeyLit reports whether a literal looks like a PERMKEY (contains ':').
func isPermKeyLit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}
