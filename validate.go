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
//
// V7 (generative isolation) is a property test (isolation_test.go), not a
// per-spec rule.
var tableOps = map[string]bool{"select": true, "insert": true, "update": true, "delete": true}
var knownLayers = map[string]bool{"rls": true, "pdp": true, "kernel": true}
var knownBuiltins = map[string]bool{"app_scope": true, "scoped": true, "session": true, "open": true, "store_manage": true, "public": true, "kind": true}

func Validate(s *Spec) error {
	var errs []error
	add := func(e error) {
		if e != nil {
			errs = append(errs, e)
		}
	}

	// V1 — tree topology (WS3: relaxed from a strict linear chain to a branching
	// tree; surfaces unknown-parent / multi-root / cycle / disconnected).
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

	vocabNames, vocabErr := valCheckVocabs(s)
	add(vocabErr)

	// Grant stores confer reach at a topology level — the level must resolve.
	add(valCheckGrants(s, levelNames))

	add(valCheckClaimsBlock(s))

	for _, sub := range s.Subjects {
		add(validateSubject(s, sub, levelNames, vocabNames))
	}

	// Explicit plane-role bindings must be unambiguous: at most one owner per
	// anchor level, at most one admin per spec (EID-265 WS2 — the binding REPLACES
	// the former first-match shape inference, so ambiguity is an error, not a
	// silent pick).
	add(valCheckPlaneBindings(s))

	// V5 — claims contract is derivable (also validates anchors resolve).
	if _, err := s.ClaimsContract(); err != nil {
		add(err)
	}

	for _, o := range s.Objects {
		add(validateObject(s, o, chain))
	}

	// Cross-object references (v3 WS3) must reference a real object and form NO
	// cycle — a cycle would make the generated `<X>_can_<v>` definers mutually
	// recursive and loop forever at query time.
	add(validateCrossObjectAcyclic(s))

	// Grant stores: grant relations sharing a physical store MUST all be
	// discriminated with DISTINCT discriminator values — otherwise their rows are
	// indistinguishable and one object's grant would leak onto another's reads.
	add(validateGrantStores(s))

	// @store_manage write-moat: the governance object's table must be a discriminated
	// grant store with ≥1 grant relation (the kinds the dispatch CASEs over).
	add(validateStoreManage(s))

	// V10 — every PDP block targets a declared vocabulary (emit-site).
	add(valCheckEmitSites(s, vocabNames))

	// V11 — definer closure. The V9 promise is that the compiler owns 100% of the
	// SECURITY DEFINER surface: every auth.<fn>() the emitted RLS calls must be one
	// the kernel generates. Enforce it by construction so a dangling reference
	// (e.g. a `via edge` relation whose definer nothing emits) cannot ship — the
	// DB oracle would catch it only for the migrated subset, and never for a
	// third-party consumer of the engine.
	add(validateDefinerClosure(s))

	return errors.Join(errs...)
}

// valCheckVocabs builds the set of declared vocabulary names and validates each
// vocabulary, surfacing duplicates.
func valCheckVocabs(s *Spec) (map[string]bool, error) {
	var errs []error
	vocabNames := map[string]bool{}
	for _, v := range s.Vocabs {
		if vocabNames[v.Name] {
			errs = append(errs, fmt.Errorf("line %d: duplicate vocabulary %q", v.Pos.Line, v.Name))
		}
		vocabNames[v.Name] = true
		if e := validateVocabulary(v); e != nil {
			errs = append(errs, e)
		}
	}
	return vocabNames, errors.Join(errs...)
}

// valCheckGrants enforces that each grant store confers reach at a resolvable
// topology level and names a complete edge.
func valCheckGrants(s *Spec, levels map[string]bool) error {
	var errs []error
	for _, g := range s.Grants {
		if !levels[g.Level] {
			errs = append(errs, fmt.Errorf("line %d: grant %q confers reach at unknown level %q", g.Pos.Line, g.Name, g.Level))
		}
		if g.Table == "" || g.GranteeCol == "" || g.LevelCol == "" {
			errs = append(errs, fmt.Errorf("line %d: grant %q must name an edge table, grantee column and level column", g.Pos.Line, g.Name))
		}
	}
	return errors.Join(errs...)
}

// valCheckClaimsBlock validates the optional claims block's setting name and cast.
func valCheckClaimsBlock(s *Spec) error {
	if s.Claims == nil {
		return nil
	}
	var errs []error
	if s.Claims.Setting == "" {
		errs = append(errs, fmt.Errorf("line %d: claims block needs a setting name", s.Claims.Pos.Line))
	}
	if s.Claims.Cast != "json" && s.Claims.Cast != "jsonb" {
		errs = append(errs, fmt.Errorf("line %d: claims cast %q must be json or jsonb", s.Claims.Pos.Line, s.Claims.Cast))
	}
	return errors.Join(errs...)
}

// valCheckPlaneBindings enforces that explicit plane-role bindings are
// unambiguous: at most one owner per anchor level, at most one admin per spec.
func valCheckPlaneBindings(s *Spec) error {
	var errs []error
	ownerAt := map[string]string{}
	adminSub := ""
	for _, sub := range s.Subjects {
		switch sub.Binds {
		case "owner":
			if prev := ownerAt[sub.Anchor]; prev != "" {
				errs = append(errs, fmt.Errorf("subjects %q and %q both `binds owner` at level %q — the owner plane must be unambiguous", prev, sub.Name, sub.Anchor))
			}
			ownerAt[sub.Anchor] = sub.Name
		case "admin":
			if adminSub != "" {
				errs = append(errs, fmt.Errorf("subjects %q and %q both `binds admin` — the admin plane must be unambiguous", adminSub, sub.Name))
			}
			adminSub = sub.Name
		}
	}
	return errors.Join(errs...)
}

// valCheckEmitSites enforces V10: every PDP/ungoverned block targets a declared
// vocabulary.
func valCheckEmitSites(s *Spec, vocabs map[string]bool) error {
	var errs []error
	for _, pr := range s.Procedures {
		if !vocabs[pr.EmitSite] {
			errs = append(errs, fmt.Errorf("line %d: procedures block targets unknown vocabulary %q (V10)", pr.Pos.Line, pr.EmitSite))
		}
	}
	for _, u := range s.Ungoverned {
		if !vocabs[u.EmitSite] {
			errs = append(errs, fmt.Errorf("line %d: ungoverned block targets unknown vocabulary %q (V10)", u.Pos.Line, u.EmitSite))
		}
	}
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
		generated[g.schema()+"."+g.Name] = true
	}
	referenced := map[string]bool{}
	for _, p := range res.Policies {
		for _, body := range []string{p.Using, p.Check} {
			for _, fn := range scanDefiners(body, s.definerSchema()) {
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

	// The explicit plane-role binding (EID-265 WS2) must name a known role.
	switch sub.Binds {
	case "", "owner", "admin":
	default:
		errs = append(errs, fmt.Errorf("line %d: subject %q has unknown binding %q (binds owner|admin)", sub.Pos.Line, sub.Name, sub.Binds))
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
	add := func(e error) {
		if e != nil {
			errs = append(errs, e)
		}
	}

	// V6 — scope-column nesting (WS3 tree/DAG-aware).
	add(valCheckScopePath(s, o, chain))

	// Level-entity objects: the declared level must be a real topology level and
	// must be the object's deepest scoped level (the object IS that node).
	add(valCheckLevelEntity(o, chain))

	relByName, relErr := valCheckObjectRelations(s, o)
	add(relErr)

	// At most one grant relation per object — two would collide in the generated
	// definer naming (both `<table>_grants[_<obj>]`).
	add(valCheckGrantRelCount(o))

	for _, pm := range o.Perms {
		add(validatePerm(s, o, pm, relByName))
	}
	return errors.Join(errs...)
}

// valCheckScopePath enforces V6 scope-column nesting (WS3 tree/DAG-aware). The
// object's `scoped` chain must list, in topological order, EVERY non-virtual
// ancestor of its deepest level across all root→leaf paths (a single-parent leaf
// → its one path; a multi-parent leaf → the union of its lineages, e.g. org_id +
// team_id + folder_id). It pins every ancestor column, never the leaf alone,
// never a stray level outside the leaf's ancestry.
func valCheckScopePath(s *Spec, o *Object, chain []*Level) error {
	leafLevel := ""
	if len(o.Scoped) > 0 {
		leafLevel = o.Scoped[len(o.Scoped)-1]
	}
	leafIsVirtual := false
	if l := s.Topology.LevelByName(leafLevel); l != nil {
		leafIsVirtual = l.Virtual
	}
	if len(o.Scoped) == 0 {
		return fmt.Errorf("line %d: object %q declares no scoped path (V6)", o.Pos.Line, o.Name)
	}
	if leafIsVirtual {
		// GLOBAL object (v3 WS6): scoped at a VIRTUAL level (the platform root). It
		// carries no containment columns — its access is the platform-role subject
		// branch, not a scope chain — so its scoped path is exactly that one virtual
		// root, never a non-virtual ancestry.
		if len(o.Scoped) != 1 {
			return fmt.Errorf("line %d: object %q is scoped at virtual level %q (a global object) but declares a multi-level path %v — a global object carries no containment columns (V6)",
				o.Pos.Line, o.Name, leafLevel, o.Scoped)
		}
		return nil
	}
	paths, perr := s.Topology.AncestorPaths(leafLevel)
	if perr != nil {
		return fmt.Errorf("line %d: object %q scoped leaf %q is not a topology level (V6)", o.Pos.Line, o.Name, leafLevel)
	}
	inAncestry := map[string]bool{}
	for _, p := range paths {
		for _, l := range p {
			inAncestry[l.Name] = true
		}
	}
	var want []string // topological order, non-virtual
	for _, l := range chain {
		if inAncestry[l.Name] && !l.Virtual {
			want = append(want, l.Name)
		}
	}
	ok := len(want) == len(o.Scoped)
	for i := 0; ok && i < len(want); i++ {
		ok = want[i] == o.Scoped[i]
	}
	if !ok {
		return fmt.Errorf("line %d: object %q scoped %v is not the non-virtual ancestry of %q in topological order (expected %v) (V6)",
			o.Pos.Line, o.Name, o.Scoped, o.Scoped[len(o.Scoped)-1], want)
	}
	return nil
}

// valCheckLevelEntity enforces that a level-entity object's declared level is a
// real topology level and is the object's deepest scoped level.
func valCheckLevelEntity(o *Object, chain []*Level) error {
	if o.Level == "" {
		return nil
	}
	var errs []error
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
	return errors.Join(errs...)
}

// valCheckObjectRelations validates each relation (duplicates, V9 representation
// presence, and ViaMemberIn well-formedness) and returns the relation lookup map
// used by the per-permission checks.
func valCheckObjectRelations(s *Spec, o *Object) (map[string]*Relation, error) {
	var errs []error
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
		// A scoped role-membership (v3 WS6) must name a real scope level, and each
		// argument must be EXACTLY one of a claim (`@key`) or a row column.
		if mi, ok := r.Repr.(ViaMemberIn); ok {
			errs = append(errs, valCheckViaMemberIn(s, o, r, mi)...)
		}
	}
	return relByName, errors.Join(errs...)
}

// valCheckViaMemberIn validates a ViaMemberIn relation's level and argument
// sources.
func valCheckViaMemberIn(s *Spec, o *Object, r *Relation, mi ViaMemberIn) []error {
	var errs []error
	if s.Topology.LevelByName(mi.Level) == nil {
		errs = append(errs, fmt.Errorf("line %d: object %q relation %q via memberin references unknown level %q", r.Pos.Line, o.Name, r.Name, mi.Level))
	}
	for label, a := range map[string]ArgSrc{"principal": mi.Principal, "scope": mi.Scope} {
		if (a.Claim == "") == (a.Col == "") {
			errs = append(errs, fmt.Errorf("line %d: object %q relation %q via memberin %s arg must be exactly one of @claim or a column", r.Pos.Line, o.Name, r.Name, label))
		}
	}
	return errs
}

// valCheckGrantRelCount enforces at most one `via grant` relation per object —
// two would collide in the generated definer naming.
func valCheckGrantRelCount(o *Object) error {
	grantRels := 0
	for _, r := range o.Relations {
		if _, ok := r.Repr.(ViaGrant); ok {
			grantRels++
		}
	}
	if grantRels > 1 {
		return fmt.Errorf("object %q declares %d `via grant` relations — at most one is allowed", o.Name, grantRels)
	}
	return nil
}

// validateGrantStores enforces the discriminated-store contract for the access-class
// grant RELATIONS (`via grant`): when more than one object points its grant relation
// at the SAME physical table, every such relation must be discriminated
// (`where <col> = "<val>"`), all on the SAME discriminator column, with DISTINCT
// values — otherwise two object types' grant rows are indistinguishable in the shared
// store and a grant on one would be read as a grant on another (a cross-type leak). A
// table used by exactly one grant relation may be bare or discriminated. Also: every
// grantee KIND (the relation's types) must name a claim-bearing subject, else the
// grant term it emits can never match (fail-closed on misconfig).
func validateGrantStores(s *Spec) error {
	type edgeRef struct {
		obj *Object
		g   *ViaGrant
	}
	byTable := map[string][]edgeRef{}
	var errs []error
	for _, o := range s.Objects {
		rel, g := grantRelation(o)
		if g == nil {
			continue
		}
		// A discriminator must be complete (both column and value).
		if (g.DiscrimCol == "") != (g.DiscrimVal == "") {
			errs = append(errs, fmt.Errorf("object %q grant relation: a discriminator needs both a column and a value (`where <col> = \"<val>\"`)", o.Name))
		}
		// Every grantee kind must be a claim-bearing subject (the principal a grant of
		// that kind is read against).
		for _, k := range rel.Types {
			if sub := s.subjectByName(k); sub == nil || sub.Identifies == "" {
				errs = append(errs, fmt.Errorf("object %q grant relation kind %q is not a claim-bearing subject (no `subject %s { ... identifies <claim> }`)", o.Name, k, k))
			}
		}
		byTable[g.Table] = append(byTable[g.Table], edgeRef{o, g})
	}
	for table, refs := range byTable {
		if len(refs) < 2 {
			continue // single owner — bare or discriminated, both fine
		}
		col := refs[0].g.DiscrimCol
		seen := map[string]string{} // discrim value -> first object that used it
		for _, r := range refs {
			if r.g.DiscrimCol == "" {
				errs = append(errs, fmt.Errorf("object %q shares grant store %q with another grant relation but is not discriminated — add `where <col> = \"<val>\"`", r.obj.Name, table))
				continue
			}
			if r.g.DiscrimCol != col {
				errs = append(errs, fmt.Errorf("grant relations sharing store %q must discriminate on the SAME column (%q vs %q)", table, col, r.g.DiscrimCol))
			}
			if prev, ok := seen[r.g.DiscrimVal]; ok {
				errs = append(errs, fmt.Errorf("objects %q and %q share grant store %q with the SAME discriminator value %q — values must be distinct", prev, r.obj.Name, table, r.g.DiscrimVal))
			}
			seen[r.g.DiscrimVal] = r.obj.Name
		}
	}
	return errors.Join(errs...)
}

// validateStoreManage checks the @store_manage write-moat builtin: the object
// using it must be backed by a discriminated grant store with at least one grant
// relation (the resource KINDS the generated dispatch CASEs over). Without a
// discriminator the dispatch has no column to switch on; without grant relations it
// has nothing to dispatch to.
func validateStoreManage(s *Spec) error {
	var errs []error
	for _, o := range s.Objects {
		if !objectUsesStoreManage(o) {
			continue
		}
		descs := s.storeDescriptors(o.Table)
		if len(descs) == 0 {
			errs = append(errs, fmt.Errorf("object %q uses @store_manage but no object uses its table %q as a grant store", o.Name, o.Table))
			continue
		}
		for _, d := range descs {
			if objectGrantEdge(d).DiscrimCol == "" {
				errs = append(errs, fmt.Errorf("object %q uses @store_manage but grant store %q on object %q is not discriminated (`where <col> = \"<val>\"`)", o.Name, o.Table, d.Name))
			}
		}
	}
	return errors.Join(errs...)
}

// validateCrossObjectAcyclic rejects an unknown target or a cycle in the
// cross-object (`via object`) reference graph (object O → Other per ViaObject
// relation). A cycle would make the generated `<X>_can_<v>` definers mutually
// recursive and loop forever at query time.
func validateCrossObjectAcyclic(s *Spec) error {
	edges := map[string][]string{}
	for _, o := range s.Objects {
		for _, r := range o.Relations {
			vo, ok := r.Repr.(ViaObject)
			if !ok {
				continue
			}
			if s.objectByName(vo.Object) == nil {
				return fmt.Errorf("object %q relation %q references unknown object %q (via object)", o.Name, r.Name, vo.Object)
			}
			edges[o.Name] = append(edges[o.Name], vo.Object)
		}
	}
	color := map[string]int{} // 0 unvisited, 1 on-stack, 2 done
	var dfs func(n string) bool
	dfs = func(n string) bool {
		color[n] = 1
		for _, m := range edges[n] {
			if color[m] == 1 {
				return true
			}
			if color[m] == 0 && dfs(m) {
				return true
			}
		}
		color[n] = 2
		return false
	}
	for _, o := range s.Objects {
		if color[o.Name] == 0 && dfs(o.Name) {
			return fmt.Errorf("cross-object `via object` references form a cycle through %q — this would generate mutually-recursive definers", o.Name)
		}
	}
	return nil
}

// permPositive reports whether a permission node grants access on its own — every
// branch reaches a positive (non-negated) term. A leaf is positive; a `not` is
// negative; an `and` is positive if ANY child is (a positive gates the negations);
// an `or` is positive only if EVERY branch is (a negated union branch is fail-open).
func permPositive(n *PermNode) bool {
	if n == nil {
		return false
	}
	switch n.Op {
	case "leaf":
		return true
	case "not":
		return false
	case "and":
		for _, k := range n.Kids {
			if permPositive(k) {
				return true
			}
		}
		return false
	case "or":
		for _, k := range n.Kids {
			if !permPositive(k) {
				return false
			}
		}
		return len(n.Kids) > 0
	}
	return false
}

func validatePerm(s *Spec, o *Object, pm *Perm, rels map[string]*Relation) error {
	var errs []error
	add := func(e error) {
		if e != nil {
			errs = append(errs, e)
		}
	}

	// Polarity (v3 WS1): a permission must be POSITIVELY GATED — every path to a
	// grant ends in a real (non-negated) term.
	add(valCheckPermPolarity(o, pm))

	// Layer values must be known.
	hasRLS, hasKernel, hasPDP, layerErr := valCheckPermLayers(o, pm)
	add(layerErr)

	// The bounded ABAC guard: the only attribute predicate allowed (§8.2).
	add(valCheckPermGuard(o, pm, hasRLS))

	// V4 — layer feasibility.
	add(valCheckPermMaps(o, pm, hasRLS, hasKernel))

	// V3 — every term resolves and is classifiable.
	add(valCheckPermTerms(s, o, pm, rels, hasRLS, hasKernel, hasPDP))

	return errors.Join(errs...)
}

// valCheckPermPolarity enforces the v3 WS1 polarity rule: a `not` (exclusion) is
// fail-OPEN unless AND'd with a positive grant that gates it. A bare `not`, or a
// `not` as a union branch, is rejected so exclusion is fail-closed by
// construction.
func valCheckPermPolarity(o *Object, pm *Perm) error {
	if pm.Tree != nil && !permPositive(pm.Tree) {
		return fmt.Errorf("line %d: permission %s.%s is not positively gated — a `not` (exclusion) must be combined with `and` with a positive grant, never used alone or as a union (`+`/`or`) branch", pm.Pos.Line, o.Name, pm.Verb)
	}
	return nil
}

// valCheckPermLayers validates the permission's layer tags and reports which row/
// capability layers are present.
func valCheckPermLayers(o *Object, pm *Perm) (hasRLS, hasKernel, hasPDP bool, err error) {
	var errs []error
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
	return hasRLS, hasKernel, hasPDP, errors.Join(errs...)
}

// valCheckPermGuard validates the bounded ABAC guard: its operator must be = or
// <>, and a guarded permission must ride RLS.
func valCheckPermGuard(o *Object, pm *Perm, hasRLS bool) error {
	if pm.Guard == nil {
		return nil
	}
	var errs []error
	if pm.Guard.Op != "=" && pm.Guard.Op != "<>" {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s guard operator %q must be = or <>", pm.Pos.Line, o.Name, pm.Verb, pm.Guard.Op))
	}
	if !hasRLS {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s has a guard but is not @rls", pm.Pos.Line, o.Name, pm.Verb))
	}
	return errors.Join(errs...)
}

// valCheckPermMaps enforces V4 layer feasibility: a row layer (rls/kernel) cannot
// see a capability verb, and an @rls mapping must be a table op.
func valCheckPermMaps(o *Object, pm *Perm, hasRLS, hasKernel bool) error {
	var errs []error
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
	return errors.Join(errs...)
}

// valCheckPermTerms enforces V3: every term resolves and is classifiable. A
// relation term must name a declared relation; a walk term's head must too; a
// @builtin is inline; a PERMKEY term is only meaningful on a @pdp permission.
func valCheckPermTerms(s *Spec, o *Object, pm *Perm, rels map[string]*Relation, hasRLS, hasKernel, hasPDP bool) error {
	var errs []error
	add := func(e error) {
		if e != nil {
			errs = append(errs, e)
		}
	}
	for _, t := range pm.Expr {
		switch {
		case t.GrantRef != "":
			add(valCheckGrantRefTerm(s, o, pm, t, hasRLS))
		case t.ModeCol != "":
			add(valCheckModeTerm(s, o, pm, t, hasRLS))
		case t.Builtin != "":
			add(valCheckBuiltinTerm(o, pm, t, rels, hasRLS))
		case isGrantSelectorTerm(t.Ident, rels):
			add(valCheckGrantSelectorTerm(o, pm, t, rels, hasRLS))
		case isPermKeyLit(t.Ident):
			if !hasPDP || hasRLS || hasKernel {
				add(fmt.Errorf("line %d: permission %s.%s uses capability term %q outside a @pdp-only permission (V3/V4)",
					pm.Pos.Line, o.Name, pm.Verb, t.Ident))
			}
		default:
			r := rels[t.Ident]
			if r == nil {
				add(fmt.Errorf("line %d: permission %s.%s references unknown relation %q (V3)",
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

// valCheckGrantRefTerm validates a `via grant <name>` term — a row-layer term
// conferred by a declared grant.
func valCheckGrantRefTerm(s *Spec, o *Object, pm *Perm, t *Term, hasRLS bool) error {
	var errs []error
	if s.grantByName(t.GrantRef) == nil {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s references unknown grant %q (via grant)", pm.Pos.Line, o.Name, pm.Verb, t.GrantRef))
	}
	if !hasRLS {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses `via grant %s` but is not @rls", pm.Pos.Line, o.Name, pm.Verb, t.GrantRef))
	}
	return errors.Join(errs...)
}

// valCheckModeTerm validates a column-condition (visibility) term — a row-layer
// read grant. It must be on @rls; an actor-scoped form must name a real subject.
func valCheckModeTerm(s *Spec, o *Object, pm *Perm, t *Term, hasRLS bool) error {
	var errs []error
	if !hasRLS {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses a mode term but is not @rls", pm.Pos.Line, o.Name, pm.Verb))
	}
	if t.ModeScope != "" && s.subjectByName(t.ModeScope) == nil {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s mode term scope `for %s` names no subject", pm.Pos.Line, o.Name, pm.Verb, t.ModeScope))
	}
	return errors.Join(errs...)
}

// valCheckBuiltinTerm validates a @builtin term and its builtin-specific
// constraints (@app_scope exclude axis, @open, @public, @kind).
func valCheckBuiltinTerm(o *Object, pm *Perm, t *Term, rels map[string]*Relation, hasRLS bool) error {
	var errs []error
	if !knownBuiltins[t.Builtin] {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses unknown builtin @%s (app_scope|scoped|session|open|store_manage)", pm.Pos.Line, o.Name, pm.Verb, t.Builtin))
	}
	// `@app_scope(exclude <rel>)` — the excluded axis must be a declared owner
	// column relation (its presence is what gets excluded).
	if t.ExcludeRel != "" {
		if r := rels[t.ExcludeRel]; r == nil {
			errs = append(errs, fmt.Errorf("line %d: permission %s.%s @app_scope(exclude %q) names no relation", pm.Pos.Line, o.Name, pm.Verb, t.ExcludeRel))
		} else if _, ok := r.Repr.(ViaColumn); !ok {
			errs = append(errs, fmt.Errorf("line %d: permission %s.%s @app_scope(exclude %q) must exclude an owner column relation", pm.Pos.Line, o.Name, pm.Verb, t.ExcludeRel))
		}
	}
	// @open is the unrestricted-INSERT bootstrap only — never a read/update/
	// delete grant (that would be a blanket leak).
	if t.Builtin == "open" && pm.Maps != "insert" {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses @open but maps to %q — @open is only valid on an insert (a bootstrap write the row engine cannot gate)", pm.Pos.Line, o.Name, pm.Verb, pm.Maps))
	}
	// @public is a world-READ grant only — never a write.
	if t.Builtin == "public" && pm.Maps != "select" {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses @public but maps to %q — @public is a world-read grant, valid only on select", pm.Pos.Line, o.Name, pm.Verb, pm.Maps))
	}
	// @kind("<value>") needs a non-empty kind value and is a row-layer grant.
	if t.Builtin == "kind" {
		if t.KindVal == "" {
			errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses @kind with an empty value — `@kind(\"<value>\")`", pm.Pos.Line, o.Name, pm.Verb))
		}
		if !hasRLS {
			errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses @kind but is not @rls", pm.Pos.Line, o.Name, pm.Verb))
		}
	}
	return errors.Join(errs...)
}

// valCheckGrantSelectorTerm validates a grant relation with an access class
// (`grantee:read`) — a row-layer (@rls) grant that must carry a non-empty class.
func valCheckGrantSelectorTerm(o *Object, pm *Perm, t *Term, rels map[string]*Relation, hasRLS bool) error {
	var errs []error
	_, access, _ := grantSelector(t.Ident, rels)
	if access == "" {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s grant term %q has an empty access class (use grantee:read|write|delete)",
			pm.Pos.Line, o.Name, pm.Verb, t.Ident))
	}
	if !hasRLS {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses grant term %q but is not @rls (V3/V4)",
			pm.Pos.Line, o.Name, pm.Verb, t.Ident))
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
