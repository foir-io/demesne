package demesne

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

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

	chain, err := s.Topology.Chain()
	if err != nil {

		return err
	}
	levelNames := map[string]bool{}
	for _, l := range chain {
		levelNames[l.Name] = true
	}

	vocabNames, vocabErr := valCheckVocabs(s)
	add(vocabErr)

	add(valCheckGrants(s, levelNames))

	add(valCheckClaimsBlock(s))

	for _, sub := range s.Subjects {
		add(validateSubject(s, sub, levelNames, vocabNames))
	}

	add(valCheckPlaneBindings(s))

	if _, err := s.ClaimsContract(); err != nil {
		add(err)
	}

	for _, o := range s.Objects {
		add(validateObject(s, o, chain))
	}

	add(validateCrossObjectAcyclic(s))

	add(validateGrantStores(s))

	add(validateStoreManage(s))

	add(valCheckEmitSites(s, vocabNames))

	add(validateDefinerClosure(s))

	add(validateAsyncFloorAsymmetry(s))

	return errors.Join(errs...)
}

func asyncTokensInBodies(bodies, tokens []string) []string {
	var found []string
	seen := map[string]bool{}
	for _, body := range bodies {
		if body == "" {
			continue
		}
		for _, tok := range tokens {
			if !seen[tok] && strings.Contains(body, tok) {
				seen[tok] = true
				found = append(found, tok)
			}
		}
	}
	return found
}

func validateAsyncFloorAsymmetry(s *Spec) error {
	tokens := s.asyncSurfaceTokens()
	if len(tokens) == 0 {
		return nil
	}
	res, err := s.EmitRLS()
	if err != nil {
		return fmt.Errorf("async asymmetry (V12): RLS does not emit: %w", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		return fmt.Errorf("async asymmetry (V12): kernel does not emit: %w", err)
	}
	var bodies []string
	for _, p := range res.Policies {
		bodies = append(bodies, p.Using, p.Check)
	}
	for _, d := range defs {
		bodies = append(bodies, d.Body)
	}

	bodies = append(bodies, s.FlatsSQL(), s.TriggersSQL(), s.ChangelogSQL())

	var errs []error
	for _, tok := range asyncTokensInBodies(bodies, tokens) {
		errs = append(errs, fmt.Errorf("async asymmetry (V12): a floor artifact references async surface %q — the floor must read only sync, committed truth; an async index may serve an affordance Check but never gate enforcement", tok))
	}
	return errors.Join(errs...)
}

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

func validateDefinerClosure(s *Spec) error {
	res, err := s.EmitRLS()
	if err != nil {
		return fmt.Errorf("definer closure (V11): RLS does not emit: %w", err)
	}

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

	if sub.Reach != "self" && sub.Reach != "descendants" && sub.Reach != "grant" {
		errs = append(errs, fmt.Errorf("line %d: subject %q has reach %q — only self|descendants|grant are emittable (V2)",
			sub.Pos.Line, sub.Name, sub.Reach))
	}
	if !levels[sub.Anchor] {
		errs = append(errs, fmt.Errorf("line %d: subject %q anchors at unknown level %q (V2)", sub.Pos.Line, sub.Name, sub.Anchor))
	}

	if sub.Reach == "grant" {
		if sub.ReachGrant == "" {
			errs = append(errs, fmt.Errorf("line %d: subject %q has `reach via grant` but names no grant", sub.Pos.Line, sub.Name))
		} else if g := s.grantByName(sub.ReachGrant); g == nil {
			errs = append(errs, fmt.Errorf("line %d: subject %q reaches via unknown grant %q", sub.Pos.Line, sub.Name, sub.ReachGrant))
		}
	}

	if sub.Roles != "" && !vocabs[sub.Roles] {
		errs = append(errs, fmt.Errorf("line %d: subject %q roles reference unknown vocabulary %q", sub.Pos.Line, sub.Name, sub.Roles))
	}

	switch sub.Binds {
	case "", "owner", "admin":
	default:
		errs = append(errs, fmt.Errorf("line %d: subject %q has unknown binding %q (binds owner|admin)", sub.Pos.Line, sub.Name, sub.Binds))
	}

	if levels[sub.Anchor] {
		cols, virtual, err := s.PinnedColumns(sub)
		if err != nil {
			errs = append(errs, err)
		} else if len(cols) == 0 && !virtual {
			errs = append(errs, fmt.Errorf("line %d: subject %q pins no scope column yet does not anchor at a virtual level — unconditional reach is only allowed for a virtual-anchored operator (V7)",
				sub.Pos.Line, sub.Name))
		}
	}

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

	add(valCheckScopePath(s, o, chain))

	add(valCheckLevelEntity(o, chain))

	relByName, relErr := valCheckObjectRelations(s, o)
	add(relErr)

	add(valCheckGrantRelCount(o))

	add(valCheckTrackChangelog(o))

	add(valCheckGates(s, o, relByName))

	for _, pm := range o.Perms {
		add(validatePerm(s, o, pm, relByName))
	}
	return errors.Join(errs...)
}

func valCheckGates(s *Spec, o *Object, relByName map[string]*Relation) error {
	var errs []error
	objHasVerb := func(obj *Object, verb string) bool {
		for _, pm := range obj.Perms {
			if pm.Verb == verb {
				return true
			}
		}
		return false
	}
	for _, g := range o.Gates {
		if !objHasVerb(o, g.Verb) {
			errs = append(errs, fmt.Errorf("line %d: object %q gate `%s via %s -> %s` gates verb %q, which the object does not declare as a permission", g.Pos.Line, o.Name, g.Verb, g.Relation, g.Perm, g.Verb))
		}
		r := relByName[g.Relation]
		if r == nil {
			errs = append(errs, fmt.Errorf("line %d: object %q gate references unknown relation %q", g.Pos.Line, o.Name, g.Relation))
			continue
		}
		if len(r.Types) == 0 {
			errs = append(errs, fmt.Errorf("line %d: object %q gate relation %q resolves to no object type", g.Pos.Line, o.Name, g.Relation))
			continue
		}
		for _, tname := range r.Types {
			target := s.objectByName(tname)
			if target == nil {
				errs = append(errs, fmt.Errorf("line %d: object %q gate relation %q targets %q, which is not a governed object", g.Pos.Line, o.Name, g.Relation, tname))
				continue
			}
			if !objHasVerb(target, g.Perm) {
				errs = append(errs, fmt.Errorf("line %d: object %q gate `%s via %s -> %s`: target object %q has no permission %q", g.Pos.Line, o.Name, g.Verb, g.Relation, g.Perm, tname, g.Perm))
			}
		}
	}
	return errors.Join(errs...)
}

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
	var want []string
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

func valCheckObjectRelations(s *Spec, o *Object) (map[string]*Relation, error) {
	var errs []error
	relByName := map[string]*Relation{}
	for _, r := range o.Relations {
		if relByName[r.Name] != nil {
			errs = append(errs, fmt.Errorf("line %d: object %q has duplicate relation %q", r.Pos.Line, o.Name, r.Name))
		}
		relByName[r.Name] = r

		if r.Repr == nil {
			errs = append(errs, fmt.Errorf("line %d: object %q relation %q has no representation (V9)", r.Pos.Line, o.Name, r.Name))
		}

		if mi, ok := r.Repr.(ViaMemberIn); ok {
			errs = append(errs, valCheckViaMemberIn(s, o, r, mi)...)
		}

		if g, ok := r.Repr.(ViaGroup); ok && g.Materialized && len(r.Types) > 1 {
			errs = append(errs, fmt.Errorf("line %d: object %q relation %q is `via group ... materialized` with multiple kinds %v — a materialized via-group must be single-kind (the flat tags only one principal_kind and the floor matches the id alone)", r.Pos.Line, o.Name, r.Name, r.Types))
		}

		if g, ok := r.Repr.(ViaGrant); ok && g.Async && !g.Tracked {
			errs = append(errs, fmt.Errorf("line %d: object %q relation %q is `via grant ... async` without `tracked` — the async affordance index is maintained off the changelog, which requires `tracked`", r.Pos.Line, o.Name, r.Name))
		}
	}
	return relByName, errors.Join(errs...)
}

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

func valCheckTrackChangelog(o *Object) error {
	if o.TrackOwner {
		if _, _, ok := o.ownerChangelogCols(); !ok {
			return fmt.Errorf("line %d: object %q declares `track owner` but has no owner column (a `via <id> where <kind> = ...` relation)", o.Pos.Line, o.Name)
		}
	}
	if o.TrackVisibility {
		if _, ok := o.modeChangelogCol(); !ok {
			return fmt.Errorf("line %d: object %q declares `track visibility` but has no `mode <col>` term", o.Pos.Line, o.Name)
		}
	}
	return nil
}

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

		if (g.DiscrimCol == "") != (g.DiscrimVal == "") {
			errs = append(errs, fmt.Errorf("object %q grant relation: a discriminator needs both a column and a value (`where <col> = \"<val>\"`)", o.Name))
		}

		for _, k := range rel.Types {
			if sub := s.subjectByName(k); sub == nil || sub.Identifies == "" {
				errs = append(errs, fmt.Errorf("object %q grant relation kind %q is not a claim-bearing subject (no `subject %s { ... identifies <claim> }`)", o.Name, k, k))
			}
		}
		byTable[g.Table] = append(byTable[g.Table], edgeRef{o, g})
	}
	for table, refs := range byTable {
		if len(refs) < 2 {
			continue
		}
		col := refs[0].g.DiscrimCol
		seen := map[string]string{}
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
	color := map[string]int{}
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

	add(valCheckPermPolarity(o, pm))

	hasRLS, hasKernel, hasPDP, layerErr := valCheckPermLayers(o, pm)
	add(layerErr)

	add(valCheckPermGuard(o, pm, hasRLS))

	add(valCheckPermMaps(o, pm, hasRLS, hasKernel))

	add(valCheckPermTerms(s, o, pm, rels, hasRLS, hasKernel, hasPDP))

	return errors.Join(errs...)
}

func valCheckPermPolarity(o *Object, pm *Perm) error {
	if pm.Tree != nil && !permPositive(pm.Tree) {
		return fmt.Errorf("line %d: permission %s.%s is not positively gated — a `not` (exclusion) must be combined with `and` with a positive grant, never used alone or as a union (`+`/`or`) branch", pm.Pos.Line, o.Name, pm.Verb)
	}
	return nil
}

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

			_ = r.CostClass()
		}
	}
	return errors.Join(errs...)
}

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

func valCheckBuiltinTerm(o *Object, pm *Perm, t *Term, rels map[string]*Relation, hasRLS bool) error {
	var errs []error
	if !knownBuiltins[t.Builtin] {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses unknown builtin @%s (app_scope|scoped|session|open|store_manage)", pm.Pos.Line, o.Name, pm.Verb, t.Builtin))
	}

	if t.ExcludeRel != "" {
		if r := rels[t.ExcludeRel]; r == nil {
			errs = append(errs, fmt.Errorf("line %d: permission %s.%s @app_scope(exclude %q) names no relation", pm.Pos.Line, o.Name, pm.Verb, t.ExcludeRel))
		} else if _, ok := r.Repr.(ViaColumn); !ok {
			errs = append(errs, fmt.Errorf("line %d: permission %s.%s @app_scope(exclude %q) must exclude an owner column relation", pm.Pos.Line, o.Name, pm.Verb, t.ExcludeRel))
		}
	}

	if t.Builtin == "open" && pm.Maps != "insert" {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses @open but maps to %q — @open is only valid on an insert (a bootstrap write the row engine cannot gate)", pm.Pos.Line, o.Name, pm.Verb, pm.Maps))
	}

	if t.Builtin == "public" && pm.Maps != "select" {
		errs = append(errs, fmt.Errorf("line %d: permission %s.%s uses @public but maps to %q — @public is a world-read grant, valid only on select", pm.Pos.Line, o.Name, pm.Verb, pm.Maps))
	}

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

func isPermKeyLit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}
