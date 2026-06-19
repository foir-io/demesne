package demesne

import (
	"fmt"
	"strings"
)

// Parser for the Demesne grammar (RFC §8.2). Recursive descent over the token
// stream; produces a Spec AST. Parsing only checks grammatical well-formedness
// — the semantic validation rules (V1–V10) run in a later pass against the AST.

// Parse parses a spec source into an AST.
func Parse(src string) (*Spec, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	s, err := p.parseSpec()
	if err != nil {
		return nil, err
	}
	// Resolve `use <template>` into each object's Perms before any downstream pass
	// sees the AST — a template is pure parse-time sugar (no effect on emission).
	if err := s.expandTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

type parser struct {
	toks []token
	i    int
}

func (p *parser) cur() token        { return p.toks[p.i] }
func (p *parser) peekKind() tokKind { return p.toks[p.i].kind }
func (p *parser) advance() token {
	t := p.toks[p.i]
	if p.i < len(p.toks)-1 {
		p.i++
	}
	return t
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("line %d: %s", p.cur().line, fmt.Sprintf(format, args...))
}

func (p *parser) expect(k tokKind) (token, error) {
	if p.peekKind() != k {
		return token{}, p.errf("expected %s, got %s %q", k, p.peekKind(), p.cur().lit)
	}
	return p.advance(), nil
}

// ident consumes an IDENT and returns its literal.
func (p *parser) ident() (string, error) {
	t, err := p.expect(tIdent)
	return t.lit, err
}

// isKw reports whether the cursor is the keyword kw (an IDENT with that literal).
func (p *parser) isKw(kw string) bool {
	return p.peekKind() == tIdent && p.cur().lit == kw
}

// acceptKw consumes the keyword kw if present and reports whether it did.
func (p *parser) acceptKw(kw string) bool {
	if p.isKw(kw) {
		p.advance()
		return true
	}
	return false
}

// expectKw consumes the keyword kw or errors.
func (p *parser) expectKw(kw string) error {
	if !p.acceptKw(kw) {
		return p.errf("expected keyword %q, got %s %q", kw, p.peekKind(), p.cur().lit)
	}
	return nil
}

func (p *parser) parseSpec() (*Spec, error) {
	s := &Spec{}
	for p.peekKind() != tEOF {
		if p.peekKind() != tIdent {
			return nil, p.errf("expected a declaration keyword, got %s %q", p.peekKind(), p.cur().lit)
		}
		if err := p.parseDecl(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// parseDecl parses one top-level declaration and folds it into s.
func (p *parser) parseDecl(s *Spec) error {
	switch p.cur().lit {
	case "topology":
		return p.ppDeclTopology(s)
	case "vocabulary":
		return p.ppDeclVocabulary(s)
	case "subject":
		return p.ppDeclSubject(s)
	case "object":
		return p.ppDeclObject(s)
	case "template":
		return p.ppDeclTemplate(s)
	case "procedures":
		return p.ppDeclProcedures(s)
	case "ungoverned":
		return p.ppDeclUngoverned(s)
	case "fieldscopes":
		return p.ppDeclFieldScopes(s)
	case "rolestore":
		return p.ppDeclRoleStore(s)
	case "grant":
		return p.ppDeclGrant(s)
	case "claims":
		return p.ppDeclClaims(s)
	case "definers":
		return p.ppDeclDefiners(s)
	case "tables":
		return p.ppDeclTables(s)
	default:
		return p.errf("unknown declaration %q", p.cur().lit)
	}
}

func (p *parser) ppDeclTopology(s *Spec) error {
	t, err := p.parseTopology()
	if err != nil {
		return err
	}
	if s.Topology != nil {
		return p.errf("duplicate topology block")
	}
	s.Topology = t
	return nil
}

func (p *parser) ppDeclVocabulary(s *Spec) error {
	v, err := p.parseVocabulary()
	if err != nil {
		return err
	}
	s.Vocabs = append(s.Vocabs, v)
	return nil
}

func (p *parser) ppDeclSubject(s *Spec) error {
	sub, err := p.parseSubject()
	if err != nil {
		return err
	}
	s.Subjects = append(s.Subjects, sub)
	return nil
}

func (p *parser) ppDeclObject(s *Spec) error {
	o, err := p.parseObject()
	if err != nil {
		return err
	}
	s.Objects = append(s.Objects, o)
	return nil
}

func (p *parser) ppDeclTemplate(s *Spec) error {
	t, err := p.parseTemplate()
	if err != nil {
		return err
	}
	s.Templates = append(s.Templates, t)
	return nil
}

func (p *parser) ppDeclProcedures(s *Spec) error {
	pr, err := p.parseProcedures()
	if err != nil {
		return err
	}
	s.Procedures = append(s.Procedures, pr)
	return nil
}

func (p *parser) ppDeclUngoverned(s *Spec) error {
	u, err := p.parseUngoverned()
	if err != nil {
		return err
	}
	s.Ungoverned = append(s.Ungoverned, u)
	return nil
}

func (p *parser) ppDeclFieldScopes(s *Spec) error {
	fs, err := p.parseFieldScopes()
	if err != nil {
		return err
	}
	s.FieldScopes = append(s.FieldScopes, fs)
	return nil
}

func (p *parser) ppDeclRoleStore(s *Spec) error {
	rs, err := p.parseRoleStore()
	if err != nil {
		return err
	}
	s.RoleStores = append(s.RoleStores, rs)
	return nil
}

func (p *parser) ppDeclGrant(s *Spec) error {
	g, err := p.parseGrant()
	if err != nil {
		return err
	}
	s.Grants = append(s.Grants, g)
	return nil
}

func (p *parser) ppDeclClaims(s *Spec) error {
	c, err := p.parseClaims()
	if err != nil {
		return err
	}
	if s.Claims != nil {
		return p.errf("duplicate claims block")
	}
	s.Claims = c
	return nil
}

func (p *parser) ppDeclDefiners(s *Spec) error {
	p.advance() // 'definers'
	if err := p.expectKw("schema"); err != nil {
		return err
	}
	sch, err := p.expect(tString)
	if err != nil {
		return err
	}
	if s.DefinerSchema != "" {
		return p.errf("duplicate definers block")
	}
	s.DefinerSchema = sch.lit
	return nil
}

// ppDeclTables parses `tables schema "<name>"` — the Postgres schema the adopter's
// governed tables live in (qualifies the emitted ENABLE/FORCE/policy/trigger DDL).
func (p *parser) ppDeclTables(s *Spec) error {
	p.advance() // 'tables'
	if err := p.expectKw("schema"); err != nil {
		return err
	}
	sch, err := p.expect(tString)
	if err != nil {
		return err
	}
	if s.TableSchema != "" {
		return p.errf("duplicate tables block")
	}
	s.TableSchema = sch.lit
	return nil
}

func (p *parser) parseTopology() (*Topology, error) {
	pos := Pos{p.cur().line}
	_ = p.advance() // 'topology'
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	t := &Topology{Pos: pos}
	for p.isKw("level") {
		lv, err := p.parseLevel()
		if err != nil {
			return nil, err
		}
		t.Levels = append(t.Levels, lv)
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return t, nil
}

// parseLevel parses one `level <name> ...` entry inside a topology block.
func (p *parser) parseLevel() (*Level, error) {
	lv := &Level{Pos: Pos{p.cur().line}}
	p.advance() // 'level'
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	lv.Name = name
	// ('parent' IDENT | 'parents' IDENT (',' IDENT)*)? ('virtual')?
	// ('col' IDENT)? ('claim' IDENT)? — any order, all optional. `parents`
	// (plural) declares a multi-parent DAG level; `col`/`claim` override the
	// `<name>_id` scope-column / claim-key conventions independently (EID-278).
	for {
		if p.acceptKw("parent") {
			par, err := p.ident()
			if err != nil {
				return nil, err
			}
			lv.Parents = append(lv.Parents, par)
			continue
		}
		if p.acceptKw("parents") {
			if err := p.parseLevelParents(lv); err != nil {
				return nil, err
			}
			continue
		}
		if p.acceptKw("virtual") {
			lv.Virtual = true
			continue
		}
		if p.acceptKw("col") {
			if lv.ScopeCol, err = p.ident(); err != nil {
				return nil, err
			}
			continue
		}
		if p.acceptKw("claim") {
			if lv.ClaimKey, err = p.ident(); err != nil {
				return nil, err
			}
			continue
		}
		break
	}
	return lv, nil
}

// parseLevelParents parses the `parents IDENT (',' IDENT)*` list into lv.
func (p *parser) parseLevelParents(lv *Level) error {
	for {
		par, err := p.ident()
		if err != nil {
			return err
		}
		lv.Parents = append(lv.Parents, par)
		if p.peekKind() != tComma {
			break
		}
		p.advance() // ','
	}
	return nil
}

func (p *parser) parseVocabulary() (*Vocabulary, error) {
	v := &Vocabulary{Pos: Pos{p.cur().line}}
	p.advance() // 'vocabulary'
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	v.Name = name
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	for p.peekKind() != tRBrace && p.peekKind() != tEOF {
		switch {
		case p.isKw("permission"):
			p.advance()
			pk, err := p.expect(tPermKey)
			if err != nil {
				return nil, err
			}
			v.Permissions = append(v.Permissions, pk.lit)
		case p.isKw("preset"):
			pr, err := p.parsePreset()
			if err != nil {
				return nil, err
			}
			v.Presets = append(v.Presets, pr)
		case p.isKw("rank"):
			r, err := p.parseRank()
			if err != nil {
				return nil, err
			}
			v.Rank = r
		default:
			return nil, p.errf("unexpected %s %q in vocabulary %q", p.peekKind(), p.cur().lit, v.Name)
		}
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return v, nil
}

func (p *parser) parsePreset() (*Preset, error) {
	pr := &Preset{Pos: Pos{p.cur().line}}
	p.advance() // 'preset'
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	pr.Name = name
	if p.peekKind() == tAt { // optional `@ <level>` (role binds at this topology level)
		p.advance()
		lvl, err := p.ident()
		if err != nil {
			return nil, err
		}
		pr.Level = lvl
	}
	if _, err := p.expect(tEq); err != nil {
		return nil, err
	}
	if p.peekKind() == tStar {
		p.advance()
		pr.Star = true
		return pr, nil
	}
	// permset := item ('+' item)*   where item is PERMKEY or IDENT (preset ref)
	first, err := p.permsetItem()
	if err != nil {
		return nil, err
	}
	pr.Set = append(pr.Set, first)
	for p.peekKind() == tPlus {
		p.advance()
		it, err := p.permsetItem()
		if err != nil {
			return nil, err
		}
		pr.Set = append(pr.Set, it)
	}
	return pr, nil
}

func (p *parser) permsetItem() (string, error) {
	switch p.peekKind() {
	case tPermKey, tIdent:
		return p.advance().lit, nil
	default:
		return "", p.errf("expected a permission or preset name, got %s %q", p.peekKind(), p.cur().lit)
	}
}

func (p *parser) parseRank() ([]string, error) {
	p.advance() // 'rank'
	first, err := p.ident()
	if err != nil {
		return nil, err
	}
	ranks := []string{first}
	if p.peekKind() != tGT {
		return nil, p.errf("rank ladder needs at least one '>' (got %s)", p.peekKind())
	}
	for p.peekKind() == tGT {
		p.advance()
		nm, err := p.ident()
		if err != nil {
			return nil, err
		}
		ranks = append(ranks, nm)
	}
	return ranks, nil
}

func (p *parser) parseSubject() (*Subject, error) {
	sub := &Subject{Pos: Pos{p.cur().line}}
	p.advance() // 'subject'
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	sub.Name = name
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	// Fields in any order (the inline `;`-separated form and the block form both
	// occur); each appears at most once.
	for p.peekKind() != tRBrace && p.peekKind() != tEOF {
		switch {
		case p.acceptKw("anchor"):
			sub.Anchor, err = p.ident()
		case p.acceptKw("reach"):
			// `reach self|descendants`, or `reach via grant <name>` (reach
			// conferred by a level-scoped grant edge rather than topology pinning).
			if p.acceptKw("via") {
				if err = p.expectKw("grant"); err == nil {
					sub.Reach = "grant"
					sub.ReachGrant, err = p.ident()
				}
			} else {
				sub.Reach, err = p.ident()
			}
		case p.acceptKw("identifies"):
			sub.Identifies, err = p.ident()
			if err == nil && p.acceptKw("via") {
				err = p.parseSubjectMembership(sub)
			}
		case p.acceptKw("roles"):
			err = p.parseSubjectRoles(sub)
		case p.acceptKw("binds"):
			// `binds owner|admin` — the subject's distinguished plane role, declared
			// explicitly rather than inferred from shape (EID-265 WS2).
			sub.Binds, err = p.ident()
		default:
			return nil, p.errf("unexpected %s %q in subject %q", p.peekKind(), p.cur().lit, sub.Name)
		}
		if err != nil {
			return nil, err
		}
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return sub, nil
}

func (p *parser) parseSubjectMembership(sub *Subject) error {
	if err := p.expectKw("membership"); err != nil {
		return err
	}
	tbl, err := p.ident()
	if err != nil {
		return err
	}
	if _, err := p.expect(tLParen); err != nil {
		return err
	}
	idCol, err := p.ident()
	if err != nil {
		return err
	}
	if _, err := p.expect(tComma); err != nil {
		return err
	}
	flagCol, err := p.ident()
	if err != nil {
		return err
	}
	if _, err := p.expect(tRParen); err != nil {
		return err
	}
	m := &Membership{Table: tbl, IDCol: idCol, FlagCol: flagCol}
	if p.acceptKw("active") {
		if m.ActiveCol, err = p.ident(); err != nil {
			return err
		}
		if _, err := p.expect(tEq); err != nil {
			return err
		}
		v, err := p.expect(tString)
		if err != nil {
			return err
		}
		m.ActiveVal = v.lit
	}
	sub.Membership = m
	return nil
}

func (p *parser) parseSubjectRoles(sub *Subject) error {
	switch {
	case p.acceptKw("configurable"):
		v, err := p.ident()
		if err != nil {
			return err
		}
		sub.Roles = v
	case p.acceptKw("none"):
		sub.RolesNone = true
	default:
		return p.errf("expected 'configurable <vocab>' or 'none' after roles, got %s %q", p.peekKind(), p.cur().lit)
	}
	return nil
}

func (p *parser) parseObject() (*Object, error) {
	o := &Object{Pos: Pos{p.cur().line}}
	p.advance() // 'object'
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	o.Name = name
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	if err := p.expectKw("table"); err != nil {
		return nil, err
	}
	if o.Table, err = p.ident(); err != nil {
		return nil, err
	}
	if p.acceptKw("pk") { // optional: the table's primary-key column (default "id")
		if o.PK, err = p.ident(); err != nil {
			return nil, err
		}
	}
	if p.acceptKw("level") { // optional: this object IS a topology level node
		if o.Level, err = p.ident(); err != nil {
			return nil, err
		}
	}
	if err := p.expectKw("scoped"); err != nil {
		return nil, err
	}
	if o.Scoped, err = p.parseLevelChain(); err != nil {
		return nil, err
	}
	if err := p.parseObjectBody(o); err != nil {
		return nil, err
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return o, nil
}

// parseObjectBody parses the relation/permission/use/omit members of an object
// up to (but not consuming) the closing brace.
func (p *parser) parseObjectBody(o *Object) error {
	for p.peekKind() != tRBrace && p.peekKind() != tEOF {
		switch {
		case p.isKw("relation"):
			r, err := p.parseRelation()
			if err != nil {
				return err
			}
			o.Relations = append(o.Relations, r)
		case p.isKw("permission"):
			pm, err := p.parseObjectPerm()
			if err != nil {
				return err
			}
			o.Perms = append(o.Perms, pm)
		case p.isKw("use"):
			p.advance()
			if o.Use != "" {
				return p.errf("object %q declares `use` more than once", o.Name)
			}
			var err error
			if o.Use, err = p.ident(); err != nil {
				return err
			}
		case p.isKw("omit"):
			p.advance()
			v, err := p.ident()
			if err != nil {
				return err
			}
			o.Omit = append(o.Omit, v)
		default:
			return p.errf("unexpected %s %q in object %q", p.peekKind(), p.cur().lit, o.Name)
		}
	}
	return nil
}

// parseTemplate parses a `template <name> { <permission lines> }` block — a named,
// reusable permission set the APP defines and applies to objects with `use <name>`.
// Only permission lines are allowed: a template carries no table/scope/relations
// (those belong to the using object), so it stays a pure, composable bundle of the
// generic permission terms. This is the generic replacement for the removed
// `settings`/`platform` Foir-domain-named sugar.
func (p *parser) parseTemplate() (*Template, error) {
	t := &Template{Pos: Pos{p.cur().line}}
	p.advance() // 'template'
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	t.Name = name
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	for p.peekKind() != tRBrace && p.peekKind() != tEOF {
		if !p.isKw("permission") {
			return nil, p.errf("template %q: only permission lines are allowed, got %s %q", t.Name, p.peekKind(), p.cur().lit)
		}
		pm, err := p.parseObjectPerm()
		if err != nil {
			return nil, err
		}
		t.Perms = append(t.Perms, pm)
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return t, nil
}

// expandTemplates resolves every object's `use <template>` into its Perms, so all
// downstream passes see an ordinary Object (a template has NO effect on emission —
// it is pure parse-time sugar). Reconciliation, in order: take the template's
// permission lines, DROP any verb the object lists in `omit`, DROP any verb the
// object declares ITSELF (the object's own line overrides the template's), then
// append the object's own lines. The merged Perms keep template order followed by
// the object's own lines; emission sorts policies, so order is immaterial.
func (s *Spec) expandTemplates() error {
	byName := map[string]*Template{}
	for _, t := range s.Templates {
		if byName[t.Name] != nil {
			return fmt.Errorf("duplicate template %q", t.Name)
		}
		byName[t.Name] = t
	}
	for _, o := range s.Objects {
		if o.Use == "" {
			if len(o.Omit) > 0 {
				return fmt.Errorf("object %q declares `omit` without `use`", o.Name)
			}
			continue
		}
		t := byName[o.Use]
		if t == nil {
			return fmt.Errorf("object %q uses unknown template %q", o.Name, o.Use)
		}
		tmplVerbs := map[string]bool{}
		for _, pm := range t.Perms {
			tmplVerbs[pm.Verb] = true
		}
		for _, v := range o.Omit {
			if !tmplVerbs[v] {
				return fmt.Errorf("object %q omits verb %q which template %q does not define", o.Name, v, o.Use)
			}
		}
		omit := map[string]bool{}
		for _, v := range o.Omit {
			omit[v] = true
		}
		own := map[string]bool{}
		for _, pm := range o.Perms {
			own[pm.Verb] = true
		}
		var merged []*Perm
		for _, pm := range t.Perms {
			if omit[pm.Verb] || own[pm.Verb] {
				continue
			}
			cp := *pm // shallow copy: Tree/Expr/Guard are immutable, sharing is safe
			merged = append(merged, &cp)
		}
		o.Perms = append(merged, o.Perms...)
	}
	return nil
}

func (p *parser) parseLevelChain() ([]string, error) {
	first, err := p.ident()
	if err != nil {
		return nil, err
	}
	chain := []string{first}
	for p.peekKind() == tGT {
		p.advance()
		nm, err := p.ident()
		if err != nil {
			return nil, err
		}
		chain = append(chain, nm)
	}
	return chain, nil
}

func (p *parser) parseRelation() (*Relation, error) {
	r := &Relation{Pos: Pos{p.cur().line}}
	p.advance() // 'relation'
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	r.Name = name
	if _, err := p.expect(tColon); err != nil {
		return nil, err
	}
	// typeref := IDENT ('|' IDENT)*
	first, err := p.ident()
	if err != nil {
		return nil, err
	}
	r.Types = []string{first}
	for p.peekKind() == tPipe {
		p.advance()
		nm, err := p.ident()
		if err != nil {
			return nil, err
		}
		r.Types = append(r.Types, nm)
	}
	if err := p.expectKw("via"); err != nil {
		return nil, err
	}
	if r.Repr, err = p.parseRepr(); err != nil {
		return nil, err
	}
	if p.acceptKw("kind") {
		switch {
		case p.acceptKw("composition"):
			r.Kind = "composition"
		case p.acceptKw("association"):
			r.Kind = "association"
		default:
			return nil, p.errf("expected 'composition' or 'association' after kind, got %s %q", p.peekKind(), p.cur().lit)
		}
	}
	return r, nil
}

// parseTableCols parses `<table>(<col>, <col>, ...)` and returns the table name
// and its column list.
func (p *parser) parseTableCols() (string, []string, error) {
	tbl, err := p.ident()
	if err != nil {
		return "", nil, err
	}
	if _, err := p.expect(tLParen); err != nil {
		return "", nil, err
	}
	var cols []string
	for {
		c, err := p.ident()
		if err != nil {
			return "", nil, err
		}
		cols = append(cols, c)
		if p.peekKind() == tComma {
			p.advance()
			continue
		}
		break
	}
	if _, err := p.expect(tRParen); err != nil {
		return "", nil, err
	}
	return tbl, cols, nil
}

func (p *parser) parseRepr() (Repr, error) {
	switch {
	case p.acceptKw("edge"):
		return p.parseReprEdge()
	case p.acceptKw("role"):
		return p.parseReprRole()
	case p.acceptKw("composition"):
		return p.parseReprComposition()
	case p.acceptKw("closure"):
		return p.parseReprClosure()
	case p.acceptKw("group"):
		return p.parseReprGroup()
	case p.acceptKw("object"):
		return p.parseReprObject()
	case p.acceptKw("memberin"):
		return p.parseReprMemberIn()
	case p.acceptKw("grant"):
		return p.parseReprGrant()
	default:
		return p.parseReprColumn()
	}
}

// parseReprEdge: edge <Table>(<col>, <col>[, <col>])
func (p *parser) parseReprEdge() (Repr, error) {
	tbl, err := p.ident()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tLParen); err != nil {
		return nil, err
	}
	var cols []string
	for {
		c, err := p.ident()
		if err != nil {
			return nil, err
		}
		cols = append(cols, c)
		if p.peekKind() == tComma {
			p.advance()
			continue
		}
		break
	}
	if _, err := p.expect(tRParen); err != nil {
		return nil, err
	}
	if len(cols) < 2 || len(cols) > 3 {
		return nil, p.errf("via edge needs 2 or 3 columns, got %d", len(cols))
	}
	return ViaEdge{Table: tbl, Cols: cols}, nil
}

// parseReprRole: role [(rank >= <min>)]
func (p *parser) parseReprRole() (Repr, error) {
	vr := ViaRole{}
	if p.peekKind() == tLParen {
		p.advance()
		if err := p.expectKw("rank"); err != nil {
			return nil, err
		}
		if _, err := p.expect(tGE); err != nil {
			return nil, err
		}
		rm, err := p.ident()
		if err != nil {
			return nil, err
		}
		vr.HasRank = true
		vr.RankMin = rm
		if _, err := p.expect(tRParen); err != nil {
			return nil, err
		}
	}
	return vr, nil
}

// parseReprComposition: composition <Table>
func (p *parser) parseReprComposition() (Repr, error) {
	tbl, err := p.ident()
	if err != nil {
		return nil, err
	}
	return ViaComposition{Table: tbl}, nil
}

// parseReprClosure: closure <Closure>(<anc>,<desc>) base <Base>(<id>,<parent>) on <col>
func (p *parser) parseReprClosure() (Repr, error) {
	clo, cloCols, err := p.parseTableCols()
	if err != nil {
		return nil, err
	}
	if len(cloCols) != 2 {
		return nil, p.errf("via closure needs a closure table with 2 columns (ancestor, descendant), got %d", len(cloCols))
	}
	if err := p.expectKw("base"); err != nil {
		return nil, err
	}
	base, baseCols, err := p.parseTableCols()
	if err != nil {
		return nil, err
	}
	if len(baseCols) != 2 {
		return nil, p.errf("via closure base needs 2 columns (id, parent), got %d", len(baseCols))
	}
	if err := p.expectKw("on"); err != nil {
		return nil, err
	}
	col, err := p.ident()
	if err != nil {
		return nil, err
	}
	return ViaClosure{
		Closure: clo, AncestorCol: cloCols[0], DescendantCol: cloCols[1],
		Base: base, BaseID: baseCols[0], BaseParent: baseCols[1], Col: col,
	}, nil
}

// parseReprGroup: group <Closure>(<group>,<member>) edge <Edge>(<member>,<group>) on <col>
func (p *parser) parseReprGroup() (Repr, error) {
	clo, cloCols, err := p.parseTableCols()
	if err != nil {
		return nil, err
	}
	if len(cloCols) != 2 {
		return nil, p.errf("via group needs a closure table with 2 columns (group, member), got %d", len(cloCols))
	}
	if err := p.expectKw("edge"); err != nil {
		return nil, err
	}
	edge, edgeCols, err := p.parseTableCols()
	if err != nil {
		return nil, err
	}
	if len(edgeCols) != 2 {
		return nil, p.errf("via group edge needs 2 columns (member, group), got %d", len(edgeCols))
	}
	if err := p.expectKw("on"); err != nil {
		return nil, err
	}
	col, err := p.ident()
	if err != nil {
		return nil, err
	}
	mat := p.acceptKw("materialized")
	return ViaGroup{
		Closure: clo, GroupCol: cloCols[0], MemberCol: cloCols[1],
		Edge: edge, EdgeMember: edgeCols[0], EdgeGroup: edgeCols[1], Col: col,
		Materialized: mat,
	}, nil
}

// parseReprObject: object <Other>-><verb> on <col>
func (p *parser) parseReprObject() (Repr, error) {
	other, err := p.ident()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tArrow); err != nil {
		return nil, err
	}
	verb, err := p.ident()
	if err != nil {
		return nil, err
	}
	if err := p.expectKw("on"); err != nil {
		return nil, err
	}
	col, err := p.ident()
	if err != nil {
		return nil, err
	}
	return ViaObject{Object: other, Verb: verb, Col: col}, nil
}

// parseReprMemberIn: memberin <level>(<principal-src>, <scope-src>) ; src = @<claim> | <col>
func (p *parser) parseReprMemberIn() (Repr, error) {
	level, err := p.ident()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tLParen); err != nil {
		return nil, err
	}
	principal, err := p.parseArgSrc()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tComma); err != nil {
		return nil, err
	}
	scope, err := p.parseArgSrc()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tRParen); err != nil {
		return nil, err
	}
	return ViaMemberIn{Level: level, Principal: principal, Scope: scope}, nil
}

// parseReprGrant: grant <Table>(record, kind, principal, access) [where <col> = "<v>"]
func (p *parser) parseReprGrant() (Repr, error) {
	tbl, cols, err := p.parseTableCols()
	if err != nil {
		return nil, err
	}
	if len(cols) != 4 {
		return nil, p.errf("via grant needs 4 columns (record, kind, principal, access), got %d", len(cols))
	}
	vg := ViaGrant{Table: tbl, RecordCol: cols[0], KindCol: cols[1], PrincipalCol: cols[2], AccessCol: cols[3]}
	if p.acceptKw("where") {
		col, err := p.ident()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tEq); err != nil {
			return nil, err
		}
		val, err := p.expect(tString)
		if err != nil {
			return nil, err
		}
		vg.DiscrimCol, vg.DiscrimVal = col, val.lit
	}
	// Optional `tracked`: opt the store into the authz changelog (WS4).
	vg.Tracked = p.acceptKw("tracked")
	// Optional `async` (after `tracked`): also build an async affordance index (WS4).
	vg.Async = p.acceptKw("async")
	return vg, nil
}

// parseReprColumn: via <fk column> [where <kind_col> = "<val>"]
func (p *parser) parseReprColumn() (Repr, error) {
	col, err := p.ident()
	if err != nil {
		return nil, err
	}
	vc := ViaColumn{Column: col}
	// Optional discriminator: an owner column gated by a kind column — the unified
	// (owner_id, owner_kind) shape, mirroring the grant-edge `where`. Several owner
	// kinds share one id column, each gated by a constant in the kind column.
	if p.acceptKw("where") {
		dcol, err := p.ident()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tEq); err != nil {
			return nil, err
		}
		val, err := p.expect(tString)
		if err != nil {
			return nil, err
		}
		vc.DiscrimCol, vc.DiscrimVal = dcol, val.lit
	}
	return vc, nil
}

// parseArgSrc parses a ViaMemberIn argument: `@<claim>` (a claim key) or `<col>`
// (a column on the object's own row).
func (p *parser) parseArgSrc() (ArgSrc, error) {
	if p.peekKind() == tAt {
		p.advance()
		k, err := p.ident()
		if err != nil {
			return ArgSrc{}, err
		}
		return ArgSrc{Claim: k}, nil
	}
	c, err := p.ident()
	if err != nil {
		return ArgSrc{}, err
	}
	return ArgSrc{Col: c}, nil
}

func (p *parser) parseObjectPerm() (*Perm, error) {
	pm := &Perm{Pos: Pos{p.cur().line}}
	p.advance() // 'permission'
	verb, err := p.ident()
	if err != nil {
		return nil, err
	}
	pm.Verb = verb
	if _, err := p.expect(tEq); err != nil {
		return nil, err
	}
	// Boolean expression (v3 WS1), stops at the '@' layertag. Precedence, low→high:
	//   union := and (('+'|'or') and)*
	//   and   := unary (('and') unary)*
	//   unary := 'not'? primary
	//   primary := '(' union ')' | term
	tree, err := p.parsePermUnion()
	if err != nil {
		return nil, err
	}
	pm.Tree = tree
	pm.Expr = tree.Leaves()
	// layertag := '@' LAYER (',' LAYER)*
	if _, err := p.expect(tAt); err != nil {
		return nil, err
	}
	first, err := p.ident()
	if err != nil {
		return nil, err
	}
	pm.Layers = append(pm.Layers, first)
	for p.peekKind() == tComma {
		p.advance()
		l, err := p.ident()
		if err != nil {
			return nil, err
		}
		pm.Layers = append(pm.Layers, l)
	}
	// ('maps' mapref)?
	if p.acceptKw("maps") {
		switch p.peekKind() {
		case tIdent, tPermKey:
			pm.Maps = p.advance().lit
		default:
			return nil, p.errf("expected a table-op or permission after maps, got %s %q", p.peekKind(), p.cur().lit)
		}
	}
	// ('guard' col op literal)?
	if p.acceptKw("guard") {
		g := &Guard{Pos: Pos{p.cur().line}}
		if g.Col, err = p.ident(); err != nil {
			return nil, err
		}
		switch p.peekKind() {
		case tEq:
			g.Op = "="
		case tNE:
			g.Op = "<>"
		default:
			return nil, p.errf("guard operator must be = or <>, got %s", p.peekKind())
		}
		p.advance()
		lit, err := p.expect(tString)
		if err != nil {
			return nil, err
		}
		g.Val = lit.lit
		pm.Guard = g
	}
	return pm, nil
}

// parsePermUnion / parsePermAnd / parsePermUnary / parsePermPrimary parse the
// permission boolean expression (v3 WS1). Union (`+`/`or`) is lowest precedence,
// then intersection (`and`), then unary `not`, then a term or a parenthesised
// sub-expression. A single operand returns its bare node (so a union-only spec is
// unchanged). Parsing stops at the `@` layertag (no operator consumes it).
func (p *parser) parsePermUnion() (*PermNode, error) {
	left, err := p.parsePermAnd()
	if err != nil {
		return nil, err
	}
	kids := []*PermNode{left}
	for p.peekKind() == tPlus || p.isKw("or") {
		p.advance()
		r, err := p.parsePermAnd()
		if err != nil {
			return nil, err
		}
		kids = append(kids, r)
	}
	if len(kids) == 1 {
		return left, nil
	}
	return &PermNode{Op: "or", Kids: kids}, nil
}

func (p *parser) parsePermAnd() (*PermNode, error) {
	left, err := p.parsePermUnary()
	if err != nil {
		return nil, err
	}
	kids := []*PermNode{left}
	for p.isKw("and") {
		p.advance()
		r, err := p.parsePermUnary()
		if err != nil {
			return nil, err
		}
		kids = append(kids, r)
	}
	if len(kids) == 1 {
		return left, nil
	}
	return &PermNode{Op: "and", Kids: kids}, nil
}

func (p *parser) parsePermUnary() (*PermNode, error) {
	if p.isKw("not") {
		p.advance()
		k, err := p.parsePermPrimary()
		if err != nil {
			return nil, err
		}
		return &PermNode{Op: "not", Kids: []*PermNode{k}}, nil
	}
	return p.parsePermPrimary()
}

func (p *parser) parsePermPrimary() (*PermNode, error) {
	if p.peekKind() == tLParen {
		p.advance()
		n, err := p.parsePermUnion()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tRParen); err != nil {
			return nil, err
		}
		return n, nil
	}
	t, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	return &PermNode{Op: "leaf", Term: t}, nil
}

func (p *parser) parseTerm() (*Term, error) {
	t := &Term{Pos: Pos{p.cur().line}}
	if p.peekKind() == tAt {
		p.advance()
		b, err := p.ident()
		if err != nil {
			return nil, err
		}
		t.Builtin = b
		if err := p.parseTermBuiltin(t); err != nil {
			return nil, err
		}
		return t, nil
	}
	// `mode <col> = "<v>" [for <subject>]` — a column-condition (visibility) term.
	if p.isKw("mode") {
		if err := p.parseTermMode(t); err != nil {
			return nil, err
		}
		return t, nil
	}
	// `via grant <name>` — reference a declared grant's reach as a permission term
	// (the same `via grant <name>` a subject uses for its reach), conferring the verb
	// to that grant's holders.
	if p.isKw("via") {
		p.advance()
		if err := p.expectKw("grant"); err != nil {
			return nil, err
		}
		name, err := p.ident()
		if err != nil {
			return nil, err
		}
		t.GrantRef = name
		return t, nil
	}
	// A term is normally a relation IDENT, but a @pdp permission maps to a
	// capability PERMKEY (e.g. `publish = content:publish @pdp`); accept both.
	switch p.peekKind() {
	case tIdent, tPermKey:
		t.Ident = p.advance().lit
	default:
		return nil, p.errf("expected a relation, capability, or @builtin term, got %s %q", p.peekKind(), p.cur().lit)
	}
	if p.peekKind() == tArrow {
		p.advance()
		v, err := p.ident()
		if err != nil {
			return nil, err
		}
		t.WalkVerb = v
	}
	return t, nil
}

// parseTermBuiltin parses the optional argument list of an `@<builtin>` term
// (t.Builtin already set): @session(<rel>), @app_scope(exclude <rel>), @kind("<v>").
func (p *parser) parseTermBuiltin(t *Term) error {
	b := t.Builtin
	// `@session(<rel>)` — a session-self-gated role grant.
	if b == "session" && p.peekKind() == tLParen {
		p.advance()
		rel, err := p.ident()
		if err != nil {
			return err
		}
		t.SessionRel = rel
		if _, err := p.expect(tRParen); err != nil {
			return err
		}
	}
	// `@app_scope(exclude <rel>)` — the broad reach minus rows owned via <rel>
	// (operator-private admin-owned rows). The de-prescribed admin-owner exclusion.
	if b == "app_scope" && p.peekKind() == tLParen {
		p.advance()
		if err := p.expectKw("exclude"); err != nil {
			return err
		}
		rel, err := p.ident()
		if err != nil {
			return err
		}
		t.ExcludeRel = rel
		if _, err := p.expect(tRParen); err != nil {
			return err
		}
	}
	// `@kind("<value>")` — a typed-subject match on the caller's principal-kind claim.
	if b == "kind" {
		if _, err := p.expect(tLParen); err != nil {
			return err
		}
		val, err := p.expect(tString)
		if err != nil {
			return err
		}
		t.KindVal = val.lit
		if _, err := p.expect(tRParen); err != nil {
			return err
		}
	}
	return nil
}

// parseTermMode parses `mode <col> = "<v>" [for <subject>]` into t.
func (p *parser) parseTermMode(t *Term) error {
	p.advance() // 'mode'
	col, err := p.ident()
	if err != nil {
		return err
	}
	if _, err := p.expect(tEq); err != nil {
		return err
	}
	val, err := p.expect(tString)
	if err != nil {
		return err
	}
	t.ModeCol, t.ModeVal = col, val.lit
	if p.acceptKw("for") {
		sub, err := p.ident()
		if err != nil {
			return err
		}
		t.ModeScope = sub
	}
	return nil
}

func (p *parser) parseProcedures() (*Procedures, error) {
	pr := &Procedures{Pos: Pos{p.cur().line}}
	p.advance() // 'procedures'
	site, err := p.ident()
	if err != nil {
		return nil, err
	}
	pr.EmitSite = site
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	for p.peekKind() == tProc {
		proc := p.advance().lit
		if _, err := p.expect(tArrow); err != nil {
			return nil, err
		}
		perm, err := p.expect(tPermKey)
		if err != nil {
			return nil, err
		}
		pr.Entries = append(pr.Entries, ProcEntry{Proc: proc, Perm: perm.lit, Pos: Pos{perm.line}})
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return pr, nil
}

func (p *parser) parseUngoverned() (*Ungoverned, error) {
	u := &Ungoverned{Pos: Pos{p.cur().line}}
	p.advance() // 'ungoverned'
	site, err := p.ident()
	if err != nil {
		return nil, err
	}
	u.EmitSite = site
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	for p.peekKind() == tProc {
		proc := p.advance().lit
		if _, err := p.expect(tColon); err != nil {
			return nil, err
		}
		reason, err := p.expect(tString)
		if err != nil {
			return nil, err
		}
		u.Entries = append(u.Entries, UngovEntry{Proc: proc, Reason: reason.lit, Pos: Pos{reason.line}})
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return u, nil
}

func roleStoreKeyword(s string) bool {
	switch s {
	case "assignments", "kind", "subject", "scope", "rolejoin", "revoked", "permissions", "pk", "granted", "column":
		return true
	}
	return false
}

// parseRoleStore: rolestore IDENT { assignments T; kind C = "V"; subject C;
// scope C+; rolejoin C RolesT RolesID KeyC; revoked C; [permissions C] }
// `permissions` is OPTIONAL — the roles-table column holding a role's materialized
// effective permission set, read by the holds-resolver (EID-334).
func (p *parser) parseRoleStore() (*RoleStore, error) {
	rs := &RoleStore{Pos: Pos{p.cur().line}}
	p.advance() // 'rolestore'
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	rs.Name = name
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	for p.peekKind() != tRBrace && p.peekKind() != tEOF {
		switch {
		case p.acceptKw("assignments"):
			rs.Assignments, err = p.ident()
		case p.acceptKw("kind"):
			err = p.parseRoleStoreKind(rs)
		case p.acceptKw("subject"):
			rs.SubjectCol, err = p.ident()
		case p.acceptKw("scope"):
			for p.peekKind() == tIdent && !roleStoreKeyword(p.cur().lit) {
				rs.ScopeCols = append(rs.ScopeCols, p.advance().lit)
			}
		case p.acceptKw("rolejoin"):
			err = p.parseRoleStoreJoin(rs)
		case p.acceptKw("revoked"):
			err = p.parseRoleStoreRevoked(rs)
		case p.acceptKw("permissions"):
			rs.PermsCol, err = p.ident()
		case p.acceptKw("pk"):
			rs.IDCol, err = p.ident()
		case p.acceptKw("granted"):
			err = p.parseRoleStoreGranted(rs)
		case p.acceptKw("column"):
			var col string
			if col, err = p.ident(); err == nil {
				rs.ExtraCols = append(rs.ExtraCols, col)
			}
		default:
			return nil, p.errf("unexpected %s %q in rolestore", p.peekKind(), p.cur().lit)
		}
		if err != nil {
			return nil, err
		}
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return rs, nil
}

// parseRoleStoreKind parses `kind <col> = "<val>"` into rs.
func (p *parser) parseRoleStoreKind(rs *RoleStore) error {
	col, err := p.ident()
	if err != nil {
		return err
	}
	rs.KindCol = col
	if _, err := p.expect(tEq); err != nil {
		return err
	}
	v, err := p.expect(tString)
	if err != nil {
		return err
	}
	rs.KindVal = v.lit
	return nil
}

// parseRoleStoreJoin parses `rolejoin <col> <table> <id> <key>` into rs.
// parseRoleStoreRevoked: revoked <col> [by <col>] — the active-filter column and
// its optional revoker-audit companion (Layer 3 write surface).
func (p *parser) parseRoleStoreRevoked(rs *RoleStore) error {
	col, err := p.ident()
	if err != nil {
		return err
	}
	rs.RevokedCol = col
	if p.acceptKw("by") {
		rs.RevokedByCol, err = p.ident()
	}
	return err
}

// parseRoleStoreGranted: granted <at-col> [by <col>] — the grant-audit timestamp
// column and its optional grantor-audit companion (Layer 3 write surface).
func (p *parser) parseRoleStoreGranted(rs *RoleStore) error {
	col, err := p.ident()
	if err != nil {
		return err
	}
	rs.GrantedAtCol = col
	if p.acceptKw("by") {
		rs.GrantedByCol, err = p.ident()
	}
	return err
}

func (p *parser) parseRoleStoreJoin(rs *RoleStore) error {
	col, err := p.ident()
	if err != nil {
		return err
	}
	rs.RoleCol = col
	if rs.RolesTable, err = p.ident(); err != nil {
		return err
	}
	if rs.RolesID, err = p.ident(); err != nil {
		return err
	}
	rs.KeyCol, err = p.ident()
	return err
}

// parseClaims: claims via "<setting>" [json|jsonb] [role <ident>] — declares the
// request-context claim accessor (the GUC name + cast) and, optionally, the RLS
// connection role a session assumes. Cast defaults to json; role defaults (via
// claimRole) to "authenticated".
func (p *parser) parseClaims() (*ClaimsAccessor, error) {
	c := &ClaimsAccessor{Cast: "json", Pos: Pos{p.cur().line}}
	p.advance() // 'claims'
	if err := p.expectKw("via"); err != nil {
		return nil, err
	}
	setting, err := p.expect(tString)
	if err != nil {
		return nil, err
	}
	c.Setting = setting.lit
	// Optional cast (json|jsonb): any trailing ident that is NOT the `role` keyword.
	if p.peekKind() == tIdent && !p.isKw("role") {
		c.Cast = p.advance().lit
	}
	// Optional RLS connection role.
	if p.acceptKw("role") {
		if c.Role, err = p.ident(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// parseGrant: grant IDENT at LEVEL via edge TABLE(grantee_col, level_col)
//
//	[active COL] [expires COL]
//	[pk COL] [granted by COL] [revoked by COL] [created COL]   (management write surface)
func (p *parser) parseGrant() (*Grant, error) {
	g := &Grant{Pos: Pos{p.cur().line}}
	p.advance() // 'grant'
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	g.Name = name
	if err := p.expectKw("at"); err != nil {
		return nil, err
	}
	if g.Level, err = p.ident(); err != nil {
		return nil, err
	}
	if err := p.expectKw("via"); err != nil {
		return nil, err
	}
	if err := p.expectKw("edge"); err != nil {
		return nil, err
	}
	if g.Table, err = p.ident(); err != nil {
		return nil, err
	}
	if _, err := p.expect(tLParen); err != nil {
		return nil, err
	}
	if g.GranteeCol, err = p.ident(); err != nil {
		return nil, err
	}
	if _, err := p.expect(tComma); err != nil {
		return nil, err
	}
	if g.LevelCol, err = p.ident(); err != nil {
		return nil, err
	}
	if _, err := p.expect(tRParen); err != nil {
		return nil, err
	}
	if err := p.parseGrantOptions(g); err != nil {
		return nil, err
	}
	return g, nil
}

// parseGrantOptions parses the optional trailing grant clauses in any order: the reach
// validity columns `active <col>` (NULL ⇒ active) / `expires <col>` (> now() ⇒ active),
// and the management write-surface columns `pk <col>`, `granted by <col>`,
// `revoked by <col>`, `created <col>`. Each binds a single identifier column (the
// `granted`/`revoked` forms consume an intervening `by`).
func (p *parser) parseGrantOptions(g *Grant) error {
	for {
		if p.acceptKw("column") {
			col, err := p.ident()
			if err != nil {
				return err
			}
			g.ExtraCols = append(g.ExtraCols, col)
			continue
		}
		var dst *string
		needBy := false
		switch {
		case p.acceptKw("active"):
			dst = &g.ActiveCol
		case p.acceptKw("expires"):
			dst = &g.ExpiresCol
		case p.acceptKw("pk"):
			dst = &g.IDCol
		case p.acceptKw("created"):
			dst = &g.CreatedAtCol
		case p.acceptKw("granted"):
			dst, needBy = &g.GrantedByCol, true
		case p.acceptKw("revoked"):
			dst, needBy = &g.RevokedByCol, true
		default:
			return nil
		}
		if needBy {
			if err := p.expectKw("by"); err != nil {
				return err
			}
		}
		col, err := p.ident()
		if err != nil {
			return err
		}
		*dst = col
	}
}

func (p *parser) parseFieldScopes() (*FieldScopes, error) {
	fs := &FieldScopes{Pos: Pos{p.cur().line}}
	p.advance() // 'fieldscopes'
	site, err := p.ident()
	if err != nil {
		return nil, err
	}
	fs.Site = site
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	for p.peekKind() == tIdent {
		field := p.advance().lit
		if _, err := p.expect(tArrow); err != nil {
			return nil, err
		}
		scope, err := p.expect(tPermKey)
		if err != nil {
			return nil, err
		}
		fs.Entries = append(fs.Entries, FieldScopeEntry{Field: field, Scope: scope.lit, Pos: Pos{scope.line}})
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return fs, nil
}

// String renders a Term back to its source form (for diagnostics/tests).
func (t *Term) String() string {
	switch {
	case t.GrantRef != "":
		return "via grant " + t.GrantRef
	case t.Builtin != "":
		return "@" + t.Builtin
	case t.WalkVerb != "":
		return t.Ident + "->" + t.WalkVerb
	default:
		return t.Ident
	}
}

// LayerTag renders the layer list (e.g. "@rls,kernel").
func (pm *Perm) LayerTag() string {
	return "@" + strings.Join(pm.Layers, ",")
}
