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
	return p.parseSpec()
}

type parser struct {
	toks []token
	i    int
	// virtualRoot is the name of the topology's virtual root level, captured when
	// the topology block is parsed so the `platform <table>` shorthand can anchor a
	// global object there without restating it. "" until the topology is seen.
	virtualRoot string
}

func (p *parser) cur() token  { return p.toks[p.i] }
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
		switch p.cur().lit {
		case "topology":
			t, err := p.parseTopology()
			if err != nil {
				return nil, err
			}
			if s.Topology != nil {
				return nil, p.errf("duplicate topology block")
			}
			s.Topology = t
			for _, l := range t.Levels {
				if l.isRoot() && l.Virtual {
					p.virtualRoot = l.Name
				}
			}
		case "vocabulary":
			v, err := p.parseVocabulary()
			if err != nil {
				return nil, err
			}
			s.Vocabs = append(s.Vocabs, v)
		case "subject":
			sub, err := p.parseSubject()
			if err != nil {
				return nil, err
			}
			s.Subjects = append(s.Subjects, sub)
		case "object":
			o, err := p.parseObject()
			if err != nil {
				return nil, err
			}
			s.Objects = append(s.Objects, o)
		case "settings":
			o, err := p.parseSettings()
			if err != nil {
				return nil, err
			}
			s.Objects = append(s.Objects, o)
		case "platform":
			o, err := p.parsePlatform()
			if err != nil {
				return nil, err
			}
			s.Objects = append(s.Objects, o)
		case "procedures":
			pr, err := p.parseProcedures()
			if err != nil {
				return nil, err
			}
			s.Procedures = append(s.Procedures, pr)
		case "ungoverned":
			u, err := p.parseUngoverned()
			if err != nil {
				return nil, err
			}
			s.Ungoverned = append(s.Ungoverned, u)
		case "fieldscopes":
			fs, err := p.parseFieldScopes()
			if err != nil {
				return nil, err
			}
			s.FieldScopes = append(s.FieldScopes, fs)
		case "rolestore":
			rs, err := p.parseRoleStore()
			if err != nil {
				return nil, err
			}
			s.RoleStores = append(s.RoleStores, rs)
		case "grant":
			g, err := p.parseGrant()
			if err != nil {
				return nil, err
			}
			s.Grants = append(s.Grants, g)
		case "claims":
			c, err := p.parseClaims()
			if err != nil {
				return nil, err
			}
			if s.Claims != nil {
				return nil, p.errf("duplicate claims block")
			}
			s.Claims = c
		case "definers":
			p.advance() // 'definers'
			if err := p.expectKw("schema"); err != nil {
				return nil, err
			}
			sch, err := p.expect(tString)
			if err != nil {
				return nil, err
			}
			if s.DefinerSchema != "" {
				return nil, p.errf("duplicate definers block")
			}
			s.DefinerSchema = sch.lit
		default:
			return nil, p.errf("unknown declaration %q", p.cur().lit)
		}
	}
	return s, nil
}

func (p *parser) parseTopology() (*Topology, error) {
	pos := Pos{p.cur().line}
	_ = p.advance() // 'topology'
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	t := &Topology{Pos: pos}
	for p.isKw("level") {
		lv := &Level{Pos: Pos{p.cur().line}}
		p.advance() // 'level'
		name, err := p.ident()
		if err != nil {
			return nil, err
		}
		lv.Name = name
		// ('parent' IDENT | 'parents' IDENT (',' IDENT)*)? ('virtual')? — any order,
		// all optional. `parents` (plural) declares a multi-parent DAG level.
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
				for {
					par, err := p.ident()
					if err != nil {
						return nil, err
					}
					lv.Parents = append(lv.Parents, par)
					if p.peekKind() != tComma {
						break
					}
					p.advance() // ','
				}
				continue
			}
			if p.acceptKw("virtual") {
				lv.Virtual = true
				continue
			}
			break
		}
		t.Levels = append(t.Levels, lv)
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return t, nil
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
	for p.peekKind() != tRBrace && p.peekKind() != tEOF {
		switch {
		case p.isKw("relation"):
			r, err := p.parseRelation()
			if err != nil {
				return nil, err
			}
			o.Relations = append(o.Relations, r)
		case p.isKw("descriptor"):
			if o.Descriptor != nil {
				return nil, p.errf("object %q has more than one descriptor block", o.Name)
			}
			d, err := p.parseDescriptor()
			if err != nil {
				return nil, err
			}
			o.Descriptor = d
		case p.isKw("permission"):
			pm, err := p.parseObjectPerm()
			if err != nil {
				return nil, err
			}
			o.Perms = append(o.Perms, pm)
		default:
			return nil, p.errf("unexpected %s %q in object %q", p.peekKind(), p.cur().lit, o.Name)
		}
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return o, nil
}

// parseSettings is the compact admin-config form: `settings <table> scoped
// <chain>` expands to a containment-only object (the §5.3 settings pattern —
// operator OR tenant+project containment, no grants; verb authority is the PDP).
func (p *parser) parseSettings() (*Object, error) {
	o := &Object{Pos: Pos{p.cur().line}}
	p.advance() // 'settings'
	tbl, err := p.ident()
	if err != nil {
		return nil, err
	}
	o.Name = tbl
	o.Table = tbl
	if err := p.expectKw("scoped"); err != nil {
		return nil, err
	}
	if o.Scoped, err = p.parseLevelChain(); err != nil {
		return nil, err
	}
	line := o.Pos
	scoped := func(verb, op string) *Perm {
		return &Perm{Verb: verb, Expr: []*Term{{Builtin: "scoped", Pos: line}}, Layers: []string{"rls"}, Maps: op, Pos: line}
	}
	o.Perms = []*Perm{
		scoped("view", "select"),
		scoped("create", "insert"),
		scoped("edit", "update"),
		scoped("delete", "delete"),
	}
	return o, nil
}

// parsePlatform is the compact GLOBAL-object form (v3 WS6): `platform <table>`
// expands to an object scoped at the virtual root level — a table ABOVE tenancy,
// with no containment columns, governed entirely by the platform-role subject
// branch. It is the platform-plane analogue of `settings <table> scoped …`: the
// same four @scoped (plane-only) permissions, but the "plane" is the platform
// role rather than a tenant/project containment chain. The general retirement of
// is_platform_admin lives here — these objects' staff-access definer is generated
// (is_platform_<role>), not hand-written.
func (p *parser) parsePlatform() (*Object, error) {
	o := &Object{Pos: Pos{p.cur().line}}
	p.advance() // 'platform'
	tbl, err := p.ident()
	if err != nil {
		return nil, err
	}
	o.Name = tbl
	o.Table = tbl
	if p.virtualRoot == "" {
		return nil, p.errf("`platform %s` needs a virtual root level in the topology (e.g. `level platform virtual`) to anchor a global object", tbl)
	}
	o.Scoped = []string{p.virtualRoot}
	line := o.Pos
	scoped := func(verb, op string) *Perm {
		return &Perm{Verb: verb, Expr: []*Term{{Builtin: "scoped", Pos: line}}, Layers: []string{"rls"}, Maps: op, Pos: line}
	}
	o.Perms = []*Perm{
		scoped("view", "select"),
		scoped("create", "insert"),
		scoped("edit", "update"),
		scoped("delete", "delete"),
	}
	return o, nil
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
	case p.acceptKw("role"):
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
	case p.acceptKw("composition"):
		tbl, err := p.ident()
		if err != nil {
			return nil, err
		}
		return ViaComposition{Table: tbl}, nil
	case p.acceptKw("closure"):
		// closure <Closure>(<anc>,<desc>) base <Base>(<id>,<parent>) on <col>
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
	case p.acceptKw("group"):
		// group <Closure>(<group>,<member>) edge <Edge>(<member>,<group>) on <col>
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
		return ViaGroup{
			Closure: clo, GroupCol: cloCols[0], MemberCol: cloCols[1],
			Edge: edge, EdgeMember: edgeCols[0], EdgeGroup: edgeCols[1], Col: col,
		}, nil
	case p.acceptKw("object"):
		// object <Other>-><verb> on <col>
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
	case p.acceptKw("memberin"):
		// memberin <level>(<principal-src>, <scope-src>) ; src = @<claim> | <col>
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
	case p.acceptKw("grant"):
		// grant <Table>(record, kind, principal, access) [where <col> = "<v>"]
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
		return vg, nil
	default:
		// via <fk column>
		col, err := p.ident()
		if err != nil {
			return nil, err
		}
		return ViaColumn{Column: col}, nil
	}
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

func (p *parser) parseDescriptor() (*Descriptor, error) {
	d := &Descriptor{Pos: Pos{p.cur().line}}
	p.advance() // 'descriptor'
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	for p.peekKind() != tRBrace && p.peekKind() != tEOF {
		switch {
		case p.acceptKw("owner"):
			if d.Owner != nil {
				return nil, p.errf("descriptor has more than one owner")
			}
			o, err := p.parseDescriptorOwner()
			if err != nil {
				return nil, err
			}
			d.Owner = o
		case p.acceptKw("admin"):
			if err := p.expectKw("owner"); err != nil {
				return nil, err
			}
			if d.AdminOwner != nil {
				return nil, p.errf("descriptor has more than one admin owner")
			}
			ao, err := p.parseDescriptorOwner()
			if err != nil {
				return nil, err
			}
			ao.Name = "admin_owner"
			d.AdminOwner = ao
		case p.acceptKw("mode"):
			if err := p.expectKw("via"); err != nil {
				return nil, err
			}
			col, err := p.ident()
			if err != nil {
				return nil, err
			}
			d.ModeCol = col
		case p.acceptKw("modes"):
			modes, err := p.parseModes()
			if err != nil {
				return nil, err
			}
			d.Modes = modes
		case p.acceptKw("grants"):
			g, err := p.parseAclEdge()
			if err != nil {
				return nil, err
			}
			d.Grants = g
		default:
			return nil, p.errf("unexpected %s %q in descriptor", p.peekKind(), p.cur().lit)
		}
	}
	if _, err := p.expect(tRBrace); err != nil {
		return nil, err
	}
	return d, nil
}

func (p *parser) parseDescriptorOwner() (*Relation, error) {
	r := &Relation{Name: "owner", Pos: Pos{p.cur().line}}
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
	col, err := p.ident()
	if err != nil {
		return nil, err
	}
	vc := ViaColumn{Column: col}
	// Optional discriminator: `where <kind_col> = "<val>"` — the owner reads
	// <id_col> gated by <kind_col> = constant (the unified owner_id/owner_kind
	// shape; mirrors the grants-edge `where`).
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
	r.Repr = vc
	return r, nil
}

func (p *parser) parseModes() ([]Mode, error) {
	var modes []Mode
	first, err := p.parseModeItem()
	if err != nil {
		return nil, err
	}
	modes = append(modes, first)
	for p.peekKind() == tPlus || p.peekKind() == tComma {
		p.advance()
		m, err := p.parseModeItem()
		if err != nil {
			return nil, err
		}
		modes = append(modes, m)
	}
	return modes, nil
}

// parseModeItem parses one descriptor mode: `private`, `read '<sentinel>'`, or
// `list '<kind>'`. The sentinel/kind are spec-declared strings — the engine has
// no baked mode vocabulary (EID-265 WS2).
func (p *parser) parseModeItem() (Mode, error) {
	m := Mode{Pos: Pos{p.cur().line}}
	switch {
	case p.acceptKw("private"):
		m.Kind = "private"
	case p.acceptKw("read"):
		v, err := p.expect(tString)
		if err != nil {
			return m, err
		}
		m.Kind, m.Value = "read", v.lit
		// Optional plane scope: `read "<sentinel>" for <subject>` confines the
		// public read to that principal plane (e.g. operators-only).
		if p.acceptKw("for") {
			sub, err := p.ident()
			if err != nil {
				return m, err
			}
			m.Scope = sub
		}
	case p.acceptKw("list"):
		v, err := p.expect(tString)
		if err != nil {
			return m, err
		}
		m.Kind, m.Value = "list", v.lit
	default:
		return m, p.errf("descriptor mode must be private | read '<sentinel>' | list '<kind>', got %s %q", p.peekKind(), p.cur().lit)
	}
	return m, nil
}

func (p *parser) parseAclEdge() (*AclEdge, error) {
	if err := p.expectKw("via"); err != nil {
		return nil, err
	}
	if err := p.expectKw("edge"); err != nil {
		return nil, err
	}
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
	if len(cols) != 4 {
		return nil, p.errf("grants edge needs 4 columns (record, kind, principal, access), got %d", len(cols))
	}
	e := &AclEdge{Table: tbl, RecordCol: cols[0], KindCol: cols[1], PrincipalCol: cols[2], AccessCol: cols[3]}
	// Optional discriminator: `where <col> = "<val>"` — lets several descriptors
	// share one store, each gated by a constant (the unified-resource_acl shape).
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
		e.DiscrimCol, e.DiscrimVal = col, val.lit
	}
	return e, nil
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
		// `@session(<rel>)` — a session-self-gated role grant.
		if b == "session" && p.peekKind() == tLParen {
			p.advance()
			rel, err := p.ident()
			if err != nil {
				return nil, err
			}
			t.SessionRel = rel
			if _, err := p.expect(tRParen); err != nil {
				return nil, err
			}
		}
		// `@app_scope(exclude <rel>)` — the broad reach minus rows owned via <rel>
		// (operator-private admin-owned rows). The de-prescribed admin-owner exclusion.
		if b == "app_scope" && p.peekKind() == tLParen {
			p.advance()
			if err := p.expectKw("exclude"); err != nil {
				return nil, err
			}
			rel, err := p.ident()
			if err != nil {
				return nil, err
			}
			t.ExcludeRel = rel
			if _, err := p.expect(tRParen); err != nil {
				return nil, err
			}
		}
		return t, nil
	}
	// `mode <col> = "<v>" [for <subject>]` — a column-condition (visibility) term.
	if p.isKw("mode") {
		p.advance()
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
		t.ModeCol, t.ModeVal = col, val.lit
		if p.acceptKw("for") {
			sub, err := p.ident()
			if err != nil {
				return nil, err
			}
			t.ModeScope = sub
		}
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
	case "assignments", "kind", "subject", "scope", "rolejoin", "revoked":
		return true
	}
	return false
}

// parseRoleStore: rolestore IDENT { assignments T; kind C = "V"; subject C;
// scope C+; rolejoin C RolesT RolesID KeyC; revoked C }
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
			if rs.KindCol, err = p.ident(); err == nil {
				if _, e := p.expect(tEq); e != nil {
					return nil, e
				}
				v, e := p.expect(tString)
				if e != nil {
					return nil, e
				}
				rs.KindVal = v.lit
			}
		case p.acceptKw("subject"):
			rs.SubjectCol, err = p.ident()
		case p.acceptKw("scope"):
			for p.peekKind() == tIdent && !roleStoreKeyword(p.cur().lit) {
				rs.ScopeCols = append(rs.ScopeCols, p.advance().lit)
			}
		case p.acceptKw("rolejoin"):
			if rs.RoleCol, err = p.ident(); err == nil {
				if rs.RolesTable, err = p.ident(); err == nil {
					if rs.RolesID, err = p.ident(); err == nil {
						rs.KeyCol, err = p.ident()
					}
				}
			}
		case p.acceptKw("revoked"):
			rs.RevokedCol, err = p.ident()
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

// parseClaims: claims via "<setting>" [json|jsonb] — declares the request-context
// claim accessor (the GUC name + cast). Cast defaults to json.
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
	if p.peekKind() == tIdent {
		c.Cast = p.advance().lit
	}
	return c, nil
}

// parseGrant: grant IDENT at LEVEL via edge TABLE(grantee_col, level_col)
//             [active COL] [expires COL]
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
	// optional `active <col>` (NULL ⇒ active) and `expires <col>` (> now() ⇒ active)
	for {
		if p.acceptKw("active") {
			if g.ActiveCol, err = p.ident(); err != nil {
				return nil, err
			}
			continue
		}
		if p.acceptKw("expires") {
			if g.ExpiresCol, err = p.ident(); err != nil {
				return nil, err
			}
			continue
		}
		break
	}
	return g, nil
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
