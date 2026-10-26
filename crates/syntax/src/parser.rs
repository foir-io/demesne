use crate::Error;
use crate::ast::{
    Admit, ArgSrc, Builtin, ClaimsAccessor, ExportParameter, External, ExternalArg, FieldRule, FieldScopeEntry, FieldScopes, Gate, Grant, GrantScope, GrantUse,
    Guard, GuardOp, Implication, Level, Membership, Object, Perm, PermNode, PermissionExport, Pos, Preset, ProcEntry, Procedures, Relation, RelationKind, Repr,
    Require, RoleStore, Spec, Subject, Template, Term, TermKind, Topology, UngovEntry, Ungoverned, ViaClosure, ViaColumn, ViaComposition, ViaEdge, ViaGrant,
    ViaGroup, ViaMemberIn, ViaObject, Vocabulary,
};
use crate::lexer::{Tok, Token, is_plain_identifier, lex};
use demesne_gocompat::quote;
use std::collections::{BTreeMap, HashMap, HashSet};

type PResult<T> = Result<T, Error>;

#[derive(Debug)]
struct LevelChain {
    chain: Vec<String>,
    wildcards: Vec<String>,
    verbs_by_level: BTreeMap<String, Vec<String>>,
}

/// The deepest a permission or requirement may nest parentheses.
///
/// The parser and every pass over a permission recurse once per level, so a limit keeps hostile
/// input from exhausting the stack. That matters most in WebAssembly, which has no stack guard:
/// an overflow there leaves the module unusable for every later call. The compiler handles a few
/// hundred levels there; real specs nest a handful.
pub const MAX_NESTING: usize = 64;

/// Parses `.demesne` spec text into a [`Spec`], expanding templates.
///
/// # Errors
///
/// A lexical or syntax error, parentheses nested deeper than [`MAX_NESTING`], or a template that
/// cannot be expanded. The error carries the line.
pub fn parse(src: &str) -> Result<Spec, Error> {
    parse_bytes(src.as_bytes())
}

/// Parses `.demesne` spec bytes into a [`Spec`], expanding templates.
///
/// # Errors
///
/// Invalid UTF-8 in a literal, a lexical or syntax error, parentheses nested deeper than
/// [`MAX_NESTING`], or a template that cannot be expanded.
pub fn parse_bytes(src: &[u8]) -> Result<Spec, Error> {
    let toks = lex(src)?;
    let mut p = Parser { toks, i: 0, depth: 0 };
    let mut s = p.parse_spec()?;
    expand_templates(&mut s)?;
    Ok(s)
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

struct Parser {
    toks: Vec<Token>,
    i: usize,
    depth: usize,
}

impl Parser {
    fn cur(&self) -> &Token {
        &self.toks[self.i]
    }

    fn line(&self) -> usize {
        self.cur().line
    }

    fn pos(&self) -> Pos {
        Pos { line: self.line() }
    }

    fn peek(&self) -> Tok {
        self.toks[self.i].kind
    }

    fn advance(&mut self) -> Token {
        let t = self.toks[self.i].clone();
        if self.i < self.toks.len() - 1 {
            self.i += 1;
        }
        t
    }

    fn err(&self, msg: impl AsRef<str>) -> Error {
        Error::at(self.line(), msg.as_ref())
    }

    fn got(&self) -> String {
        format!("{} {}", self.peek(), quote(&self.cur().lit))
    }

    fn expect(&mut self, k: Tok) -> PResult<Token> {
        if self.peek() != k {
            return Err(self.err(format!("expected {}, got {}", k, self.got())));
        }
        Ok(self.advance())
    }

    fn ident(&mut self) -> PResult<String> {
        Ok(self.expect(Tok::Ident)?.lit)
    }

    fn string(&mut self) -> PResult<String> {
        Ok(self.expect(Tok::Str)?.lit)
    }

    fn is_kw(&self, kw: &str) -> bool {
        self.peek() == Tok::Ident && self.cur().lit == kw
    }

    fn accept_kw(&mut self, kw: &str) -> bool {
        if self.is_kw(kw) {
            self.advance();
            return true;
        }
        false
    }

    fn expect_kw(&mut self, kw: &str) -> PResult<()> {
        if !self.accept_kw(kw) {
            return Err(self.err(format!("expected keyword {}, got {}", quote(kw), self.got())));
        }
        Ok(())
    }

    fn parse_spec(&mut self) -> PResult<Spec> {
        let mut s = Spec::default();
        while self.peek() != Tok::Eof {
            if self.peek() != Tok::Ident {
                return Err(self.err(format!("expected a declaration keyword, got {}", self.got())));
            }
            self.parse_decl(&mut s)?;
        }
        Ok(s)
    }

    fn parse_decl(&mut self, s: &mut Spec) -> PResult<()> {
        match self.cur().lit.as_str() {
            "topology" => {
                let t = self.parse_topology()?;
                if s.topology.is_some() {
                    return Err(self.err("duplicate topology block"));
                }
                s.topology = Some(t);
            }
            "vocabulary" => s.vocabs.push(self.parse_vocabulary()?),
            "subject" => s.subjects.push(self.parse_subject()?),
            "object" => s.objects.push(self.parse_object()?),
            "template" => s.templates.push(self.parse_template()?),
            "procedures" => s.procedures.push(self.parse_procedures()?),
            "ungoverned" => s.ungoverned.push(self.parse_ungoverned()?),
            "fieldscopes" => s.field_scopes.push(self.parse_field_scopes()?),
            "rolestore" => s.role_stores.push(self.parse_role_store()?),
            "grant" => s.grants.push(self.parse_grant()?),
            "claims" => {
                let c = self.parse_claims()?;
                if s.claims.is_some() {
                    return Err(self.err("duplicate claims block"));
                }
                s.claims = Some(c);
            }
            "definers" => s.definer_schema = self.parse_schema_decl(s.definer_schema.is_some(), "duplicate definers block")?,
            "tables" => s.table_schema = self.parse_schema_decl(s.table_schema.is_some(), "duplicate tables block")?,
            "identifiers" => {
                self.advance();
                let t = self.ident()?;
                if s.identifiers.is_some() {
                    return Err(self.err("duplicate identifiers declaration"));
                }
                s.identifiers = Some(t);
            }
            "external" => self.parse_external(s)?,
            other => return Err(self.err(format!("unknown declaration {}", quote(other)))),
        }
        Ok(())
    }

    fn parse_schema_decl(&mut self, declared: bool, duplicate: &str) -> PResult<Option<String>> {
        self.advance();
        self.expect_kw("schema")?;
        let sch = self.string()?;
        if declared {
            return Err(self.err(duplicate));
        }
        if !sch.is_empty() && !is_plain_identifier(&sch) {
            return Err(self.err(format!("schema {} is not a plain identifier: use letters, digits and _, not starting with a digit", quote(&sch))));
        }
        Ok(non_empty(sch))
    }

    fn parse_external(&mut self, s: &mut Spec) -> PResult<()> {
        let pos = self.pos();
        self.advance();
        self.expect_kw("predicate")?;
        let name = self.ident()?;
        self.expect(Tok::LParen)?;
        let mut arg_types = Vec::new();
        while self.peek() != Tok::RParen {
            arg_types.push(self.ident()?);
            if self.peek() == Tok::Comma {
                self.advance();
                continue;
            }
            break;
        }
        self.expect(Tok::RParen)?;
        if s.external_by_name(&name).is_some() {
            return Err(self.err(format!("duplicate external predicate {}", quote(&name))));
        }
        s.externals.push(External { name, arg_types, pos });
        Ok(())
    }

    fn parse_topology(&mut self) -> PResult<Topology> {
        let pos = self.pos();
        self.advance();
        self.expect(Tok::LBrace)?;
        let mut t = Topology { levels: Vec::new(), pos };
        while self.is_kw("level") {
            let lv = self.parse_level()?;
            t.levels.push(lv);
        }
        self.expect(Tok::RBrace)?;
        Ok(t)
    }

    fn parse_level(&mut self) -> PResult<Level> {
        let mut lv = Level { pos: self.pos(), ..Default::default() };
        self.advance();
        lv.name = self.ident()?;
        loop {
            if self.accept_kw("parent") {
                lv.parents.push(self.ident()?);
                continue;
            }
            if self.accept_kw("parents") {
                lv.parents.extend(self.ident_list()?);
                continue;
            }
            if self.accept_kw("virtual") {
                lv.is_virtual = true;
                continue;
            }
            if self.accept_kw("col") {
                lv.scope_col = Some(self.ident()?);
                continue;
            }
            if self.accept_kw("claim") {
                lv.claim_key = Some(self.ident()?);
                continue;
            }
            break;
        }
        Ok(lv)
    }

    fn parse_vocabulary(&mut self) -> PResult<Vocabulary> {
        let mut v = Vocabulary { pos: self.pos(), ..Default::default() };
        self.advance();
        v.name = self.ident()?;
        self.expect(Tok::LBrace)?;
        while self.peek() != Tok::RBrace && self.peek() != Tok::Eof {
            if self.is_kw("permission") {
                self.advance();
                let pk = self.expect(Tok::PermKey)?;
                v.permissions.push(pk.lit.clone());
                self.parse_implies(&mut v, &pk.lit)?;
            } else if self.is_kw("preset") {
                let pr = self.parse_preset()?;
                v.presets.push(pr);
            } else if self.is_kw("rank") {
                v.rank = self.parse_rank()?;
            } else {
                return Err(self.err(format!("unexpected {} in vocabulary {}", self.got(), quote(&v.name))));
            }
        }
        self.expect(Tok::RBrace)?;
        Ok(v)
    }

    fn parse_implies(&mut self, v: &mut Vocabulary, perm: &str) -> PResult<()> {
        if !self.is_kw("implies") {
            return Ok(());
        }
        let mut im = Implication { perm: perm.to_string(), pos: self.pos(), ..Default::default() };
        self.advance();
        if self.peek() == Tok::Star {
            self.advance();
            im.star = true;
            v.implications.push(im);
            return Ok(());
        }
        im.set.push(self.implies_item(perm)?);
        while self.peek() == Tok::Comma {
            self.advance();
            im.set.push(self.implies_item(perm)?);
        }
        v.implications.push(im);
        Ok(())
    }

    fn implies_item(&mut self, perm: &str) -> PResult<String> {
        match self.peek() {
            Tok::PermKey | Tok::Str => Ok(self.advance().lit),
            _ => Err(self.err(format!(
                "permission {}: `implies` takes `*` or a comma-separated list of permission keys (`<domain>:<verb>` or `<domain>:*`), got {}",
                quote(perm),
                self.got()
            ))),
        }
    }

    fn parse_preset(&mut self) -> PResult<Preset> {
        let mut pr = Preset { pos: self.pos(), ..Default::default() };
        self.advance();
        pr.name = self.ident()?;
        if self.peek() == Tok::At {
            self.advance();
            pr.level = Some(self.ident()?);
        }
        self.expect(Tok::Eq)?;
        if self.peek() == Tok::Star {
            self.advance();
            pr.star = true;
            return Ok(pr);
        }
        pr.set.push(self.permset_item()?);
        while self.peek() == Tok::Plus {
            self.advance();
            pr.set.push(self.permset_item()?);
        }
        Ok(pr)
    }

    fn permset_item(&mut self) -> PResult<String> {
        match self.peek() {
            Tok::PermKey | Tok::Ident => Ok(self.advance().lit),
            _ => Err(self.err(format!("expected a permission or preset name, got {}", self.got()))),
        }
    }

    fn parse_rank(&mut self) -> PResult<Vec<String>> {
        self.advance();
        let first = self.ident()?;
        let mut ranks = vec![first];
        if self.peek() != Tok::Gt {
            return Err(self.err(format!("rank ladder needs at least one '>' (got {})", self.peek())));
        }
        while self.peek() == Tok::Gt {
            self.advance();
            ranks.push(self.ident()?);
        }
        Ok(ranks)
    }

    fn parse_subject(&mut self) -> PResult<Subject> {
        let mut sub = Subject { pos: self.pos(), ..Default::default() };
        self.advance();
        sub.name = self.ident()?;
        self.expect(Tok::LBrace)?;
        while self.peek() != Tok::RBrace && self.peek() != Tok::Eof {
            self.parse_subject_clause(&mut sub)?;
        }
        self.expect(Tok::RBrace)?;
        Ok(sub)
    }

    fn parse_subject_clause(&mut self, sub: &mut Subject) -> PResult<()> {
        if self.accept_kw("anchor") {
            sub.anchor = Some(self.ident()?);
        } else if self.accept_kw("reach") {
            if self.accept_kw("via") {
                self.expect_kw("grant")?;
                sub.reach = Some("grant".to_string());
                sub.reach_grant = Some(self.ident()?);
            } else {
                sub.reach = Some(self.ident()?);
            }
        } else if self.accept_kw("identifies") {
            sub.identifies = Some(self.ident()?);
            if self.accept_kw("via") {
                self.parse_subject_membership(sub)?;
            }
        } else if self.accept_kw("roles") {
            if self.accept_kw("configurable") {
                sub.roles = Some(self.ident()?);
            } else if self.accept_kw("none") {
                sub.roles_none = true;
            } else {
                return Err(self.err(format!("expected 'configurable <vocab>' or 'none' after roles, got {}", self.got())));
            }
        } else if self.accept_kw("binds") {
            sub.binds = Some(self.ident()?);
        } else if self.accept_kw("transient") {
            sub.transient = true;
            sub.transient_set = self.accept_kw("set");
        } else {
            return Err(self.err(format!("unexpected {} in subject {}", self.got(), quote(&sub.name))));
        }
        Ok(())
    }

    fn parse_subject_membership(&mut self, sub: &mut Subject) -> PResult<()> {
        self.expect_kw("membership")?;
        let table = self.ident()?;
        self.expect(Tok::LParen)?;
        let id_col = self.ident()?;
        self.expect(Tok::Comma)?;
        let flag_col = self.ident()?;
        self.expect(Tok::RParen)?;
        let mut m = Membership { table, id_col, flag_col, active_col: None, active_val: None };
        if self.accept_kw("active") {
            m.active_col = Some(self.ident()?);
            self.expect(Tok::Eq)?;
            m.active_val = non_empty(self.string()?);
        }
        sub.membership = Some(m);
        Ok(())
    }

    fn parse_object(&mut self) -> PResult<Object> {
        let mut o = Object { pos: self.pos(), ..Default::default() };
        self.advance();
        o.name = self.ident()?;
        self.expect(Tok::LBrace)?;
        self.expect_kw("table")?;
        o.table = self.ident()?;
        if self.accept_kw("pk") {
            if self.peek() == Tok::LParen {
                self.advance();
                o.pk_cols.extend(self.ident_list()?);
                self.expect(Tok::RParen)?;
            } else {
                o.pk = Some(self.ident()?);
            }
        }
        if self.accept_kw("level") {
            o.level = Some(self.ident()?);
        }
        self.expect_kw("scoped")?;
        let LevelChain { chain, wildcards, verbs_by_level: verbs } = self.parse_level_chain()?;
        o.scoped = chain;
        o.scope_wildcards = wildcards;
        o.scope_wildcard_verbs = verbs;
        self.parse_object_body(&mut o)?;
        self.expect(Tok::RBrace)?;
        Ok(o)
    }

    fn parse_object_body(&mut self, o: &mut Object) -> PResult<()> {
        while self.peek() != Tok::RBrace && self.peek() != Tok::Eof {
            self.parse_object_clause(o)?;
        }
        Ok(())
    }

    fn parse_object_clause(&mut self, o: &mut Object) -> PResult<()> {
        if self.is_kw("relation") {
            let r = self.parse_relation()?;
            o.relations.push(r);
        } else if self.is_kw("permission") {
            let pm = self.parse_object_perm()?;
            o.perms.push(pm);
        } else if self.is_kw("require") {
            let rq = self.parse_object_require()?;
            o.requires.push(rq);
        } else if self.is_kw("gate") {
            let g = self.parse_gate()?;
            o.gates.push(g);
        } else if self.is_kw("field") {
            let f = self.parse_field_rule(o)?;
            o.fields.push(f);
        } else if self.is_kw("export") {
            self.parse_permission_export(o)?;
        } else if self.is_kw("reach") {
            self.parse_grant_use(o)?;
        } else if self.is_kw("admit") {
            self.parse_admit(o)?;
        } else if self.is_kw("use") {
            self.advance();
            if o.use_template.is_some() {
                return Err(self.err(format!("object {} declares `use` more than once", quote(&o.name))));
            }
            o.use_template = Some(self.ident()?);
        } else if self.is_kw("omit") {
            self.advance();
            o.omit.push(self.ident()?);
        } else if self.is_kw("track") {
            self.parse_track(o)?;
        } else if self.is_kw("fields") {
            self.parse_fields_decl(o)?;
        } else {
            return Err(self.err(format!("unexpected {} in object {}", self.got(), quote(&o.name))));
        }
        Ok(())
    }

    fn parse_track(&mut self, o: &mut Object) -> PResult<()> {
        self.advance();
        let what = self.ident()?;
        match what.as_str() {
            "owner" => o.track_owner = true,
            "visibility" => o.track_visibility = true,
            _ => {
                return Err(self.err(format!("object {}: `track` expects `owner` or `visibility`, got {}", quote(&o.name), quote(&what))));
            }
        }
        Ok(())
    }

    fn parse_gate(&mut self) -> PResult<Gate> {
        let pos = self.pos();
        self.advance();
        let verb = self.ident()?;
        self.expect_kw("via")?;
        let relation = self.ident()?;
        self.expect(Tok::Arrow)?;
        let perm = self.ident()?;
        Ok(Gate { verb, relation, perm, pos })
    }

    fn parse_fields_decl(&mut self, o: &mut Object) -> PResult<()> {
        self.advance();
        if !o.field_principals.is_empty() {
            return Err(self.err(format!("object {} declares `fields` more than once", quote(&o.name))));
        }
        self.expect(Tok::LBrace)?;
        while self.peek() != Tok::RBrace && self.peek() != Tok::Eof {
            o.field_principals.push(self.ident()?);
        }
        self.expect(Tok::RBrace)?;
        if o.field_principals.is_empty() {
            return Err(self.err(format!("object {}: `fields {{ ... }}` declares no principals", quote(&o.name))));
        }
        Ok(())
    }

    fn parse_field_rule(&mut self, o: &Object) -> PResult<FieldRule> {
        let mut f = FieldRule { pos: self.pos(), ..Default::default() };
        self.advance();
        f.name = self.ident()?;
        self.expect(Tok::LBrace)?;
        while self.peek() != Tok::RBrace && self.peek() != Tok::Eof {
            if self.is_kw("read") {
                self.advance();
                self.expect(Tok::Eq)?;
                f.read = self.parse_token_union()?;
            } else if self.is_kw("write") {
                self.advance();
                self.expect(Tok::Eq)?;
                f.write = self.parse_token_union()?;
            } else if self.is_kw("column") {
                self.advance();
                f.column = Some(self.ident()?);
            } else {
                return Err(self.err(format!(
                    "unexpected {} in field {} of object {} (expected read, write, or column)",
                    self.got(),
                    quote(&f.name),
                    quote(&o.name)
                )));
            }
        }
        self.expect(Tok::RBrace)?;
        Ok(f)
    }

    fn parse_token_union(&mut self) -> PResult<Vec<String>> {
        let mut toks = vec![self.ident()?];
        while self.peek() == Tok::Plus {
            self.advance();
            toks.push(self.ident()?);
        }
        Ok(toks)
    }

    fn parse_template(&mut self) -> PResult<Template> {
        let pos = self.pos();
        self.advance();
        let name = self.ident()?;
        self.expect(Tok::LBrace)?;
        let mut perms = Vec::new();
        while self.peek() != Tok::RBrace && self.peek() != Tok::Eof {
            if !self.is_kw("permission") {
                return Err(self.err(format!("template {}: only permission lines are allowed, got {}", quote(&name), self.got())));
            }
            perms.push(self.parse_object_perm()?);
        }
        self.expect(Tok::RBrace)?;
        Ok(Template { name, perms, pos })
    }

    fn parse_level_chain(&mut self) -> PResult<LevelChain> {
        let mut chain = Vec::new();
        let mut wildcards = Vec::new();
        let mut verbs_by_level = BTreeMap::new();
        loop {
            let nm = self.ident()?;
            chain.push(nm.clone());
            let wildcard = self.accept_kw("wildcard");
            if wildcard {
                wildcards.push(nm.clone());
            }
            if wildcard && self.accept_kw("confers") {
                verbs_by_level.insert(nm, self.ident_list()?);
            }
            if self.peek() != Tok::Gt {
                return Ok(LevelChain { chain, wildcards, verbs_by_level });
            }
            self.advance();
        }
    }

    fn parse_relation(&mut self) -> PResult<Relation> {
        let pos = self.pos();
        self.advance();
        let name = self.ident()?;
        self.expect(Tok::Colon)?;
        let mut types = vec![self.ident()?];
        while self.peek() == Tok::Pipe {
            self.advance();
            types.push(self.ident()?);
        }
        self.expect_kw("via")?;
        let repr = self.parse_repr()?;
        let mut kind = None;
        if self.accept_kw("kind") {
            if self.accept_kw("composition") {
                kind = Some(RelationKind::Composition);
            } else if self.accept_kw("association") {
                kind = Some(RelationKind::Association);
            } else {
                return Err(self.err(format!("expected 'composition' or 'association' after kind, got {}", self.got())));
            }
        }
        Ok(Relation { name, types, repr, kind, pos })
    }

    fn parse_table_cols(&mut self) -> PResult<(String, Vec<String>)> {
        let tbl = self.ident()?;
        self.expect(Tok::LParen)?;
        let cols = self.ident_list()?;
        self.expect(Tok::RParen)?;
        Ok((tbl, cols))
    }

    fn parse_repr(&mut self) -> PResult<Repr> {
        if self.accept_kw("edge") {
            let (table, cols) = self.parse_table_cols()?;
            if cols.len() < 2 || cols.len() > 3 {
                return Err(self.err(format!("via edge needs 2 or 3 columns, got {}", cols.len())));
            }
            return Ok(Repr::Edge(ViaEdge { table, cols }));
        }
        if self.accept_kw("role") {
            return Ok(Repr::Role);
        }
        if self.accept_kw("composition") {
            return self.parse_repr_composition();
        }
        if self.accept_kw("closure") {
            return self.parse_repr_closure();
        }
        if self.accept_kw("group") {
            return self.parse_repr_group();
        }
        if self.accept_kw("object") {
            return self.parse_repr_object();
        }
        if self.accept_kw("memberin") {
            return self.parse_repr_member_in();
        }
        if self.accept_kw("grant") {
            return self.parse_repr_grant();
        }
        self.parse_repr_column()
    }

    fn parse_where(&mut self) -> PResult<Option<(String, String)>> {
        if !self.accept_kw("where") {
            return Ok(None);
        }
        let col = self.ident()?;
        self.expect(Tok::Eq)?;
        let val = self.string()?;
        Ok(Some((col, val)))
    }

    fn parse_repr_composition(&mut self) -> PResult<Repr> {
        let (table, cols) = self.parse_table_cols()?;
        if cols.len() != 2 {
            return Err(self.err(format!("via composition needs 2 columns (child, parent), got {}", cols.len())));
        }
        let mut vc = ViaComposition { table, child_col: cols[0].clone(), parent_col: cols[1].clone(), ..Default::default() };
        if let Some((col, val)) = self.parse_where()? {
            vc.kind_col = Some(col);
            vc.kind_val = non_empty(val);
        }
        Ok(Repr::Composition(vc))
    }

    fn parse_repr_closure(&mut self) -> PResult<Repr> {
        let (closure, clo_cols) = self.parse_table_cols()?;
        if clo_cols.len() != 2 {
            return Err(self.err(format!("via closure needs a closure table with 2 columns (ancestor, descendant), got {}", clo_cols.len())));
        }
        let mut base = None;
        let mut base_cols = vec![String::new(), String::new()];
        if self.accept_kw("base") {
            let (b, cols) = self.parse_table_cols()?;
            if cols.len() != 2 {
                return Err(self.err(format!("via closure base needs 2 columns (id, parent), got {}", cols.len())));
            }
            base = Some(b);
            base_cols = cols;
        }
        self.expect_kw("on")?;
        let col = self.ident()?;
        let mut c = ViaClosure {
            closure,
            ancestor_col: clo_cols[0].clone(),
            descendant_col: clo_cols[1].clone(),
            base,
            base_id: non_empty(base_cols[0].clone()),
            base_parent: non_empty(base_cols[1].clone()),
            col,
            claim: None,
            missing: None,
        };
        if self.accept_kw("from") {
            self.expect_kw("claim")?;
            c.claim = Some(self.ident()?);
            self.expect_kw("missing")?;
            c.missing = Some(self.ident()?);
        }
        Ok(Repr::Closure(c))
    }

    fn parse_repr_group(&mut self) -> PResult<Repr> {
        let (closure, clo_cols) = self.parse_table_cols()?;
        if clo_cols.len() != 2 {
            return Err(self.err(format!("via group needs a closure table with 2 columns (group, member), got {}", clo_cols.len())));
        }
        self.expect_kw("edge")?;
        let (edge, edge_cols) = self.parse_table_cols()?;
        if edge_cols.len() != 2 {
            return Err(self.err(format!("via group edge needs 2 columns (member, group), got {}", edge_cols.len())));
        }
        self.expect_kw("on")?;
        let col = self.ident()?;
        let materialized = self.accept_kw("materialized");
        Ok(Repr::Group(ViaGroup {
            closure,
            group_col: clo_cols[0].clone(),
            member_col: clo_cols[1].clone(),
            edge,
            edge_member: edge_cols[0].clone(),
            edge_group: edge_cols[1].clone(),
            col,
            materialized,
        }))
    }

    fn parse_repr_object(&mut self) -> PResult<Repr> {
        let object = self.ident()?;
        self.expect(Tok::Arrow)?;
        let verb = self.ident()?;
        self.expect_kw("on")?;
        let col = self.ident()?;
        let mut v = ViaObject { object, verb, col, op: None };
        if self.accept_kw("for") {
            v.op = Some(self.ident()?);
        }
        Ok(Repr::Object(v))
    }

    fn parse_repr_member_in(&mut self) -> PResult<Repr> {
        let level = self.ident()?;
        self.expect(Tok::LParen)?;
        let principal = self.parse_arg_src()?;
        self.expect(Tok::Comma)?;
        let scope = self.parse_arg_src()?;
        self.expect(Tok::RParen)?;
        let reached_by = self.accept_kw("reachedby");
        let reach_member = reached_by && self.accept_kw("member");
        Ok(Repr::MemberIn(ViaMemberIn { level, principal, scope, reached_by, reach_member }))
    }

    fn parse_repr_grant(&mut self) -> PResult<Repr> {
        let (table, cols) = self.parse_table_cols()?;
        if cols.len() != 4 {
            return Err(self.err(format!("via grant needs 4 columns (record, kind, principal, access), got {}", cols.len())));
        }
        let mut vg = ViaGrant {
            table,
            record_col: cols[0].clone(),
            kind_col: cols[1].clone(),
            principal_col: cols[2].clone(),
            access_col: cols[3].clone(),
            ..Default::default()
        };
        if let Some((col, val)) = self.parse_where()? {
            vg.discrim_col = Some(col);
            vg.discrim_val = non_empty(val);
        }
        if self.accept_kw("group") {
            vg.group_kind_val = non_empty(self.string()?);
            self.expect_kw("closure")?;
            let (clo, clo_cols) = self.parse_table_cols()?;
            if clo_cols.len() != 2 {
                return Err(self.err(format!("grant group closure needs 2 columns (group, member), got {}", clo_cols.len())));
            }
            self.expect_kw("edge")?;
            let (edge, edge_cols) = self.parse_table_cols()?;
            if edge_cols.len() != 2 {
                return Err(self.err(format!("grant group edge needs 2 columns (member, group), got {}", edge_cols.len())));
            }
            vg.group_closure = Some(clo);
            vg.group_group_col = Some(clo_cols[0].clone());
            vg.group_member_col = Some(clo_cols[1].clone());
            vg.group_edge = Some(edge);
            vg.group_edge_member = Some(edge_cols[0].clone());
            vg.group_edge_group = Some(edge_cols[1].clone());
        }
        vg.tracked = self.accept_kw("tracked");
        vg.is_async = self.accept_kw("async");
        Ok(Repr::Grant(vg))
    }

    fn parse_repr_column(&mut self) -> PResult<Repr> {
        let column = self.ident()?;
        let mut vc = ViaColumn { column, discrim_col: None, discrim_val: None };
        if let Some((col, val)) = self.parse_where()? {
            vc.discrim_col = Some(col);
            vc.discrim_val = non_empty(val);
        }
        Ok(Repr::Column(vc))
    }

    fn parse_arg_src(&mut self) -> PResult<ArgSrc> {
        if self.peek() == Tok::At {
            self.advance();
            return Ok(ArgSrc::Claim(self.ident()?));
        }
        Ok(ArgSrc::Col(self.ident()?))
    }

    fn parse_object_perm(&mut self) -> PResult<Perm> {
        let pos = self.pos();
        self.advance();
        let verb = self.ident()?;
        self.expect(Tok::Eq)?;
        let tree = self.parse_perm_union()?;
        self.expect(Tok::At)?;
        let mut layers = vec![self.ident()?];
        while self.peek() == Tok::Comma {
            self.advance();
            layers.push(self.ident()?);
        }
        let mut pm = Perm { verb, tree, layers, maps: None, guard: None, self_check: None, predicate_only: false, blind: false, pos };
        if self.accept_kw("maps") {
            match self.peek() {
                Tok::Ident | Tok::PermKey => pm.maps = Some(self.advance().lit),
                _ => {
                    return Err(self.err(format!("expected a table-op or permission after maps, got {}", self.got())));
                }
            }
        }
        pm.blind = self.accept_kw("blind");
        if self.accept_kw("predicate") {
            pm.predicate_only = true;
        }
        if self.accept_kw("guard") {
            let gpos = self.pos();
            let col = self.ident()?;
            let op = match self.peek() {
                Tok::Eq => GuardOp::Eq,
                Tok::Ne => GuardOp::Ne,
                other => return Err(self.err(format!("guard operator must be = or <>, got {other}"))),
            };
            self.advance();
            let val = self.string()?;
            pm.guard = Some(Guard { col, op, val, pos: gpos });
        }
        if self.accept_kw("selfcheck") {
            pm.self_check = Some(self.ident()?);
        }
        Ok(pm)
    }

    fn parse_object_require(&mut self) -> PResult<Require> {
        let pos = self.pos();
        self.advance();
        let verb = self.ident()?;
        self.expect(Tok::Eq)?;
        let tree = self.parse_perm_union()?;
        Ok(Require { verb, tree, pos })
    }

    fn parse_perm_union(&mut self) -> PResult<PermNode> {
        let left = self.parse_perm_and()?;
        let mut kids = vec![left];
        while self.peek() == Tok::Plus || self.is_kw("or") {
            self.advance();
            kids.push(self.parse_perm_and()?);
        }
        if kids.len() == 1
            && let Some(only) = kids.pop()
        {
            return Ok(only);
        }
        Ok(PermNode::Or(kids))
    }

    fn parse_perm_and(&mut self) -> PResult<PermNode> {
        let left = self.parse_perm_unary()?;
        let mut kids = vec![left];
        while self.is_kw("and") {
            self.advance();
            kids.push(self.parse_perm_unary()?);
        }
        if kids.len() == 1
            && let Some(only) = kids.pop()
        {
            return Ok(only);
        }
        Ok(PermNode::And(kids))
    }

    fn parse_perm_unary(&mut self) -> PResult<PermNode> {
        if self.is_kw("not") {
            self.advance();
            let k = self.parse_perm_primary()?;
            return Ok(PermNode::Not(Box::new(k)));
        }
        self.parse_perm_primary()
    }

    fn parse_perm_primary(&mut self) -> PResult<PermNode> {
        if self.peek() == Tok::LParen {
            if self.depth == MAX_NESTING {
                return Err(self.err(format!("parentheses nest more than {MAX_NESTING} deep")));
            }
            self.advance();
            self.depth += 1;
            let n = self.parse_perm_union()?;
            self.depth -= 1;
            self.expect(Tok::RParen)?;
            return Ok(n);
        }
        Ok(PermNode::Leaf(self.parse_term()?))
    }

    fn parse_term(&mut self) -> PResult<Term> {
        let pos = self.pos();
        if self.peek() == Tok::At {
            self.advance();
            let b = self.ident()?;
            let builtin = if b == "row" { self.parse_term_row()? } else { self.parse_term_builtin(b)? };
            return Ok(Term { kind: TermKind::Builtin(builtin), pos });
        }
        if self.is_kw("mode") {
            self.advance();
            let col = self.ident()?;
            self.expect(Tok::Eq)?;
            let val = self.string()?;
            let mut scope = None;
            if self.accept_kw("for") {
                scope = Some(self.ident()?);
            }
            return Ok(Term { kind: TermKind::Mode { col, val, scope }, pos });
        }
        if self.is_kw("via") {
            self.advance();
            self.expect_kw("grant")?;
            let name = self.ident()?;
            return Ok(Term { kind: TermKind::Grant(name), pos });
        }
        let ident = match self.peek() {
            Tok::Ident | Tok::PermKey => self.advance().lit,
            _ => {
                return Err(self.err(format!("expected a relation, capability, or @builtin term, got {}", self.got())));
            }
        };
        let mut walk_verb = None;
        if self.peek() == Tok::Arrow {
            self.advance();
            walk_verb = Some(self.ident()?);
        }
        Ok(Term { kind: TermKind::Ref { ident, walk_verb }, pos })
    }

    fn parse_app_scope_excludes(&mut self) -> PResult<Vec<String>> {
        if self.peek() != Tok::LParen {
            return Ok(Vec::new());
        }
        self.advance();
        self.expect_kw("exclude")?;
        let rels = self.ident_list()?;
        self.expect(Tok::RParen)?;
        Ok(rels)
    }

    fn parse_term_builtin(&mut self, name: String) -> PResult<Builtin> {
        Ok(match name.as_str() {
            "session" => {
                let mut rel = None;
                if self.peek() == Tok::LParen {
                    rel = Some(self.paren_ident()?);
                }
                Builtin::Session(rel)
            }
            "app_scope" => Builtin::AppScope(self.parse_app_scope_excludes()?),
            "kind" => {
                self.expect(Tok::LParen)?;
                let val = self.string()?;
                self.expect(Tok::RParen)?;
                Builtin::Kind(val)
            }
            "claim" => {
                self.expect(Tok::LParen)?;
                let key = self.string()?;
                self.expect(Tok::Comma)?;
                let val = self.string()?;
                self.expect(Tok::RParen)?;
                Builtin::Claim { key, val }
            }
            "self" => Builtin::SelfCol(self.paren_ident()?),
            "within" => {
                self.expect(Tok::LParen)?;
                let level = self.ident()?;
                let nullable = self.accept_kw("nullable");
                self.expect(Tok::RParen)?;
                Builtin::Within { level, nullable }
            }
            "external" => {
                self.expect(Tok::LParen)?;
                let func = self.ident()?;
                let mut args = Vec::new();
                while self.peek() == Tok::Comma {
                    self.advance();
                    args.push(self.parse_external_arg()?);
                }
                self.expect(Tok::RParen)?;
                Builtin::External { func, args }
            }
            "holds" => {
                self.expect(Tok::LParen)?;
                let perm = match self.peek() {
                    Tok::PermKey | Tok::Str => self.advance().lit,
                    _ => {
                        return Err(self.err(format!("@holds needs a permission verb (`@holds(<domain>:<verb>)`), got {}", self.got())));
                    }
                };
                self.expect(Tok::RParen)?;
                Builtin::Holds(perm)
            }
            _ => Builtin::Other(name),
        })
    }

    fn parse_term_row(&mut self) -> PResult<Builtin> {
        self.expect(Tok::LParen)?;
        let col = self.ident()?;
        self.expect(Tok::Comma)?;
        let val = self.string()?;
        self.expect(Tok::RParen)?;
        Ok(Builtin::Row { col, val })
    }

    fn parse_external_arg(&mut self) -> PResult<ExternalArg> {
        match self.peek() {
            Tok::At => {
                self.advance();
                Ok(ExternalArg::Claim(self.ident()?))
            }
            Tok::Str => Ok(ExternalArg::Lit(self.advance().lit)),
            _ => Ok(ExternalArg::Col(self.ident()?)),
        }
    }

    fn paren_ident(&mut self) -> PResult<String> {
        self.expect(Tok::LParen)?;
        let id = self.ident()?;
        self.expect(Tok::RParen)?;
        Ok(id)
    }

    fn parse_procedures(&mut self) -> PResult<Procedures> {
        let pos = self.pos();
        self.advance();
        let emit_site = self.ident()?;
        self.expect(Tok::LBrace)?;
        let mut entries = Vec::new();
        while self.peek() == Tok::Proc {
            let proc_ = self.advance().lit;
            self.expect(Tok::Arrow)?;
            let perm = self.expect(Tok::PermKey)?;
            entries.push(ProcEntry { proc_, perm: perm.lit, pos: Pos { line: perm.line } });
        }
        self.expect(Tok::RBrace)?;
        Ok(Procedures { emit_site, entries, pos })
    }

    fn parse_ungoverned(&mut self) -> PResult<Ungoverned> {
        let pos = self.pos();
        self.advance();
        let emit_site = self.ident()?;
        self.expect(Tok::LBrace)?;
        let mut entries = Vec::new();
        while self.peek() == Tok::Proc {
            let proc_ = self.advance().lit;
            self.expect(Tok::Colon)?;
            let reason = self.expect(Tok::Str)?;
            entries.push(UngovEntry { proc_, reason: reason.lit, pos: Pos { line: reason.line } });
        }
        self.expect(Tok::RBrace)?;
        Ok(Ungoverned { emit_site, entries, pos })
    }

    fn parse_role_store(&mut self) -> PResult<RoleStore> {
        let mut rs = RoleStore { pos: self.pos(), ..Default::default() };
        self.advance();
        rs.name = self.ident()?;
        self.expect(Tok::LBrace)?;
        while self.peek() != Tok::RBrace && self.peek() != Tok::Eof {
            self.parse_role_store_clause(&mut rs)?;
        }
        self.expect(Tok::RBrace)?;
        Ok(rs)
    }

    fn parse_role_store_clause(&mut self, rs: &mut RoleStore) -> PResult<()> {
        if self.accept_kw("assignments") {
            rs.assignments = Some(self.ident()?);
        } else if self.accept_kw("kind") {
            rs.kind_col = Some(self.ident()?);
            self.expect(Tok::Eq)?;
            rs.kind_val = non_empty(self.string()?);
        } else if self.accept_kw("subject") {
            rs.subject_col = Some(self.ident()?);
        } else if self.accept_kw("scope") {
            while self.peek() == Tok::Ident && !role_store_keyword(&self.cur().lit) {
                rs.scope_cols.push(self.advance().lit);
            }
        } else if self.accept_kw("plane") {
            rs.plane = Some(self.ident()?);
        } else if self.accept_kw("rolejoin") {
            rs.role_col = Some(self.ident()?);
            rs.roles_table = Some(self.ident()?);
            rs.roles_id = Some(self.ident()?);
            rs.key_col = Some(self.ident()?);
        } else if self.accept_kw("revoked") {
            rs.revoked_col = Some(self.ident()?);
            if self.accept_kw("by") {
                rs.revoked_by_col = Some(self.ident()?);
            }
        } else if self.accept_kw("permissions") {
            rs.perms_col = Some(self.ident()?);
        } else if self.accept_kw("pk") {
            rs.id_col = Some(self.ident()?);
        } else if self.accept_kw("granted") {
            rs.granted_at_col = Some(self.ident()?);
            if self.accept_kw("by") {
                rs.granted_by_col = Some(self.ident()?);
            }
        } else if self.accept_kw("column") {
            rs.extra_cols.push(self.ident()?);
        } else {
            return Err(self.err(format!("unexpected {} in rolestore", self.got())));
        }
        Ok(())
    }

    fn parse_claims(&mut self) -> PResult<ClaimsAccessor> {
        let pos = self.pos();
        self.advance();
        self.expect_kw("via")?;
        let setting = self.string()?;
        let mut c = ClaimsAccessor { setting, cast: "json".to_string(), role: None, pos };
        if self.peek() == Tok::Ident && !self.is_kw("role") {
            c.cast = self.advance().lit;
        }
        if self.accept_kw("role") {
            c.role = Some(self.ident()?);
        }
        Ok(c)
    }

    fn parse_grant(&mut self) -> PResult<Grant> {
        let mut g = Grant { pos: self.pos(), ..Default::default() };
        self.advance();
        g.name = self.ident()?;
        self.expect_kw("at")?;
        g.level = self.ident()?;
        self.expect_kw("via")?;
        if self.accept_kw("claim") {
            g.claim_key = Some(self.ident()?);
            self.expect(Tok::Eq)?;
            g.claim_value = non_empty(self.string()?);
            self.parse_grant_options(&mut g)?;
            return Ok(g);
        }
        self.expect_kw("edge")?;
        g.table = Some(self.ident()?);
        self.expect(Tok::LParen)?;
        g.grantee_col = Some(self.ident()?);
        self.expect(Tok::Comma)?;
        g.level_col = Some(self.ident()?);
        self.expect(Tok::RParen)?;
        self.parse_grant_options(&mut g)?;
        Ok(g)
    }

    fn ident_list(&mut self) -> PResult<Vec<String>> {
        let mut ops = Vec::new();
        loop {
            ops.push(self.ident()?);
            if self.peek() != Tok::Comma {
                return Ok(ops);
            }
            self.advance();
        }
    }

    fn parse_grant_options(&mut self, g: &mut Grant) -> PResult<()> {
        loop {
            if self.accept_kw("named") {
                g.named = Some(self.ident()?);
                continue;
            }
            if self.accept_kw("scope") {
                let level = self.ident()?;
                self.expect_kw("on")?;
                let column = self.ident()?;
                self.expect_kw("missing")?;
                let missing = self.ident()?;
                g.scopes.push(GrantScope { level, column, missing });
                continue;
            }
            if self.accept_kw("confers") {
                let verbs = self.ident_list()?;
                g.verbs.extend(verbs);
                continue;
            }
            if self.accept_kw("column") {
                g.extra_cols.push(self.ident()?);
                continue;
            }
            let (dst, need_by) = if self.accept_kw("active") {
                (&mut g.active_col, false)
            } else if self.accept_kw("expires") {
                (&mut g.expires_col, false)
            } else if self.accept_kw("pk") {
                (&mut g.id_col, false)
            } else if self.accept_kw("created") {
                (&mut g.created_at_col, false)
            } else if self.accept_kw("granted") {
                (&mut g.granted_by_col, true)
            } else if self.accept_kw("revoked") {
                (&mut g.revoked_by_col, true)
            } else {
                return Ok(());
            };
            if need_by {
                self.expect_kw("by")?;
            }
            *dst = Some(self.ident()?);
        }
    }

    fn parse_field_scopes(&mut self) -> PResult<FieldScopes> {
        let pos = self.pos();
        self.advance();
        let site = self.ident()?;
        self.expect(Tok::LBrace)?;
        let mut entries = Vec::new();
        while self.peek() == Tok::Ident {
            let field = self.advance().lit;
            self.expect(Tok::Arrow)?;
            let scope = self.expect(Tok::PermKey)?;
            entries.push(FieldScopeEntry { field, scope: scope.lit, pos: Pos { line: scope.line } });
        }
        self.expect(Tok::RBrace)?;
        Ok(FieldScopes { site, entries, pos })
    }

    fn parse_grant_use(&mut self, o: &mut Object) -> PResult<()> {
        let mut u = GrantUse { pos: self.pos(), ..Default::default() };
        self.advance();
        u.grant = self.ident()?;
        if self.accept_kw("unscoped") {
            u.unscoped = true;
        } else if self.accept_kw("bound") {
            u.bound = Some(self.ident()?);
        } else if self.accept_kw("via") {
            u.via = Some(self.ident()?);
        } else {
            return Err(self.err(format!("reach {} needs `unscoped`, `bound <level>` or `via <grant>`", u.grant)));
        }
        if self.accept_kw("for") {
            u.ops = self.ident_list()?;
        }
        o.reach_uses.push(u);
        Ok(())
    }

    fn parse_admit(&mut self, o: &mut Object) -> PResult<()> {
        let pos = self.pos();
        self.advance();
        let ops = self.ident_list()?;
        self.expect(Tok::Eq)?;
        let tree = self.parse_perm_union()?;
        o.admits.push(Admit { ops, tree, pos });
        Ok(())
    }

    fn parse_permission_export(&mut self, o: &mut Object) -> PResult<()> {
        let pos = self.pos();
        self.advance();
        let verb = self.ident()?;
        self.expect_kw("as")?;
        let name = self.ident()?;
        self.expect(Tok::LParen)?;
        let mut params = Vec::new();
        loop {
            let column = self.ident()?;
            let ty = self.ident()?;
            let mut pname = None;
            if self.accept_kw("as") {
                pname = Some(self.ident()?);
            }
            params.push(ExportParameter { column, ty, name: pname });
            if self.peek() != Tok::Comma {
                break;
            }
            self.advance();
        }
        self.expect(Tok::RParen)?;
        o.exports.push(PermissionExport { verb, name, params, pos });
        Ok(())
    }
}

fn role_store_keyword(s: &str) -> bool {
    matches!(s, "assignments" | "kind" | "subject" | "scope" | "plane" | "rolejoin" | "revoked" | "permissions" | "pk" | "granted" | "column")
}

fn expand_templates(s: &mut Spec) -> Result<(), Error> {
    let mut by_name: HashMap<String, usize> = HashMap::new();
    for (i, t) in s.templates.iter().enumerate() {
        if by_name.contains_key(&t.name) {
            return Err(Error::new(format!("duplicate template {}", quote(&t.name))));
        }
        by_name.insert(t.name.clone(), i);
    }
    for o in &mut s.objects {
        let Some(use_name) = o.use_template.clone() else {
            if !o.omit.is_empty() {
                return Err(Error::new(format!("object {} declares `omit` without `use`", quote(&o.name))));
            }
            continue;
        };
        let Some(&ti) = by_name.get(&use_name) else {
            return Err(Error::new(format!("object {} uses unknown template {}", quote(&o.name), quote(&use_name))));
        };
        let t = &s.templates[ti];
        let tmpl_verbs: HashSet<&str> = t.perms.iter().map(|p| p.verb.as_str()).collect();
        for v in &o.omit {
            if !tmpl_verbs.contains(v.as_str()) {
                return Err(Error::new(format!("object {} omits verb {} which template {} does not define", quote(&o.name), quote(v), quote(&use_name))));
            }
        }
        let omit: HashSet<&str> = o.omit.iter().map(String::as_str).collect();
        let own: HashSet<&str> = o.perms.iter().map(|p| p.verb.as_str()).collect();
        let mut merged: Vec<Perm> = t.perms.iter().filter(|pm| !omit.contains(pm.verb.as_str()) && !own.contains(pm.verb.as_str())).cloned().collect();
        merged.append(&mut o.perms);
        o.perms = merged;
    }
    Ok(())
}
