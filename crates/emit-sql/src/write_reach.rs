use crate::Sql;
use crate::rls::{Virtual, leaf};
use demesne_model::SpecExt;
use demesne_syntax::{Admit, Finding, Object, Perm, PermNode, Repr, Spec, Term, ViaObject};
use std::collections::BTreeSet;

const DNF_LIMIT: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Atom(String),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
}

type Conj = BTreeSet<(bool, String)>;
type Literals = Vec<(bool, Term)>;

fn depths(s: &[u8]) -> Vec<Option<i32>> {
    let (mut depth, mut quoted) = (0i32, false);
    s.iter()
        .map(|&c| {
            if quoted || c == b'\'' {
                quoted ^= c == b'\'';
                return None;
            }
            let here = depth;
            depth += i32::from(c == b'(') - i32::from(c == b')');
            Some(here)
        })
        .collect()
}

fn wraps_whole(s: &str) -> bool {
    let b = s.as_bytes();
    if b.first() != Some(&b'(') {
        return false;
    }
    let d = depths(b);
    (1..b.len()).find(|&i| b[i] == b')' && d[i] == Some(1)) == Some(b.len() - 1)
}

fn split_top<'a>(s: &'a str, kw: &str) -> Vec<&'a str> {
    let b = s.as_bytes();
    let d = depths(b);
    let mut parts = Vec::new();
    let (mut start, mut i) = (0usize, 0usize);
    while i < b.len() {
        if d[i] == Some(0) && b[i..].starts_with(kw.as_bytes()) {
            parts.push(&s[start..i]);
            i += kw.len();
            start = i;
        } else {
            i += 1;
        }
    }
    parts.push(&s[start..]);
    parts
}

fn parse(s: &str) -> Expr {
    let s = s.trim();
    let ors = split_top(s, " OR ");
    if ors.len() > 1 {
        return Expr::Or(ors.into_iter().map(parse).collect());
    }
    let ands = split_top(s, " AND ");
    if ands.len() > 1 {
        return Expr::And(ands.into_iter().map(parse).collect());
    }
    if let Some(inner) = s.strip_suffix(" IS NOT TRUE")
        && wraps_whole(inner)
    {
        return Expr::Not(Box::new(parse(&inner[1..inner.len() - 1])));
    }
    if wraps_whole(s) {
        return parse(&s[1..s.len() - 1]);
    }
    if let [x, y] = split_top(s, " IS NOT DISTINCT FROM ")[..] {
        let (x, y) = (x.trim(), y.trim());
        return Expr::Or(vec![Expr::Atom(format!("{x} = {y}")), Expr::And(vec![Expr::Atom(format!("{x} IS NULL")), Expr::Atom(format!("{y} IS NULL"))])]);
    }
    Expr::Atom(s.to_string())
}

fn product<C>(a: &[C], b: &[C], join: impl Fn(&C, &C) -> C) -> Option<Vec<C>> {
    let out: Vec<C> = a.iter().flat_map(|x| b.iter().map(|y| join(x, y))).take(DNF_LIMIT + 1).collect();
    (out.len() <= DNF_LIMIT).then_some(out)
}

fn dnf(e: &Expr, neg: bool) -> Option<Vec<Conj>> {
    let out = match (e, neg) {
        (Expr::Atom(a), _) => vec![BTreeSet::from([(neg, a.clone())])],
        (Expr::Not(k), _) => dnf(k, !neg)?,
        (Expr::Or(kids), false) | (Expr::And(kids), true) => kids.iter().map(|k| dnf(k, neg)).collect::<Option<Vec<_>>>()?.concat(),
        (Expr::And(kids), false) | (Expr::Or(kids), true) => {
            let mut out: Vec<Conj> = vec![BTreeSet::new()];
            for k in kids {
                out = product(&out, &dnf(k, neg)?, |x, y| x.union(y).cloned().collect())?;
            }
            out
        }
    };
    (out.len() <= DNF_LIMIT).then_some(out)
}

fn spec_dnf(n: &PermNode, neg: bool) -> Option<Vec<Literals>> {
    let out = match (n, neg) {
        (PermNode::Leaf(t), _) => vec![vec![(neg, t.clone())]],
        (PermNode::Not(k), _) => spec_dnf(k, !neg)?,
        (PermNode::Or(kids), false) | (PermNode::And(kids), true) => kids.iter().map(|k| spec_dnf(k, neg)).collect::<Option<Vec<_>>>()?.concat(),
        (PermNode::And(kids), false) | (PermNode::Or(kids), true) => {
            let mut out: Vec<Literals> = vec![Vec::new()];
            for k in kids {
                out = product(&out, &spec_dnf(k, neg)?, |x, y| [x.as_slice(), y.as_slice()].concat())?;
            }
            out
        }
    };
    (out.len() <= DNF_LIMIT).then_some(out)
}

fn split_last_literal(a: &str) -> Option<(&str, &str, &str)> {
    let end = a.rfind('\'')?;
    let start = a[..end].rfind('\'')?;
    Some((&a[..start], &a[start + 1..end], &a[end + 1..]))
}

fn perm_implies(s: &Spec, held: &str, needed: &str) -> bool {
    held.contains(':')
        && needed.contains(':')
        && s.vocabs
            .iter()
            .filter(|v| v.permissions.iter().any(|p| p == held))
            .any(|v| demesne_model::vocab::to_runtime(v).implied_permissions(held).is_ok_and(|implied| implied.iter().any(|p| p == needed)))
}

struct Implications<'a> {
    s: &'a Spec,
    pairs: BTreeSet<(String, String)>,
}

impl Implications<'_> {
    fn atom(&self, have: &str, want: &str) -> bool {
        if have == want || want == "true" || self.pairs.contains(&(have.to_string(), want.to_string())) {
            return true;
        }
        match (split_last_literal(have), split_last_literal(want)) {
            (Some((hp, hl, hs)), Some((wp, wl, ws))) => hp == wp && hs == ws && perm_implies(self.s, hl, wl),
            _ => false,
        }
    }

    fn conj(&self, have: &Conj, want: &Conj) -> bool {
        want.iter().all(|(neg, w)| if *neg { have.contains(&(true, w.clone())) } else { w == "true" || have.iter().any(|(hn, h)| !hn && self.atom(h, w)) })
    }
}

fn composition_implications(schema: &str, obj: &Object, rel: &str) -> Vec<(String, String)> {
    let call = |access: &str| format!("{schema}.{}_composition_{rel}({}.{}, '{access}')", obj.name, obj.table, obj.pk());
    [("update", "write"), ("delete", "delete")]
        .into_iter()
        .filter(|(op, _)| obj.perms.iter().find(|p| p.has_layer("rls") && p.maps() == *op).is_some_and(|p| !p.blind))
        .map(|(_, access)| (call(access), call("read")))
        .collect()
}

fn borrow_implications(s: &Spec, vo: &ViaObject) -> Vec<(String, String)> {
    let Some(other) = s.object_by_name(&vo.object).filter(|_| vo.op.is_none()) else { return Vec::new() };
    let Some(borrowed) = other.perms.iter().find(|p| p.verb == vo.verb) else { return Vec::new() };
    let call = |f: &str| format!("{}.{}_can_{f}({})", s.definer_schema(), vo.object, vo.col);
    if borrowed.maps.is_none() {
        return ["select", "insert", "update", "delete"].iter().map(|op| (call(&vo.verb), call(&format!("{}_for_{op}", vo.verb)))).collect();
    }
    match select_perm(other) {
        Some(sel) if write_op(borrowed).is_some() && !borrowed.blind => vec![(call(&vo.verb), call(&sel.verb))],
        _ => Vec::new(),
    }
}

fn implications(s: &Spec) -> Implications<'_> {
    let mut pairs = BTreeSet::new();
    for (obj, r) in s.relations() {
        match &r.repr {
            Repr::Composition(_) => pairs.extend(composition_implications(s.definer_schema(), obj, &r.name)),
            Repr::Object(vo) => pairs.extend(borrow_implications(s, vo)),
            _ => {}
        }
    }
    Implications { s, pairs }
}

fn disjunct_node(d: &[(bool, Term)]) -> PermNode {
    let mut lits: Vec<PermNode> =
        d.iter().map(|(neg, t)| if *neg { PermNode::Not(Box::new(PermNode::Leaf(t.clone()))) } else { PermNode::Leaf(t.clone()) }).collect();
    if lits.len() == 1 { lits.remove(0) } else { PermNode::And(lits) }
}

fn write_op(pm: &Perm) -> Option<&'static str> {
    if !pm.has_layer("rls") || pm.predicate_only {
        return None;
    }
    match pm.maps.as_deref() {
        Some("update") => Some("update"),
        Some("delete") => Some("delete"),
        _ => None,
    }
}

fn admit_write_ops(o: &Object) -> Vec<(&Admit, &'static str)> {
    o.admits
        .iter()
        .flat_map(|a| {
            a.ops.iter().filter_map(move |op| match op.as_str() {
                "update" => Some((a, "update")),
                "delete" => Some((a, "delete")),
                _ => None,
            })
        })
        .collect()
}

fn select_perm(o: &Object) -> Option<&Perm> {
    o.perms.iter().find(|p| p.has_layer("rls") && !p.predicate_only && p.maps.as_deref() == Some("select"))
}

fn with_requirement(conjs: &[Conj], requirement: &[Conj]) -> Option<Vec<Conj>> {
    product(conjs, requirement, |x, y| x.union(y).cloned().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escape {
    Permission,
    Requirement,
}

struct Reach<'a> {
    line: usize,
    obj: &'a Object,
    verb: &'a str,
    op: &'a str,
    what: String,
    sel: Option<&'a Perm>,
    escape: Escape,
    blind: bool,
}

impl Reach<'_> {
    fn finding(&self) -> Finding {
        let Reach { line, obj, verb, op, what, sel, escape, blind } = self;
        let (why, remedy) = match (escape, sel) {
            (Escape::Permission, Some(p)) => {
                (format!("the select permission {}.{} does not reach", obj.name, p.verb), "reach them in the select permission".to_string())
            }
            (Escape::Permission, None) => (format!("no select permission on {} reaches", obj.name), "add a select permission that reaches them".to_string()),
            (Escape::Requirement, p) => {
                let sel_verb = p.map_or("", |p| p.verb.as_str());
                (
                    format!("that {}'s `require {sel_verb}` refuses", obj.name),
                    format!("make `require {verb}` imply `require {sel_verb}`, or widen `require {sel_verb}`"),
                )
            }
        };
        let tail = if *blind {
            "kept as a warning because the permission is marked `blind`".to_string()
        } else {
            format!("{remedy}, or mark the permission `blind` if it is meant to {op} without reading")
        };
        let statement = if *op == "update" { "an UPDATE" } else { "a DELETE" };
        let admits = if what.starts_with("its terms ") { "admit" } else { "admits" };
        Finding::at(
            *line,
            format!(
                "permission {}.{verb} maps {op}, and {what} {admits} callers {why}; Postgres applies {statement} only to rows the SELECT policy shows, so for those callers it changes nothing and reports success: {tail}",
                obj.name
            ),
        )
    }
}

#[derive(Debug, Default)]
pub(crate) struct WriteReach {
    pub(crate) errors: Vec<Finding>,
    pub(crate) warnings: Vec<Finding>,
}

impl WriteReach {
    fn report(&mut self, f: &Reach<'_>) {
        if f.blind {
            self.warnings.push(f.finding());
        } else {
            self.errors.push(f.finding());
        }
    }
}

struct ObjectReach<'a> {
    imp: &'a Implications<'a>,
    obj: &'a Object,
    sel: Option<&'a Perm>,
    sel_permission: Vec<Conj>,
    sel_requirement: Vec<Conj>,
    requirements: [(&'static str, Vec<Conj>); 2],
    writes: Vec<(&'a Perm, &'static str)>,
    admits: Vec<(&'a Admit, &'static str)>,
}

impl<'a> ObjectReach<'a> {
    fn escape(&self, conjs: &[Conj]) -> Option<Escape> {
        let within = |part: &[Conj]| conjs.iter().all(|c| part.iter().any(|e| self.imp.conj(c, e)));
        if !within(&self.sel_permission) {
            Some(Escape::Permission)
        } else if !within(&self.sel_requirement) {
            Some(Escape::Requirement)
        } else {
            None
        }
    }

    fn requirement(&self, op: &str) -> &[Conj] {
        self.requirements.iter().find(|(o, _)| *o == op).map_or(&[], |(_, r)| r.as_slice())
    }

    fn writes_op(&self, op: &str) -> bool {
        self.writes.iter().any(|(_, w)| *w == op) || self.admits.iter().any(|(_, w)| *w == op)
    }

    fn finding(&self, line: usize, verb: &'a str, op: &'a str, what: String, escape: Escape, blind: bool) -> Reach<'a> {
        Reach { line, obj: self.obj, verb, op, what, sel: self.sel, escape, blind }
    }
}

struct WriteTerm<'a> {
    pm: &'a Perm,
    structural: BTreeSet<String>,
    requirement: Vec<Conj>,
}

fn quoted_terms(trees: &[PermNode]) -> String {
    let terms: Vec<String> = trees.iter().map(|t| format!("`{}`", PermNode::display(t))).collect();
    if let [one] = terms.as_slice() { format!("its term {one}") } else { format!("its terms {}", terms.join(", ")) }
}

impl Sql<'_> {
    fn requirement_dnf(&self, o: &Object, pm: Option<&Perm>) -> Option<Vec<Conj>> {
        let Some(pm) = pm else { return Some(vec![BTreeSet::new()]) };
        let req = self.perm_require_sql(o, pm, self.s.owner_subject(leaf(o))).ok()?;
        if req.is_empty() {
            return Some(vec![BTreeSet::new()]);
        }
        dnf(&parse(&req), false)
    }

    fn op_requirement(&self, o: &Object, op: &str) -> Option<Vec<Conj>> {
        self.requirement_dnf(o, o.perms.iter().find(|p| p.has_layer("rls") && p.maps() == op))
    }

    fn select_permission_dnf(&self, o: &Object, sel: Option<&Perm>, virt: &Virtual) -> Option<Vec<Conj>> {
        let Some(sel) = sel else { return Some(Vec::new()) };
        let pred = self.admission_predicate(o, sel, self.s.owner_subject(leaf(o)), virt).ok()?;
        dnf(&parse(&pred), false)
    }

    fn blind_misuse(&self) -> Vec<Finding> {
        self.s
            .objects
            .iter()
            .flat_map(|o| o.perms.iter().filter(|p| p.blind && write_op(p).is_none()).map(move |pm| (o, pm)))
            .map(|(o, pm)| {
                Finding::at(
                    pm.pos.line,
                    format!("permission {}.{} is marked `blind` but does not map update or delete under @rls; only a write can be blind", o.name, pm.verb),
                )
            })
            .collect()
    }

    fn object_reach<'a>(&self, imp: &'a Implications<'a>, o: &'a Object, virt: &Virtual) -> Option<ObjectReach<'a>> {
        let writes: Vec<(&Perm, &'static str)> = o.perms.iter().filter_map(|p| write_op(p).map(|op| (p, op))).collect();
        let admits = admit_write_ops(o);
        if writes.is_empty() && admits.is_empty() {
            return None;
        }
        let sel = select_perm(o);
        Some(ObjectReach {
            imp,
            obj: o,
            sel,
            sel_permission: self.select_permission_dnf(o, sel, virt)?,
            sel_requirement: self.requirement_dnf(o, sel)?,
            requirements: [("update", self.op_requirement(o, "update")?), ("delete", self.op_requirement(o, "delete")?)],
            writes,
            admits,
        })
    }

    pub(crate) fn write_reach(&self) -> WriteReach {
        let mut out = WriteReach { errors: self.blind_misuse(), warnings: Vec::new() };
        let Ok(virt) = self.virtual_levels() else { return out };
        let imp = implications(self.s);
        for o in &self.s.objects {
            let Some(r) = self.object_reach(&imp, o, &virt) else { continue };
            self.check_structural_reach(&r, &virt, &mut out);
            self.check_write_terms(&r, &virt, &mut out);
            self.check_admit_arms(&r, &virt, &mut out);
        }
        out
    }

    fn check_structural_reach(&self, r: &ObjectReach<'_>, virt: &Virtual, out: &mut WriteReach) {
        for op in ["update", "delete"].into_iter().filter(|op| r.writes_op(op)) {
            let structural = self.structural_branches(r.obj, virt, op);
            if structural.is_empty() {
                continue;
            }
            let Some(conjs) = dnf(&parse(&structural.join(" OR ")), false).and_then(|c| with_requirement(&c, r.requirement(op))) else { continue };
            let Some(escape) = r.escape(&conjs) else { continue };
            let write = r.writes.iter().find(|(_, w)| *w == op);
            let line = write.map_or(r.obj.pos.line, |(p, _)| p.pos.line);
            let verb = write.map_or("admit", |(p, _)| p.verb.as_str());
            let blind = write.is_some_and(|(p, _)| p.blind);
            out.report(&r.finding(line, verb, op, "a subject's own reach on this object".to_string(), escape, blind));
        }
    }

    fn check_write_terms(&self, r: &ObjectReach<'_>, virt: &Virtual, out: &mut WriteReach) {
        for &(pm, op) in &r.writes {
            let w = WriteTerm { pm, structural: self.structural_atoms(r.obj, virt, op), requirement: r.requirement(op).to_vec() };
            let disjuncts = spec_dnf(&pm.tree, false).unwrap_or_default();
            let escapes: Vec<(PermNode, Escape)> =
                disjuncts.iter().filter(|d| d.iter().any(|(neg, _)| !neg)).filter_map(|d| self.disjunct_escape(r, &w, d, virt)).collect();
            for (tree, _) in escapes.iter().filter(|(_, e)| *e == Escape::Permission) {
                let what = quoted_terms(std::slice::from_ref(tree));
                out.report(&r.finding(pm.pos.line, &pm.verb, op, what, Escape::Permission, pm.blind));
            }
            let refused: Vec<PermNode> = escapes.into_iter().filter(|(_, e)| *e == Escape::Requirement).map(|(t, _)| t).collect();
            if !refused.is_empty() {
                out.report(&r.finding(pm.pos.line, &pm.verb, op, quoted_terms(&refused), Escape::Requirement, pm.blind));
            }
        }
    }

    fn structural_atoms(&self, obj: &Object, virt: &Virtual, op: &str) -> BTreeSet<String> {
        self.structural_branches(obj, virt, op)
            .into_iter()
            .filter_map(|b| match parse(&b) {
                Expr::Atom(a) => Some(a),
                _ => None,
            })
            .collect()
    }

    fn disjunct_escape(&self, r: &ObjectReach<'_>, w: &WriteTerm<'_>, d: &[(bool, Term)], virt: &Virtual) -> Option<(PermNode, Escape)> {
        let mut part = w.pm.clone();
        part.tree = disjunct_node(d);
        let pred = self.rls_predicate(r.obj, &part, self.s.owner_subject(leaf(r.obj)), virt).ok()?;
        let conjs = dnf(&parse(&pred), false)?;
        let own: Vec<Conj> = conjs.into_iter().filter(|c| !(c.len() == 1 && c.iter().all(|(n, a)| !n && w.structural.contains(a)))).collect();
        let escape = r.escape(&with_requirement(&own, &w.requirement)?)?;
        Some((part.tree, escape))
    }

    fn check_admit_arms(&self, r: &ObjectReach<'_>, virt: &Virtual, out: &mut WriteReach) {
        let cust = self.s.owner_subject(leaf(r.obj));
        for &(a, op) in &r.admits {
            let Ok(pred) = self.admit_arm_predicate(r.obj, a, op, cust, virt) else { continue };
            let Some(conjs) = dnf(&parse(&pred), false).and_then(|c| with_requirement(&c, r.requirement(op))) else { continue };
            if let Some(escape) = r.escape(&conjs) {
                let what = format!("its admit arm `{}`", PermNode::display(&a.tree));
                out.report(&r.finding(a.pos.line, "admit", op, what, escape, false));
            }
        }
    }
}
