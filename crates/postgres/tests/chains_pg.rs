use postgres::{Client, NoTls, Transaction};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_chain_rows";
const AUTH: &str = "demesne_chain_auth";
const CALLER: &str = "demesne_chain_caller";

const BRACKET: &str = "every s in rule_slots(rule) where role = \"require\" ((@slot(kind, \"edge\") and shared) + (@slot(kind, \"grant\") and granted:read) + (@slot(kind, \"lend\") and lent) + (@slot(kind, \"tree\") and under)) and none s in rule_slots(rule) where role = \"except\" ((@slot(kind, \"edge\") and barred) + (@slot(kind, \"lend\") and lent)) and terms";

fn spec() -> String {
    let hops =
        |hop: &str| format!("(every h in trail_hops(trail) ((@slot(kind, \"claim\") and @slot(rule held rules_held)) + (@slot(kind, \"live\") and {hop})))");
    let some = |prefix: &str| format!("some r in rules_live prefix \"{prefix}\" held rules_held ({BRACKET})");
    format!(
        "definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\ntopology {{ level estate }}\nsubject member {{ anchor estate; reach self; identifies sub; roles none }}\nobject doc {{\n  table docs\n  scoped estate\n  nested 1\n  relation shared: member via edge doc_shares(member_id, doc_id) key rule\n  relation barred: member via edge doc_bars(member_id, doc_id) key rule\n  relation granted: member via grant doc_acl(doc_id, principal_kind, principal_id, access)\n  relation terms: member via conditions doc_terms(doc_id, term, op) values (num, txt, at) key rule on id from claim facts\n  relation lent: member via composition doc_lends(borrower_id, lender_id) slot field from param path trail along {}\n  relation under: member via composition doc_tree(below_id, above_id) path select seen, update changed, delete dropped along {}\n  permission view = {} @rls maps select\n  permission edit = {} and {} @rls maps update blind\n  permission remove = {} and {} @rls maps delete blind\n}}\n",
        hops("@holds_at(doc_id, rule slot field for select)"),
        hops("@holds_at(doc_id, rule)"),
        some("read."),
        some("write."),
        some("read."),
        some("delete."),
        some("read."),
    )
}

type Slot = (&'static str, &'static str, &'static str, &'static str);
type Hop = (&'static str, &'static str, &'static str, &'static str);

const SLOTS: [Slot; 22] = [
    ("read.edge", "require", "edge", ""),
    ("write.edge", "require", "edge", ""),
    ("delete.edge", "require", "edge", ""),
    ("read.grant", "require", "grant", ""),
    ("read.both", "require", "edge", ""),
    ("read.both", "require", "grant", ""),
    ("read.unless", "require", "edge", ""),
    ("read.unless", "except", "edge", ""),
    ("read.lend", "require", "lend", "f1"),
    ("read.lend2", "require", "lend", "f1"),
    ("read.lend_edge", "require", "lend", "f1"),
    ("read.lend_edge", "require", "edge", ""),
    ("read.lend_unless", "require", "lend", "f1"),
    ("read.lend_unless", "except", "edge", ""),
    ("read.two", "require", "lend", "f1"),
    ("read.two", "require", "lend", "f2"),
    ("read.unless_lent", "require", "edge", ""),
    ("read.unless_lent", "except", "lend", "f1"),
    ("read.tree", "require", "tree", ""),
    ("write.tree", "require", "tree", ""),
    ("delete.tree", "require", "tree", ""),
    ("read.grant_tree", "require", "grant", ""),
];

const RULES: [&str; 16] = [
    "read.edge",
    "write.edge",
    "delete.edge",
    "read.grant",
    "read.both",
    "read.open",
    "read.unless",
    "read.lend",
    "read.lend2",
    "read.lend_edge",
    "read.lend_unless",
    "read.two",
    "read.unless_lent",
    "read.tree",
    "write.tree",
    "delete.tree",
];

const DOCS: [(&str, &str, &[&str]); 48] = [
    ("k_edge", "e1", &["read.edge", "write.edge", "delete.edge"]),
    ("k_edge_ro", "e1", &["read.edge", "write.edge"]),
    ("k_grant", "e1", &["read.grant"]),
    ("k_both_half", "e1", &["read.both"]),
    ("k_both", "e1", &["read.both"]),
    ("k_open", "e1", &["read.open"]),
    ("k_unless", "e1", &["read.unless"]),
    ("k_terms", "e1", &["read.edge"]),
    ("k_far", "e2", &["read.open"]),
    ("k_none", "e1", &[]),
    ("c1_r", "e1", &["read.lend"]),
    ("c1_a", "e1", &["read.edge"]),
    ("c2_r", "e1", &["read.lend"]),
    ("c2_x", "e1", &["read.lend2"]),
    ("c2_a", "e1", &["read.edge"]),
    ("c4_r", "e1", &["read.lend"]),
    ("c4_x1", "e1", &["read.lend_edge"]),
    ("c4_x2", "e1", &["read.lend_unless"]),
    ("c4_x3", "e1", &["read.lend"]),
    ("c4_a", "e1", &["read.edge"]),
    ("t_r", "e1", &["read.tree", "write.tree", "delete.tree"]),
    ("t_m", "e1", &["read.tree", "write.tree"]),
    ("t_a", "e1", &["read.edge", "write.edge", "delete.edge"]),
    ("n_r", "e1", &["read.lend", "write.edge"]),
    ("n_x", "e1", &["read.two"]),
    ("n_a", "e1", &["read.edge", "write.edge"]),
    ("n_b", "e1", &["read.edge"]),
    ("e_doc", "e1", &["read.unless_lent"]),
    ("e_a", "e1", &["read.edge"]),
    ("u_doc", "e1", &["read.unless_lent"]),
    ("u_a", "e1", &["read.edge"]),
    ("d_r", "e1", &["read.lend"]),
    ("d_x", "e1", &["read.two"]),
    ("d_a", "e1", &["read.edge"]),
    ("d_m", "e1", &["read.two"]),
    ("d_b", "e1", &["read.edge"]),
    ("d_c", "e1", &["read.edge"]),
    ("x_doc", "e1", &["read.unless_lent"]),
    ("x_m", "e1", &["read.two"]),
    ("x_a", "e1", &["read.edge"]),
    ("x_n", "e1", &["read.two"]),
    ("x_b", "e1", &["read.edge"]),
    ("x_c", "e1", &["read.edge"]),
    ("f_r", "e1", &["read.lend"]),
    ("f_x", "e1", &["read.two"]),
    ("f_a", "e1", &["read.edge"]),
    ("f_b", "e1", &["read.unless_lent"]),
    ("f_c", "e1", &["read.edge"]),
];

const DEEPER_THAN_THE_NESTING: [&str; 2] = ["d_r", "x_doc"];

const SHARES: [(&str, &str, &str); 40] = [
    ("ann", "k_edge", "read.edge"),
    ("ann", "k_edge", "write.edge"),
    ("ann", "k_edge", "delete.edge"),
    ("ann", "k_edge_ro", "read.edge"),
    ("bob", "k_edge", "read.edge"),
    ("ann", "k_both_half", "read.both"),
    ("ann", "k_both", "read.both"),
    ("ann", "k_unless", "read.unless"),
    ("bob", "k_unless", "read.unless"),
    ("ann", "k_terms", "read.edge"),
    ("ann", "c1_a", "read.edge"),
    ("ann", "c2_a", "read.edge"),
    ("ann", "c4_a", "read.edge"),
    ("bob", "c4_a", "read.edge"),
    ("cat", "c4_a", "read.edge"),
    ("ann", "c4_x1", "read.lend_edge"),
    ("cat", "c4_x1", "read.lend_edge"),
    ("ann", "t_a", "read.edge"),
    ("ann", "t_a", "write.edge"),
    ("ann", "t_a", "delete.edge"),
    ("bob", "t_a", "read.edge"),
    ("ann", "n_a", "read.edge"),
    ("ann", "n_b", "read.edge"),
    ("bob", "n_a", "read.edge"),
    ("ann", "e_doc", "read.unless_lent"),
    ("bob", "e_doc", "read.unless_lent"),
    ("bob", "e_a", "read.edge"),
    ("ann", "u_doc", "read.unless_lent"),
    ("ann", "u_a", "read.edge"),
    ("ann", "d_a", "read.edge"),
    ("ann", "d_b", "read.edge"),
    ("ann", "d_c", "read.edge"),
    ("ann", "x_doc", "read.unless_lent"),
    ("ann", "x_a", "read.edge"),
    ("ann", "x_b", "read.edge"),
    ("ann", "f_a", "read.edge"),
    ("ann", "f_b", "read.unless_lent"),
    ("ann", "f_c", "read.edge"),
    ("ann", "n_r", "write.edge"),
    ("ann", "n_a", "write.edge"),
];

const BARS: [(&str, &str, &str); 2] = [("bob", "k_unless", "read.unless"), ("cat", "c4_x2", "read.lend_unless")];
const ACL: [(&str, &str); 2] = [("ann", "k_grant"), ("ann", "k_both")];
const TERMS: [(&str, &str, &str); 3] = [("k_terms", "read.edge", "blue"), ("c4_x3", "read.lend", "blue"), ("u_a", "read.edge", "blue")];

const LENDS: [(&str, &str, &str, &[Hop]); 31] = [
    ("c1_r", "c1_a", "f1", &[]),
    ("c2_r", "c2_x", "f1", &[]),
    ("c2_x", "c2_a", "f1", &[]),
    ("c2_r", "c2_a", "f1", &[("c2_x", "read.lend2", "claim", "f1")]),
    ("c4_r", "c4_x1", "f1", &[]),
    ("c4_x1", "c4_x2", "f1", &[]),
    ("c4_x2", "c4_x3", "f1", &[]),
    ("c4_x3", "c4_a", "f1", &[]),
    ("c4_x2", "c4_a", "f1", &[("c4_x3", "read.lend", "live", "f1")]),
    ("c4_x1", "c4_a", "f1", &[("c4_x2", "read.lend_unless", "live", "f1"), ("c4_x3", "read.lend", "live", "f1")]),
    ("c4_r", "c4_a", "f1", &[("c4_x1", "read.lend_edge", "live", "f1"), ("c4_x2", "read.lend_unless", "live", "f1"), ("c4_x3", "read.lend", "live", "f1")]),
    ("n_r", "n_x", "f1", &[]),
    ("n_x", "n_a", "f1", &[]),
    ("n_x", "n_b", "f2", &[]),
    ("n_r", "n_a", "f1", &[("n_x", "read.two", "live", "f1")]),
    ("e_doc", "e_a", "f1", &[]),
    ("u_doc", "u_a", "f1", &[]),
    ("d_r", "d_x", "f1", &[]),
    ("d_x", "d_a", "f1", &[]),
    ("d_r", "d_a", "f1", &[("d_x", "read.two", "live", "f1")]),
    ("d_x", "d_m", "f2", &[]),
    ("d_m", "d_b", "f2", &[]),
    ("d_x", "d_b", "f2", &[("d_m", "read.two", "live", "f2")]),
    ("d_m", "d_c", "f1", &[]),
    ("x_doc", "x_a", "f1", &[("x_m", "read.two", "live", "f1")]),
    ("x_m", "x_b", "f2", &[("x_n", "read.two", "live", "f2")]),
    ("f_r", "f_x", "f1", &[]),
    ("f_x", "f_a", "f1", &[]),
    ("f_r", "f_a", "f1", &[("f_x", "read.two", "live", "f1")]),
    ("f_x", "f_b", "f2", &[]),
    ("f_b", "f_c", "f1", &[]),
];

type TreeHops = &'static [(&'static str, &'static str, &'static str)];

const TREE: [(&str, &str, TreeHops, TreeHops, TreeHops); 3] = [
    ("t_r", "t_m", &[], &[], &[]),
    ("t_m", "t_a", &[], &[], &[]),
    ("t_r", "t_a", &[("t_m", "read.tree", "live")], &[("t_m", "write.tree", "live")], &[("t_m", "delete.tree", "live")]),
];

#[derive(Clone, Copy, Debug)]
struct Caller {
    name: &'static str,
    sub: &'static str,
    held: &'static [&'static str],
    team: Option<&'static str>,
    estate: &'static str,
}

const CALLERS: [Caller; 9] = [
    Caller { name: "ann", sub: "ann", held: &RULES, team: Some("blue"), estate: "e1" },
    Caller { name: "ann on the red team", sub: "ann", held: &RULES, team: Some("red"), estate: "e1" },
    Caller { name: "ann with no team", sub: "ann", held: &RULES, team: None, estate: "e1" },
    Caller { name: "ann holding little", sub: "ann", held: &["read.edge", "read.lend", "write.edge"], team: Some("blue"), estate: "e1" },
    Caller { name: "ann holding nothing", sub: "ann", held: &[], team: Some("blue"), estate: "e1" },
    Caller { name: "bob", sub: "bob", held: &RULES, team: Some("blue"), estate: "e1" },
    Caller { name: "cat", sub: "cat", held: &RULES, team: Some("blue"), estate: "e1" },
    Caller { name: "dan", sub: "dan", held: &RULES, team: Some("blue"), estate: "e1" },
    Caller { name: "ann in another estate", sub: "ann", held: &RULES, team: Some("blue"), estate: "e2" },
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tri {
    No,
    Unknown,
    Yes,
}

impl Tri {
    fn of(b: bool) -> Tri {
        if b { Tri::Yes } else { Tri::No }
    }

    fn and(self, other: Tri) -> Tri {
        match (self, other) {
            (Tri::No, _) | (_, Tri::No) => Tri::No,
            (Tri::Yes, Tri::Yes) => Tri::Yes,
            _ => Tri::Unknown,
        }
    }

    fn or(self, other: Tri) -> Tri {
        match (self, other) {
            (Tri::Yes, _) | (_, Tri::Yes) => Tri::Yes,
            (Tri::No, Tri::No) => Tri::No,
            _ => Tri::Unknown,
        }
    }
}

fn any(items: impl Iterator<Item = Tri>) -> Tri {
    items.fold(Tri::No, Tri::or)
}

fn all(items: impl Iterator<Item = Tri>) -> Tri {
    items.fold(Tri::Yes, Tri::and)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Followed {
    Nothing,
    Lent(&'static str),
    Under,
    OwnRule,
}

fn doc(id: &str) -> (&'static str, &'static [&'static str]) {
    DOCS.iter().find(|d| d.0 == id).map_or_else(|| panic!("no doc {id}"), |d| (d.1, d.2))
}

fn prefix(op: &str) -> &'static str {
    match op {
        "select" => "read.",
        "update" => "write.",
        _ => "delete.",
    }
}

struct Oracle {
    who: Caller,
}

impl Oracle {
    fn lent(&self, op: &str, at: &str, field: &str) -> Tri {
        any(LENDS.iter().filter(|l| l.0 == at && l.2 == field).map(|(_, to, _, hops)| {
            let each = hops.iter().map(|(hop, rule, kind, hop_field)| match *kind {
                "claim" => Tri::of(self.who.held.contains(rule)),
                _ => self.element("select", hop, rule, Followed::Lent(hop_field)),
            });
            self.rule(op, to, Followed::OwnRule).and(all(each))
        }))
    }

    fn under(&self, op: &str, at: &str) -> Tri {
        any(TREE.iter().filter(|t| t.0 == at).map(|(_, to, seen, changed, dropped)| {
            let hops = match op {
                "select" => seen,
                "update" => changed,
                _ => dropped,
            };
            let each = hops.iter().map(|(hop, rule, kind)| match *kind {
                "claim" => Tri::of(self.who.held.contains(rule)),
                _ => self.element(op, hop, rule, Followed::Under),
            });
            self.rule(op, to, Followed::OwnRule).and(all(each))
        }))
    }

    fn slot(&self, op: &str, at: &str, rule: &str, (_, part, kind, param): Slot, followed: Followed) -> Tri {
        let widens = part == "require";
        let composed = |real: &dyn Fn() -> Tri, given: bool| match followed {
            _ if given => Tri::Yes,
            Followed::OwnRule if widens => Tri::No,
            _ => real(),
        };
        match (kind, widens) {
            ("edge", true) => Tri::of(SHARES.contains(&(self.who.sub, at, rule))),
            ("edge", false) => Tri::of(BARS.contains(&(self.who.sub, at, rule))),
            ("grant", _) => Tri::of(ACL.contains(&(self.who.sub, at))),
            ("lend", _) => composed(&|| self.lent(op, at, param), followed == Followed::Lent(param)),
            _ => composed(&|| self.under(op, at), followed == Followed::Under),
        }
    }

    fn bracket(&self, op: &str, at: &str, rule: &'static str, followed: Followed) -> Tri {
        let slots = |role: &'static str| SLOTS.iter().filter(move |s| s.0 == rule && s.1 == role);
        let required = slots("require").all(|s| self.slot(op, at, rule, *s, followed) == Tri::Yes);
        let excepted = slots("except").any(|s| self.slot(op, at, rule, *s, followed) != Tri::No);
        let terms = all(TERMS.iter().filter(|t| t.0 == at && t.1 == rule).map(|t| match self.who.team {
            None => Tri::Unknown,
            Some(team) => Tri::of(team == t.2),
        }));
        if required && !excepted { terms } else { Tri::No }
    }

    fn element(&self, op: &str, at: &str, rule: &'static str, followed: Followed) -> Tri {
        let (estate, live) = doc(at);
        let named = rule.starts_with(prefix(op)) || rule.starts_with("read.");
        if estate != self.who.estate || !named || !live.contains(&rule) || !self.who.held.contains(&rule) {
            return Tri::No;
        }
        self.bracket(op, at, rule, followed)
    }

    fn rule(&self, op: &str, at: &str, followed: Followed) -> Tri {
        let (_, live) = doc(at);
        let some = |prefix: &str| any(live.iter().filter(|r| r.starts_with(prefix)).map(|r| self.element(op, at, r, followed)));
        if op == "select" { some("read.") } else { some(prefix(op)).and(some("read.")) }
    }

    fn admits(&self, op: &str, at: &str) -> bool {
        let reads = self.rule("select", at, Followed::Nothing) == Tri::Yes;
        reads && (op == "select" || self.rule(op, at, Followed::Nothing) == Tri::Yes)
    }
}

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&spec()).unwrap_or_else(|e| panic!("the spec parses: {e}\n{}", spec()));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("the spec validates: {e}"));
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    assert_eq!(rls.unsupported, [] as [String; 0]);
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, rules_live text[], note text);
         CREATE TABLE rule_slots (rule text, role text, kind text, param text);
         CREATE TABLE doc_shares (member_id text, doc_id text, rule text);
         CREATE TABLE doc_bars (member_id text, doc_id text, rule text);
         CREATE TABLE doc_acl (doc_id text, principal_kind text, principal_id text, access text);
         CREATE TABLE doc_terms (doc_id text, rule text, term text, op text, num double precision, txt text, at timestamptz);
         CREATE TABLE doc_lends (borrower_id text, lender_id text, field text, trail text);
         CREATE TABLE doc_tree (below_id text, above_id text, seen text, changed text, dropped text);
         CREATE TABLE trail_hops (trail text, doc_id text, rule text, kind text, field text);
         RESET search_path;"
    ))
    .expect("fresh schemas and tables");
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT, UPDATE, DELETE ON {ROWS}.docs TO {CALLER}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {AUTH} TO {CALLER}; SET search_path = {ROWS};"
    ))
    .expect("grants");
    seed(db);
}

fn seed(db: &mut Client) {
    for (id, estate, rules) in DOCS {
        let rules: Vec<String> = rules.iter().map(ToString::to_string).collect();
        db.execute("INSERT INTO docs VALUES ($1, $2, $3, 'first')", &[&id, &estate, &rules]).expect("a doc");
    }
    for (rule, role, kind, param) in SLOTS {
        db.execute("INSERT INTO rule_slots VALUES ($1, $2, $3, $4)", &[&rule, &role, &kind, &param]).expect("a slot");
    }
    for (who, at, rule) in SHARES {
        db.execute("INSERT INTO doc_shares VALUES ($1, $2, $3)", &[&who, &at, &rule]).expect("a share");
    }
    for (who, at, rule) in BARS {
        db.execute("INSERT INTO doc_bars VALUES ($1, $2, $3)", &[&who, &at, &rule]).expect("a bar");
    }
    for (who, at) in ACL {
        db.execute("INSERT INTO doc_acl VALUES ($2, 'member', $1, 'read')", &[&who, &at]).expect("a grant");
    }
    for (at, rule, team) in TERMS {
        db.execute("INSERT INTO doc_terms VALUES ($1, $2, 'team', 'eq', NULL, $3, NULL)", &[&at, &rule, &team]).expect("a term");
    }
    for (from, to, field, hops) in LENDS {
        let trail = format!("lend:{from}:{to}:{field}");
        db.execute("INSERT INTO doc_lends VALUES ($1, $2, $3, $4)", &[&from, &to, &field, &trail]).expect("a lend");
        for (hop, rule, kind, hop_field) in hops {
            db.execute("INSERT INTO trail_hops VALUES ($1, $2, $3, $4, $5)", &[&trail, hop, rule, kind, hop_field]).expect("a hop");
        }
    }
    for (from, to, seen, changed, dropped) in TREE {
        let trails: Vec<String> = ["seen", "changed", "dropped"].iter().map(|op| format!("tree:{from}:{to}:{op}")).collect();
        db.execute("INSERT INTO doc_tree VALUES ($1, $2, $3, $4, $5)", &[&from, &to, &trails[0], &trails[1], &trails[2]]).expect("a tree row");
        for (trail, hops) in trails.iter().zip([seen, changed, dropped]) {
            for (hop, rule, kind) in hops {
                db.execute("INSERT INTO trail_hops VALUES ($1, $2, $3, $4, NULL)", &[trail, hop, rule, kind]).expect("a hop");
            }
        }
    }
}

fn claims(tx: &mut Transaction<'_>, who: Caller) {
    let held: Vec<String> = who.held.iter().map(|r| format!("\"{r}\"")).collect();
    let facts = who.team.map(|t| format!("\"team\":\"{t}\"")).unwrap_or_default();
    let claims = format!("{{\"sub\":\"{}\",\"estate_id\":\"{}\",\"rules_held\":[{}],\"facts\":{{{facts}}}}}", who.sub, who.estate, held.join(","));
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
}

fn ids(tx: &mut Transaction<'_>, sql: &str) -> BTreeSet<String> {
    tx.query(sql, &[]).unwrap_or_else(|e| panic!("{sql}: {e}")).iter().map(|r| r.get(0)).collect()
}

fn reached(db: &mut Client, who: Caller, op: &str) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    claims(&mut tx, who);
    let got = ids(
        &mut tx,
        match op {
            "select" => "SELECT id FROM docs",
            "update" => "UPDATE docs SET note = 'second' RETURNING id",
            _ => "DELETE FROM docs RETURNING id",
        },
    );
    tx.rollback().expect("rollback");
    got
}

fn judged(db: &mut Client, who: Caller, op: &str) -> BTreeSet<(String, String)> {
    let mut tx = db.transaction().expect("a transaction");
    claims(&mut tx, who);
    let rules: Vec<String> = RULES.iter().map(|r| format!("('{r}')")).collect();
    let sql = format!("SELECT d.id, r.rule FROM docs d CROSS JOIN (VALUES {}) AS r(rule) WHERE {AUTH}.doc_{op}_holds_at(d.id, r.rule)", rules.join(", "));
    let got = tx.query(&sql, &[]).unwrap_or_else(|e| panic!("{sql}: {e}")).iter().map(|r| (r.get(0), r.get(1))).collect();
    tx.rollback().expect("rollback");
    got
}

fn connect() -> Client {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the chain checks against a live Postgres");
    Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL")
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn the_policy_and_the_evaluator_answer_as_the_rule_says_for_every_caller_row_and_operation() {
    let mut db = connect();
    install(&mut db);
    let within = |id: &&str| !DEEPER_THAN_THE_NESTING.contains(id);
    let mut cells = 0;
    for op in ["select", "update", "delete"] {
        let mut outcomes = [0, 0];
        for who in CALLERS {
            let oracle = Oracle { who };
            let policy = reached(&mut db, who, op);
            let want: BTreeSet<String> = DOCS.iter().map(|d| d.0).filter(within).filter(|id| oracle.admits(op, id)).map(str::to_string).collect();
            let got: BTreeSet<String> = policy.iter().filter(|id| within(&id.as_str())).cloned().collect();
            assert_eq!(got, want, "{op} by {}", who.name);
            outcomes[1] += want.len();
            outcomes[0] += DOCS.len() - DEEPER_THAN_THE_NESTING.len() - want.len();
            cells += DOCS.len() - DEEPER_THAN_THE_NESTING.len();

            let elements = judged(&mut db, who, op);
            let held: BTreeSet<(String, String)> = DOCS
                .iter()
                .filter(|d| within(&d.0))
                .flat_map(|d| RULES.iter().map(move |r| (d.0, *r)))
                .filter(|(id, r)| oracle.element(op, id, r, Followed::Nothing) == Tri::Yes)
                .map(|(id, r)| (id.to_string(), r.to_string()))
                .collect();
            let judged_within: BTreeSet<(String, String)> = elements.iter().filter(|(id, _)| within(&id.as_str())).cloned().collect();
            assert_eq!(judged_within, held, "the evaluator for {op} by {}", who.name);
            if op == "select" {
                let by_element: BTreeSet<String> = elements.iter().map(|(id, _)| id.clone()).collect();
                assert_eq!(by_element, policy, "a row is read exactly when the evaluator holds for one of its elements, by {}", who.name);
            }
        }
        assert!(outcomes[0] > 0 && outcomes[1] > 0, "{op} is both admitted and refused: {outcomes:?}");
    }
    assert_eq!(cells, 3 * 9 * 46);

    let ann = CALLERS[0];
    let read = reached(&mut db, ann, "select");
    for (id, why) in [
        ("c1_r", "a chain of one hop"),
        ("c2_r", "a chain of two with a hop the claim decides"),
        ("c4_r", "a chain of four with an extra slot, an exception and a comparison on the way"),
        ("n_r", "a hop whose rule borrows a second time, inside the nesting"),
        ("t_r", "a tree"),
        ("e_doc", "an exception by a composition the caller does not reach"),
    ] {
        assert!(read.contains(id), "ann reads {id}: {why}");
    }
    for (who, id, why) in [
        (CALLERS[3], "c2_r", "the hop's rule is not among those the caller holds"),
        (CALLERS[5], "c4_r", "the extra slot at the first hop is not the caller's"),
        (CALLERS[6], "c4_r", "the caller is excepted at the second hop"),
        (CALLERS[1], "c4_r", "the comparison at the third hop is decided false"),
        (CALLERS[2], "c4_r", "the comparison at the third hop cannot be decided"),
        (CALLERS[5], "n_r", "the hop's second borrow is not the caller's"),
        (CALLERS[5], "e_doc", "the caller reaches what the exception names"),
        (CALLERS[0], "u_doc", "the caller reaches what the exception names"),
        (CALLERS[2], "u_doc", "whether the caller reaches what the exception names cannot be decided, so it bars"),
        (CALLERS[0], "d_r", "a borrow deeper than the nesting is not followed"),
        (CALLERS[0], "x_doc", "an exception deeper than the nesting bars"),
        (CALLERS[0], "f_r", "what a hop borrows a second time is itself excepted for the caller"),
    ] {
        assert!(!reached(&mut db, who, "select").contains(id), "{} does not read {id}: {why}", who.name);
    }
    assert!(reached(&mut db, CALLERS[1], "select").contains("u_doc"), "a comparison decided false is no reach, so the exception does not bar");
    assert!(reached(&mut db, ann, "update").contains("t_r") && !reached(&mut db, ann, "delete").contains("t_r"), "each operation follows its own path");
    assert!(reached(&mut db, ann, "update").contains("n_r"), "a borrow's hops are judged for reading whatever the operation");

    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_change_at_a_middle_hop_ends_or_gives_access_in_the_same_transaction() {
    let mut db = connect();
    install(&mut db);
    let ann = CALLERS[0];
    for (change, why) in [
        ("DELETE FROM doc_shares WHERE member_id = 'ann' AND doc_id = 'c4_x1'", "the first hop loses its extra slot"),
        ("INSERT INTO doc_bars VALUES ('ann', 'c4_x2', 'read.lend_unless')", "the second hop gains an exception"),
        ("UPDATE doc_terms SET txt = 'red' WHERE doc_id = 'c4_x3'", "the third hop's comparison turns false"),
        ("UPDATE docs SET rules_live = '{}' WHERE id = 'c4_x2'", "the second hop's rule is no longer live"),
        ("DELETE FROM doc_shares WHERE member_id = 'ann' AND doc_id = 'c4_a'", "the far end no longer admits"),
    ] {
        let mut tx = db.transaction().expect("a transaction");
        claims(&mut tx, ann);
        tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
        assert_eq!(ids(&mut tx, "SELECT id FROM docs WHERE id = 'c4_r'").len(), 1, "before: {why}");
        tx.batch_execute(&format!("RESET ROLE; {change}; SET LOCAL ROLE {CALLER}")).unwrap_or_else(|e| panic!("{change}: {e}"));
        assert_eq!(ids(&mut tx, "SELECT id FROM docs WHERE id = 'c4_r'").len(), 0, "after: {why}");
        tx.rollback().expect("rollback");
    }
    let mut tx = db.transaction().expect("a transaction");
    claims(&mut tx, CALLERS[5]);
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    assert_eq!(ids(&mut tx, "SELECT id FROM docs WHERE id = 'c4_r'").len(), 0, "bob has no share at the first hop");
    tx.batch_execute(&format!("RESET ROLE; INSERT INTO doc_shares VALUES ('bob', 'c4_x1', 'read.lend_edge'); SET LOCAL ROLE {CALLER}")).expect("the share");
    assert_eq!(ids(&mut tx, "SELECT id FROM docs WHERE id = 'c4_r'").len(), 1, "the share at the first hop gives the chain at once");
    tx.rollback().expect("rollback");
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
