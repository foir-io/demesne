use demesne_model::SpecExt;
use demesne_syntax::{Grant, Object, PermNode, Repr, RoleStore, Spec, Term};
use postgres::error::SqlState;
use postgres::{Client, Config, NoTls, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const ROWS: usize = 36;
const CLAIM_SETS: usize = 40;
const INSTALL_ROUNDS: usize = 40;
const IDS: usize = 3;
const UUID_SPECS_WHOSE_DEFINERS_TAKE_TEXT: [&str; 2] =
    ["testdata/corpus/fixtures/5966e3f5904f0e54.demesne", "testdata/corpus/fixtures/8618b7c7f7925eb0.demesne"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Id,
    Text,
    Flag,
    Moment,
    Perms,
}

#[derive(Debug, Default, Clone)]
struct Tables(BTreeMap<String, BTreeMap<String, Kind>>);

impl Tables {
    fn table(&mut self, table: &str) {
        if !table.is_empty() {
            self.0.entry(table.to_string()).or_default();
        }
    }

    fn col(&mut self, table: &str, col: &str, kind: Kind) {
        if !table.is_empty() && !col.is_empty() {
            self.0.entry(table.to_string()).or_default().entry(col.to_string()).or_insert(kind);
        }
    }

    fn everywhere(&mut self, col: &str) {
        for cols in self.0.values_mut() {
            cols.entry(col.to_string()).or_insert(Kind::Text);
        }
    }
}

fn leaves(tree: &PermNode) -> Vec<&Term> {
    tree.leaves()
}

fn term_cols(t: &mut Tables, s: &Spec, o: &Object, term: &Term) {
    let table = o.table.as_str();
    if let Some(m) = term.mode_col() {
        t.col(table, m, Kind::Text);
    }
    t.col(table, term.self_col(), Kind::Id);
    t.col(table, term.row_col(), Kind::Text);
    if !term.within_level().is_empty() {
        t.col(table, &s.scope_col(o, term.within_level()), Kind::Id);
    }
    let declared = s.externals.iter().find(|e| e.name == term.external_fn()).map_or(&[][..], |e| e.arg_types.as_slice());
    for (i, arg) in term.external_args().iter().enumerate() {
        let kind = match declared.get(i).map(String::as_str) {
            Some("text[]") => Kind::Perms,
            Some("boolean") => Kind::Flag,
            Some("timestamptz") => Kind::Moment,
            Some(t) if t == s.id_type() => Kind::Id,
            _ => Kind::Text,
        };
        t.col(table, arg.col(), kind);
    }
}

fn relation_cols(t: &mut Tables, o: &Object, repr: &Repr) {
    let table = o.table.as_str();
    match repr {
        Repr::Column(vc) => {
            t.col(table, &vc.column, Kind::Id);
            t.col(table, vc.discrim_col.as_deref().unwrap_or(""), Kind::Text);
        }
        Repr::Edge(e) => {
            t.table(&e.table);
            for c in &e.cols {
                t.col(&e.table, c, Kind::Id);
            }
        }
        Repr::Composition(c) => {
            t.table(&c.table);
            t.col(&c.table, &c.child_col, Kind::Id);
            t.col(&c.table, &c.parent_col, Kind::Id);
            t.col(&c.table, c.kind_col.as_deref().unwrap_or(""), Kind::Text);
        }
        Repr::Closure(c) => {
            t.col(table, &c.col, Kind::Id);
            t.table(&c.closure);
            t.col(&c.closure, &c.ancestor_col, Kind::Id);
            t.col(&c.closure, &c.descendant_col, Kind::Id);
            if let Some(base) = &c.base {
                t.table(base);
                t.col(base, c.base_id.as_deref().unwrap_or(""), Kind::Id);
                t.col(base, c.base_parent.as_deref().unwrap_or(""), Kind::Id);
            }
        }
        Repr::Group(g) => {
            t.col(table, &g.col, Kind::Id);
            t.table(&g.closure);
            t.col(&g.closure, &g.group_col, Kind::Id);
            t.col(&g.closure, &g.member_col, Kind::Id);
            t.table(&g.edge);
            t.col(&g.edge, &g.edge_member, Kind::Id);
            t.col(&g.edge, &g.edge_group, Kind::Id);
        }
        Repr::Object(vo) => t.col(table, &vo.col, Kind::Id),
        Repr::Grant(g) => {
            t.table(&g.table);
            t.col(&g.table, &g.record_col, Kind::Id);
            t.col(&g.table, &g.kind_col, Kind::Text);
            t.col(&g.table, &g.principal_col, Kind::Id);
            t.col(&g.table, &g.access_col, Kind::Text);
            t.col(&g.table, g.discrim_col.as_deref().unwrap_or(""), Kind::Text);
            if let Some(closure) = &g.group_closure {
                t.table(closure);
                t.col(closure, g.group_group_col.as_deref().unwrap_or(""), Kind::Id);
                t.col(closure, g.group_member_col.as_deref().unwrap_or(""), Kind::Id);
            }
            if let Some(edge) = &g.group_edge {
                t.table(edge);
                t.col(edge, g.group_edge_member.as_deref().unwrap_or(""), Kind::Id);
                t.col(edge, g.group_edge_group.as_deref().unwrap_or(""), Kind::Id);
            }
        }
        Repr::MemberIn(mi) => {
            t.col(table, mi.principal.col(), Kind::Id);
            t.col(table, mi.scope.col(), Kind::Id);
        }
        Repr::Role => {}
    }
}

fn object_cols(t: &mut Tables, s: &Spec, o: &Object) {
    let table = o.table.as_str();
    t.table(table);
    t.col(table, o.pk(), Kind::Id);
    for c in &o.pk_cols {
        t.col(table, c, Kind::Id);
    }
    for lvl in o.scoped.iter().chain(o.reach_uses.iter().filter_map(|u| u.bound.as_ref())) {
        t.col(table, &s.scope_col(o, lvl), Kind::Id);
    }
    for r in &o.relations {
        relation_cols(t, o, &r.repr);
    }
    for pm in &o.perms {
        t.col(table, pm.self_check.as_deref().unwrap_or(""), Kind::Id);
        t.col(table, pm.guard.as_ref().map_or("", |g| g.col.as_str()), Kind::Text);
    }
    let trees = o.perms.iter().map(|pm| &pm.tree).chain(o.requires.iter().map(|rq| &rq.tree)).chain(o.admits.iter().map(|a| &a.tree));
    for term in trees.flat_map(leaves) {
        term_cols(t, s, o, term);
    }
    for f in &o.fields {
        t.col(table, f.column.as_deref().unwrap_or(""), Kind::Text);
    }
}

fn store_cols(t: &mut Tables, rs: &RoleStore) {
    let a = rs.assignments.as_deref().unwrap_or("");
    t.table(a);
    t.col(a, rs.assignment_pk(), Kind::Id);
    for (col, kind) in [
        (&rs.subject_col, Kind::Id),
        (&rs.role_col, Kind::Id),
        (&rs.kind_col, Kind::Text),
        (&rs.revoked_col, Kind::Moment),
        (&rs.granted_at_col, Kind::Moment),
        (&rs.granted_by_col, Kind::Id),
        (&rs.revoked_by_col, Kind::Id),
    ] {
        t.col(a, col.as_deref().unwrap_or(""), kind);
    }
    for c in &rs.scope_cols {
        t.col(a, c, Kind::Id);
    }
    for c in &rs.extra_cols {
        t.col(a, c, Kind::Text);
    }
    let roles = rs.roles_table.as_deref().unwrap_or("");
    t.table(roles);
    t.col(roles, rs.roles_id.as_deref().unwrap_or(""), Kind::Id);
    t.col(roles, rs.key_col.as_deref().unwrap_or(""), Kind::Text);
    t.col(roles, rs.perms_col.as_deref().unwrap_or(""), Kind::Perms);
}

fn grant_cols(t: &mut Tables, g: &Grant) {
    let table = g.table();
    t.table(table);
    t.col(table, g.grant_pk(), Kind::Id);
    t.col(table, g.grantee_col(), Kind::Id);
    t.col(table, g.level_col(), Kind::Id);
    for scope in &g.scopes {
        t.col(table, &scope.column, Kind::Id);
    }
    for (col, kind) in [
        (&g.active_col, Kind::Moment),
        (&g.expires_col, Kind::Moment),
        (&g.created_at_col, Kind::Moment),
        (&g.granted_by_col, Kind::Id),
        (&g.revoked_by_col, Kind::Id),
    ] {
        t.col(table, col.as_deref().unwrap_or(""), kind);
    }
    for c in &g.extra_cols {
        t.col(table, c, Kind::Text);
    }
}

fn tables_of(s: &Spec) -> Tables {
    let mut t = Tables::default();
    for o in &s.objects {
        object_cols(&mut t, s, o);
    }
    for rs in &s.role_stores {
        store_cols(&mut t, rs);
    }
    for g in s.grants.iter().filter(|g| g.claim_key.is_none()) {
        grant_cols(&mut t, g);
    }
    for m in s.subjects.iter().filter_map(|sub| sub.membership.as_ref()) {
        t.table(&m.table);
        t.col(&m.table, &m.id_col, Kind::Id);
        t.col(&m.table, &m.flag_col, Kind::Flag);
        t.col(&m.table, m.active_col.as_deref().unwrap_or(""), Kind::Text);
    }
    t
}

fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn pick(seed: &str, n: usize) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in seed.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    usize::try_from(h % u64::try_from(n).expect("a pool size fits in u64")).expect("an index below a pool size fits in usize")
}

struct Pools {
    ids: Vec<String>,
    literals: Vec<String>,
}

impl Pools {
    fn new(id_type: &str, ddl: &[&str], keys: &BTreeSet<String>) -> Self {
        let ids = (1..=IDS)
            .map(|n| match id_type {
                "uuid" => format!("00000000-0000-4000-8000-00000000000{n}"),
                "bigint" | "integer" | "int" | "int8" | "int4" => n.to_string(),
                _ => format!("i{n}"),
            })
            .collect();
        let literals: BTreeSet<String> = ddl
            .iter()
            .flat_map(|sql| sql.split('\'').skip(1).step_by(2))
            .filter(|lit| !lit.is_empty() && lit.len() <= 40 && !lit.contains(char::is_whitespace) && !keys.contains(*lit) && !lit.contains("jwt"))
            .map(str::to_string)
            .collect();
        Self { ids, literals: literals.into_iter().collect() }
    }

    fn raw(&self, kind: Kind, seed: &str) -> Option<&String> {
        match kind {
            Kind::Id => self.ids.get(pick(seed, self.ids.len() + 1)),
            Kind::Text => {
                let all: Vec<&String> = self.ids.iter().chain(&self.literals).chain(&self.literals).collect();
                all.get(pick(seed, all.len() + 1)).copied()
            }
            Kind::Flag | Kind::Moment | Kind::Perms => None,
        }
    }

    fn value(&self, kind: Kind, seed: &str) -> String {
        match kind {
            Kind::Id | Kind::Text => self.raw(kind, seed).map_or_else(|| "NULL".to_string(), |v| literal(v)),
            Kind::Flag => ["true", "false", "NULL"][pick(seed, 3)].to_string(),
            Kind::Moment => ["'2001-01-01T00:00:00Z'", "'2999-01-01T00:00:00Z'", "NULL"][pick(seed, 3)].to_string(),
            Kind::Perms => {
                let chosen: Vec<String> =
                    self.literals.iter().filter(|l| pick(&format!("{seed}/{l}"), 3) == 0).map(|l| format!("\"{}\"", l.replace('"', "\\\""))).collect();
                literal(&format!("{{{}}}", chosen.join(",")))
            }
        }
    }
}

fn sql_type(kind: Kind, id_type: &str) -> &str {
    match kind {
        Kind::Id => id_type,
        Kind::Text => "text",
        Kind::Flag => "boolean",
        Kind::Moment => "timestamptz",
        Kind::Perms => "text[]",
    }
}

struct Keys {
    all: BTreeSet<String>,
    sets: BTreeSet<String>,
    literal: BTreeSet<String>,
}

fn claim_reads(sql: &str) -> impl Iterator<Item = (&str, &str)> {
    sql.match_indices("->> '").filter(|(at, _)| sql[..*at].ends_with("::json ") || sql[..*at].ends_with("::jsonb ")).filter_map(|(at, _)| {
        let after = &sql[at + 5..];
        let end = after.find('\'')?;
        Some((&after[..end], &after[end + 1..]))
    })
}

fn claim_keys(ddl: &[&str]) -> Keys {
    let mut keys = Keys { all: BTreeSet::new(), sets: BTreeSet::new(), literal: BTreeSet::new() };
    for (key, tail) in ddl.iter().flat_map(|sql| claim_reads(sql)) {
        keys.all.insert(key.to_string());
        if tail.starts_with(")::jsonb") {
            keys.sets.insert(key.to_string());
        }
        if tail.starts_with(") = '") || tail.starts_with(") <> '") {
            keys.literal.insert(key.to_string());
        }
    }
    keys
}

fn claim_sets(keys: &Keys, pools: &Pools, tables: &Tables, governed: &[String]) -> Vec<Option<String>> {
    let mut out = vec![None, Some("{}".to_string())];
    let quoted = |v: &str| format!("\"{}\"", v.replace('"', "\\\""));
    for k in 0..CLAIM_SETS * 2 {
        let aimed = (k % 2 == 1 && !governed.is_empty()).then(|| {
            let table = &governed[(k / 2) % governed.len()];
            (table, &tables.0[table], pick(&format!("{k}/row"), ROWS))
        });
        let mut fields = Vec::new();
        for key in &keys.all {
            if pick(&format!("{k}/{key}/absent"), 8) == 0 {
                continue;
            }
            let pool: &[String] = if keys.literal.contains(key) && !pools.literals.is_empty() { &pools.literals } else { &pools.ids };
            let at = |n: usize| quoted(&pool[pick(&format!("{k}/{key}/{n}"), pool.len())]);
            let from_row = aimed.and_then(|(table, cols, row)| cols.get(key).and_then(|kind| pools.raw(*kind, &format!("{table}/{key}/{row}"))));
            let value = match from_row {
                Some(v) if keys.sets.contains(key) => format!("[{},{}]", quoted(v), at(1)),
                Some(v) => quoted(v),
                None if keys.sets.contains(key) => format!("[{},{}]", at(0), at(1)),
                None => at(0),
            };
            fields.push(format!("{}:{value}", quoted(key)));
        }
        out.push(Some(format!("{{{}}}", fields.join(","))));
    }
    out
}

type Outcome = Result<Vec<i32>, String>;

#[derive(Debug, Default, PartialEq, Eq)]
struct Judged {
    rules: BTreeMap<String, Vec<Outcome>>,
    visible: BTreeMap<String, Vec<Outcome>>,
    checks: BTreeMap<String, Vec<Result<Vec<String>, String>>>,
}

fn why(e: &postgres::Error) -> String {
    e.as_db_error().map_or_else(|| e.to_string(), |d| format!("{}: {}", d.code().code(), d.message()))
}

fn sqlstate(e: &postgres::Error) -> String {
    e.code().map_or_else(|| e.to_string(), |c| c.code().to_string())
}

fn rows_where(tx: &mut Transaction<'_>, table: &str, filter: &str) -> Outcome {
    let mut sp = tx.savepoint("rule").map_err(|e| sqlstate(&e))?;
    let got = sp.query(&format!("SELECT _row FROM {table} WHERE ({filter}) ORDER BY _row"), &[]).map_err(|e| sqlstate(&e));
    sp.rollback().map_err(|e| sqlstate(&e))?;
    got.map(|rows| rows.iter().map(|r| r.get(0)).collect())
}

struct Setup<'a> {
    spec: &'a Spec,
    tables: Tables,
    setting: String,
    role: String,
}

fn create(tx: &mut Transaction<'_>, setup: &Setup<'_>, pools: &Pools) -> Result<(), postgres::Error> {
    let s = setup.spec;
    let schema = s.table_schema();
    let mut b = format!("CREATE SCHEMA IF NOT EXISTS {}; CREATE SCHEMA IF NOT EXISTS {};", ident(schema), ident(s.definer_schema()));
    write!(b, "SET LOCAL search_path = {}, public;", ident(schema)).expect("fmt::Write for String never fails");
    for (table, cols) in &setup.tables.0 {
        let defs: Vec<String> = cols.iter().filter(|(c, _)| c.as_str() != "_row").map(|(c, k)| format!("{} {}", ident(c), sql_type(*k, s.id_type()))).collect();
        write!(b, "CREATE TABLE {}.{} (_row int PRIMARY KEY{}{});", ident(schema), ident(table), if defs.is_empty() { "" } else { ", " }, defs.join(", "))
            .expect("fmt::Write for String never fails");
        let columns: Vec<(&String, &Kind)> = cols.iter().filter(|(c, _)| c.as_str() != "_row").collect();
        let names: Vec<String> = std::iter::once("_row".to_string()).chain(columns.iter().map(|(c, _)| ident(c))).collect();
        for row in 0..ROWS {
            let values: Vec<String> =
                std::iter::once(row.to_string()).chain(columns.iter().map(|(c, k)| pools.value(**k, &format!("{table}/{c}/{row}")))).collect();
            write!(b, "INSERT INTO {}.{} ({}) VALUES ({});", ident(schema), ident(table), names.join(", "), values.join(", "))
                .expect("fmt::Write for String never fails");
        }
    }
    for e in &s.externals {
        let args: Vec<String> = e.arg_types.iter().enumerate().map(|(i, t)| format!("p{i} {t}")).collect();
        let body: Vec<String> = (0..e.arg_types.len()).map(|i| format!("coalesce(p{i}::text, '')")).collect();
        write!(
            b,
            "CREATE FUNCTION {}.{}({}) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$ SELECT md5(concat_ws('/', {})) < '8' $$;",
            ident(s.definer_schema()),
            ident(&e.name),
            args.join(", "),
            if body.is_empty() { "''".to_string() } else { body.join(", ") }
        )
        .expect("fmt::Write for String never fails");
    }
    tx.batch_execute(&b)
}

fn missing_name(e: &postgres::Error) -> Option<(SqlState, String)> {
    let db = e.as_db_error()?;
    let named = db.message().strip_prefix("column ").or_else(|| db.message().strip_prefix("relation "))?;
    let name = named.split(' ').next()?.trim_matches('"');
    Some((db.code().clone(), name.rsplit('.').next().unwrap_or(name).trim_matches('"').to_string()))
}

fn install(db: &mut Client, setup: &mut Setup<'_>, pools: &Pools, ddl: &str) -> Result<(), String> {
    let mut added = BTreeSet::new();
    for _ in 0..INSTALL_ROUNDS {
        let mut tx = db.transaction().map_err(|e| why(&e))?;
        create(&mut tx, setup, pools).map_err(|e| format!("the synthesised tables: {}", why(&e)))?;
        match tx.batch_execute(ddl) {
            Ok(()) => {
                tx.rollback().map_err(|e| why(&e))?;
                return Ok(());
            }
            Err(e) => {
                drop(tx);
                match missing_name(&e) {
                    Some((code, name)) if code == SqlState::UNDEFINED_TABLE && added.insert(format!("table {name}")) => setup.tables.table(&name),
                    Some((code, name)) if code == SqlState::UNDEFINED_COLUMN && added.insert(format!("column {name}")) => setup.tables.everywhere(&name),
                    _ => return Err(why(&e)),
                }
            }
        }
    }
    Err("the tables never settled".to_string())
}

type Policy = (String, String, Option<String>, Option<String>);

struct Found {
    policies: Vec<Policy>,
    checks: Vec<String>,
}

fn judge_rules(tx: &mut Transaction<'_>, schema: &str, policies: &[Policy], judged: &mut Judged) {
    for (table, name, qual, check) in policies {
        let at = format!("{}.{}", ident(schema), ident(table));
        for (side, filter) in [("using", qual), ("check", check)].into_iter().filter_map(|(side, f)| f.as_ref().map(|f| (side, f))) {
            judged.rules.entry(format!("{table}.{name}.{side}")).or_default().push(rows_where(tx, &at, filter));
        }
    }
}

fn judge_views(tx: &mut Transaction<'_>, setup: &Setup<'_>, policies: &[Policy], judged: &mut Judged) -> Result<(), String> {
    let schema = setup.spec.table_schema();
    for table in policies.iter().map(|p| &p.0).collect::<BTreeSet<_>>() {
        let mut sp = tx.savepoint("seen").map_err(|e| why(&e))?;
        sp.batch_execute(&format!("SET LOCAL ROLE {}", ident(&setup.role))).map_err(|e| why(&e))?;
        let got = sp
            .query(&format!("SELECT _row FROM {}.{} ORDER BY _row", ident(schema), ident(table)), &[])
            .map(|rows| rows.iter().map(|r| r.get(0)).collect())
            .map_err(|e| sqlstate(&e));
        sp.rollback().map_err(|e| why(&e))?;
        judged.visible.entry(table.clone()).or_default().push(got);
    }
    Ok(())
}

fn judge_checks(tx: &mut Transaction<'_>, id_type: &str, pools: &Pools, checks: &[String], claims: &str, judged: &mut Judged) -> Result<(), String> {
    for check in checks {
        let name = check.split('(').next().unwrap_or(check);
        let mut answers = Vec::new();
        for id in &pools.ids {
            let mut sp = tx.savepoint("point_check").map_err(|e| why(&e))?;
            let got = sp
                .query_one(&format!("SELECT {name}($1::text::{id_type}, $2::text::jsonb)::text"), &[id, &claims])
                .map(|r| r.get::<_, Option<String>>(0).unwrap_or_default())
                .map_err(|e| sqlstate(&e));
            sp.rollback().map_err(|e| why(&e))?;
            answers.push(got);
        }
        judged.checks.entry(check.clone()).or_default().push(answers.into_iter().collect());
    }
    Ok(())
}

fn judge(db: &mut Client, setup: &Setup<'_>, pools: &Pools, ddl: &str, claims: &[Option<String>]) -> Result<Judged, String> {
    let s = setup.spec;
    let mut tx = db.transaction().map_err(|e| why(&e))?;
    create(&mut tx, setup, pools).map_err(|e| why(&e))?;
    tx.batch_execute(ddl).map_err(|e| why(&e))?;
    let schema = s.table_schema();
    tx.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {schema}, {defs} TO {role}; GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {role}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {defs} TO {role};",
        schema = ident(schema),
        defs = ident(s.definer_schema()),
        role = ident(&setup.role)
    ))
    .map_err(|e| why(&e))?;
    let policies: Vec<Policy> = tx
        .query("SELECT tablename::text, policyname::text, qual, with_check FROM pg_policies WHERE schemaname = $1 ORDER BY 1, 2", &[&schema])
        .map_err(|e| why(&e))?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    let checks: Vec<String> = tx
        .query(
            "SELECT p.oid::regprocedure::text FROM pg_proc p WHERE p.pronamespace = to_regnamespace($1) AND p.pronargs = 2 AND p.proargtypes[1] = 'jsonb'::regtype AND p.prorettype = 'boolean'::regtype ORDER BY 1",
            &[&s.definer_schema()],
        )
        .map_err(|e| why(&e))?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut judged = Judged::default();
    let found = Found { policies, checks };
    for set in claims {
        if let Some(json) = set {
            tx.execute("SELECT set_config($1, $2, true)", &[&setup.setting, json]).map_err(|e| why(&e))?;
        }
        judge_rules(&mut tx, schema, &found.policies, &mut judged);
        judge_views(&mut tx, setup, &found.policies, &mut judged)?;
        judge_checks(&mut tx, s.id_type(), pools, &found.checks, set.as_deref().unwrap_or("{}"), &mut judged)?;
    }
    tx.rollback().map_err(|e| why(&e))?;
    Ok(judged)
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn specs() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut dirs = vec![root().join("examples"), root().join("testdata/corpus/fixtures")];
    while let Some(dir) = dirs.pop() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir).expect("the spec directory reads").map(|e| e.expect("a directory entry").path()).collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                dirs.push(p);
            } else if p.extension().is_some_and(|e| e == "demesne") {
                let name = p.strip_prefix(root()).expect("under the root").display().to_string();
                out.push((name, std::fs::read_to_string(&p).expect("the spec reads")));
            }
        }
    }
    out.sort();
    out
}

fn ddl_now(src: &str) -> Option<(Spec, String)> {
    let s = demesne_syntax::parse(src).ok()?;
    demesne_emit_sql::validate(&s).ok()?;
    let mut ddl = String::new();
    demesne_emit_sql::Sql::new(&s).write_all_sql(&mut ddl).ok()?;
    Some((s, ddl))
}

fn ddl_before(src: &str) -> Option<String> {
    let s = demesne_syntax_v1_1::parse(src).ok()?;
    demesne_emit_sql_v1_1::validate(&s).ok()?;
    let mut ddl = String::new();
    demesne_emit_sql_v1_1::Sql::new(&s).write_all_sql(&mut ddl).ok()?;
    Some(ddl)
}

fn require_env(var: &str) -> String {
    std::env::var(var).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| panic!("set ${var} to run the claim-read checks against a live Postgres"))
}

fn scratch_database(url: &str) -> (Config, String) {
    let mut config: Config = url.parse().expect("$DEMESNE_PG_URL parses");
    let name = format!("{}_claim_reads_{}", config.get_dbname().unwrap_or("demesne"), std::process::id());
    let mut admin = config.connect(NoTls).expect("connect to $DEMESNE_PG_URL");
    let powers: bool = admin.query_one("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user", &[]).expect("the role reads").get(0);
    assert!(powers, "the claim-read checks judge each rule past row security, so $DEMESNE_PG_URL must name a superuser or a BYPASSRLS role");
    admin.batch_execute(&format!("DROP DATABASE IF EXISTS {}", ident(&name))).expect("no scratch database left over");
    admin.batch_execute(&format!("CREATE DATABASE {}", ident(&name))).expect("a scratch database");
    config.dbname(&name);
    (config, name)
}

#[derive(Debug, Default)]
struct Tally {
    specs: usize,
    compared: usize,
    invalid: Vec<String>,
    uninstallable: Vec<String>,
    rules: usize,
    both_ways: usize,
    checks: usize,
    one_way: BTreeMap<String, Vec<String>>,
    differing: Vec<String>,
}

fn varies(outcomes: &[Outcome]) -> bool {
    outcomes.iter().any(|o| o.as_ref().is_ok_and(|rows| !rows.is_empty())) && outcomes.iter().any(|o| o.as_ref().is_ok_and(|rows| rows.len() < ROWS))
}

fn compare_spec(config: &Config, name: &str, src: &str, tally: &mut Tally) {
    tally.specs += 1;
    let Some((s, now)) = ddl_now(src) else {
        tally.invalid.push(name.to_string());
        return;
    };
    let role = "authenticated".to_string();
    let before = ddl_before(src).unwrap_or_else(|| panic!("{name}: the current release emits it, so the earlier one must too"));
    let keys = claim_keys(&[&before, &now]);
    let pools = Pools::new(s.id_type(), &[&before, &now], &keys.all);
    let setting = s.claims.as_ref().map_or_else(|| "request.jwt.claims".to_string(), |c| c.setting.clone());
    let mut setup = Setup { spec: &s, tables: tables_of(&s), setting, role: role.clone() };
    let governed: Vec<String> = s.objects.iter().map(|o| o.table.clone()).collect();
    let mut db = config.connect(NoTls).expect("connect to the scratch database");
    db.batch_execute(&format!(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {}) THEN CREATE ROLE {} NOLOGIN; END IF; END $$",
        literal(&role),
        ident(&role)
    ))
    .expect("the policies' role");
    if let Err(e) = install(&mut db, &mut setup, &pools, &now).and_then(|()| install(&mut db, &mut setup, &pools, &before)) {
        tally.uninstallable.push(format!("{name}: {e}"));
        return;
    }
    let claims = claim_sets(&keys, &pools, &setup.tables, &governed);
    let judged: Vec<Judged> = [&before, &now]
        .into_iter()
        .map(|ddl| {
            let mut fresh = config.connect(NoTls).expect("connect to the scratch database");
            judge(&mut fresh, &setup, &pools, ddl, &claims).unwrap_or_else(|e| panic!("{name}: {e}"))
        })
        .collect();
    let (old, new) = (&judged[0], &judged[1]);
    tally.compared += 1;
    tally.rules += new.rules.len();
    tally.both_ways += new.rules.values().filter(|o| varies(o)).count();
    for (rule, outcomes) in new.rules.iter().filter(|(_, o)| !varies(o)) {
        let how = if outcomes.iter().all(|o| o.as_ref().is_ok_and(Vec::is_empty)) {
            "admits nothing"
        } else if outcomes.iter().all(|o| o.as_ref().is_ok_and(|r| r.len() == ROWS)) {
            "admits everything"
        } else if outcomes.iter().any(Result::is_err) {
            "errs"
        } else {
            "other"
        };
        tally.one_way.entry(how.to_string()).or_default().push(format!("{name} {rule}"));
    }
    tally.checks += new.checks.len();
    assert_eq!(old.rules.keys().collect::<Vec<_>>(), new.rules.keys().collect::<Vec<_>>(), "{name}: the same rules on both sides");
    for (rule, outcomes) in &old.rules {
        if new.rules.get(rule) != Some(outcomes) {
            let at = outcomes.iter().zip(&new.rules[rule]).position(|(a, b)| a != b).unwrap_or(0);
            tally.differing.push(format!("{name}: rule {rule} under claims {:?}: before {:?}, now {:?}", claims[at], outcomes[at], new.rules[rule][at]));
        }
    }
    if old.visible != new.visible {
        tally.differing.push(format!("{name}: the rows the role sees differ"));
    }
    if old.checks != new.checks {
        tally.differing.push(format!("{name}: a point check answers differently"));
    }
}

fn read_per_row(sql: &str) -> String {
    sql.replace("(SELECT current_setting(", "(current_setting(").replace("(SELECT NULLIF(current_setting(", "(NULLIF(current_setting(")
}

#[test]
fn the_sql_differs_from_v1_1_0_only_in_its_claim_reads() {
    let (mut compared, mut refused, mut reads) = (0, 0, 0);
    for (name, src) in specs() {
        match (ddl_now(&src), ddl_before(&src)) {
            (Some((_, now)), Some(before)) => {
                assert_eq!(read_per_row(&now), before, "{name}: the SQL changed beyond its claim reads");
                compared += 1;
                reads += now.matches("(SELECT current_setting(").count() + now.matches("(SELECT NULLIF(current_setting(").count();
            }
            (None, None) => refused += 1,
            (now, before) => panic!("{name}: emitted now {}, by v1.1.0 {}", now.is_some(), before.is_some()),
        }
    }
    assert_eq!((compared, refused), (158, 188), "the specs both releases emit, and those both refuse");
    assert!(reads > compared, "{reads} claim reads over {compared} specs");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn every_rule_admits_the_rows_v1_1_0_admitted() {
    let url = require_env("DEMESNE_PG_URL");
    let (config, name) = scratch_database(&url);
    let mut tally = Tally::default();
    for (spec, src) in specs() {
        compare_spec(&config, &spec, &src, &mut tally);
    }
    let admin: Config = url.parse().expect("$DEMESNE_PG_URL parses");
    admin
        .connect(NoTls)
        .expect("connect to $DEMESNE_PG_URL")
        .batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", ident(&name)))
        .expect("drop the scratch database");
    let mut summary = String::new();
    writeln!(summary, "{tally:#?}").expect("fmt::Write for String never fails");
    assert!(tally.differing.is_empty(), "rules admit different rows:\n{summary}");
    let stuck: Vec<&str> = tally.uninstallable.iter().map(|u| u.split(": ").next().unwrap_or(u)).collect();
    assert_eq!(stuck, UUID_SPECS_WHOSE_DEFINERS_TAKE_TEXT, "the specs whose SQL no schema can hold:\n{summary}");
    assert_eq!(tally.compared + stuck.len(), tally.specs - tally.invalid.len(), "every spec that compiles is compared:\n{summary}");
    assert!(tally.both_ways * 100 >= tally.rules * 85, "too few rules both admitted and refused a row to prove anything:\n{summary}");
}
