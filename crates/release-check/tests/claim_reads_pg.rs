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
    tree.leaves_deep()
}

fn term_cols(t: &mut Tables, s: &Spec, o: &Object, term: &Term) {
    let table = o.table.as_str();
    if let Some(m) = term.mode_col() {
        t.col(table, m, Kind::Text);
    }
    if let Some(scope) = term.some_scope() {
        t.col(table, &scope.col, Kind::Perms);
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
            for c in [e.key.as_deref(), e.filter.as_ref().map(|f| f.0.as_str()), e.slot.as_ref().map(|f| f.0.as_str())].into_iter().flatten() {
                t.col(&e.table, c, Kind::Text);
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
        Repr::Role | Repr::Conditions(_) => {}
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
        "GRANT USAGE ON SCHEMA {schema}, {defs} TO {role}; GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {role};",
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

const SPECS_V1_1_0_CANNOT_PARSE: [&str; 3] = ["examples/chains.demesne", "examples/changelog.demesne", "examples/tree.demesne"];

const SPECS_WHERE_TERMS_NOW_BIND_A_GRANTS_REACH: [&str; 8] = [
    "testdata/corpus/fixtures/1f18a238f968d83f.demesne",
    "testdata/corpus/fixtures/26584f0e4c9ae6a1.demesne",
    "testdata/corpus/fixtures/26ecf6f96c07e480.demesne",
    "testdata/corpus/fixtures/38d02b53bac27607.demesne",
    "testdata/corpus/fixtures/66e5cc6fd058fb60.demesne",
    "testdata/corpus/fixtures/7b734f125d1f2f8a.demesne",
    "testdata/corpus/fixtures/9f89b69b6515b612.demesne",
    "testdata/corpus/fixtures/fdf0cc61cbd9ee98.demesne",
];

fn terms_now_bind_a_reach(name: &str) -> bool {
    SPECS_WHERE_TERMS_NOW_BIND_A_GRANTS_REACH.contains(&name)
}

fn admits_no_row_more(before: &[Outcome], now: &[Outcome]) -> bool {
    before.len() == now.len()
        && before.iter().zip(now).all(|(b, n)| match (b, n) {
            (Ok(b), Ok(n)) => n.iter().all(|row| b.contains(row)),
            (b, n) => b == n,
        })
}

fn specs() -> Vec<(String, String)> {
    every_spec().into_iter().filter(|(name, _)| !SPECS_V1_1_0_CANNOT_PARSE.contains(&name.as_str())).collect()
}

fn every_spec() -> Vec<(String, String)> {
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

fn ddl_v4(src: &str) -> Option<(String, Option<demesne_emit_sql::Manifest>)> {
    let s = demesne_syntax_v4::parse(src).ok()?;
    demesne_emit_sql_v4::validate(&s).ok()?;
    let sql = demesne_emit_sql_v4::Sql::new(&s);
    let mut ddl = String::new();
    sql.write_all_sql(&mut ddl).ok()?;
    let manifest = sql.manifest().ok().map(|m| demesne_emit_sql::Manifest::from_json(&m.to_json()).expect("v5.0.0 reads v4.0.0's manifest"));
    Some((ddl, manifest))
}

fn upgrade_by_diff(url: &str, name: &str, src: &str) -> usize {
    let ((s, now), (v4, _)) = (ddl_now(src).expect("v5.0.0 emits it"), ddl_v4(src).expect("v4.0.0 emits it"));
    let keys = claim_keys(&[&v4, &now]);
    let pools = Pools::new(s.id_type(), &[&v4, &now], &keys.all);
    let setting = s.claims.as_ref().map_or_else(|| "request.jwt.claims".to_string(), |c| c.setting.clone());
    let mut setup = Setup { spec: &s, tables: tables_of(&s), setting, role: "authenticated".to_string() };
    let (config, scratch) = scratch_database(url, "upgrade_by_diff");
    let mut db = config.connect(NoTls).expect("connect to the scratch database");
    install(&mut db, &mut setup, &pools, &format!("{v4}\n{now}")).unwrap_or_else(|e| panic!("{name}: {e}"));
    let mut tx = db.transaction().expect("a transaction");
    create(&mut tx, &setup, &pools).unwrap_or_else(|e| panic!("{name}: the tables: {}", why(&e)));
    tx.commit().expect("the tables");
    db.batch_execute(&v4).unwrap_or_else(|e| panic!("{name}: v4.0.0's SQL: {}", why(&e)));
    db.batch_execute(&now).unwrap_or_else(|e| panic!("{name}: v5.0.0's SQL: {}", why(&e)));
    let current = demesne_emit_sql::Sql::new(&s).manifest().unwrap_or_else(|e| panic!("{name}: {e}"));
    let v4_made = demesne_emit_sql::Manifest::from_sql(&v4).unwrap_or_else(|e| panic!("{name}: {e}")).functions;
    let left: BTreeSet<String> = v4_made.difference(&current.functions).map(|f| f.replace(", ", ",")).collect();
    let found = demesne_postgres::drift(&mut db, &now, &[]).unwrap_or_else(|e| panic!("{name}: diff: {e}"));
    let orphans: BTreeSet<String> = found.findings.iter().filter_map(|f| f.object.strip_prefix("function ").map(str::to_string)).collect();
    assert_eq!(orphans, left, "{name}: diff names each function v4.0.0 made and v5.0.0 does not: {:#?}", found.findings);
    assert_eq!(found.findings.len(), left.len(), "{name}: diff finds nothing else: {:#?}", found.findings);
    for f in &orphans {
        db.batch_execute(&format!("DROP FUNCTION {f}")).unwrap_or_else(|e| panic!("{name}: drop {f}: {}", why(&e)));
    }
    let after = demesne_postgres::drift(&mut db, &now, &[]).unwrap_or_else(|e| panic!("{name}: diff: {e}"));
    assert_eq!(after.findings, [], "{name}: diff is clean once the orphans are dropped");
    drop(db);
    let mut admin: Client = url.parse::<Config>().expect("$DEMESNE_PG_URL parses").connect(NoTls).expect("connect");
    admin.batch_execute(&format!("DROP DATABASE IF EXISTS {}", ident(&scratch))).expect("drop the scratch database");
    left.len()
}

fn upgrade_from_v4(config: &Config, name: &str, src: &str) -> Option<(usize, usize)> {
    let ((s, now), (v4, Some(previous))) = (ddl_now(src)?, ddl_v4(src)?) else { return None };
    let keys = claim_keys(&[&v4, &now]);
    let pools = Pools::new(s.id_type(), &[&v4, &now], &keys.all);
    let setting = s.claims.as_ref().map_or_else(|| "request.jwt.claims".to_string(), |c| c.setting.clone());
    let mut setup = Setup { spec: &s, tables: tables_of(&s), setting, role: "authenticated".to_string() };
    let mut db = config.connect(NoTls).expect("connect to the scratch database");
    install(&mut db, &mut setup, &pools, &now).unwrap_or_else(|e| panic!("{name}: {e}"));
    let current = demesne_emit_sql::Sql::new(&s).manifest().unwrap_or_else(|e| panic!("{name}: {e}"));
    let migration = demesne_emit_sql::Sql::new(&s).migration(&previous).unwrap_or_else(|e| panic!("{name}: {e}"));
    let mut tx = db.transaction().expect("a transaction");
    create(&mut tx, &setup, &pools).unwrap_or_else(|e| panic!("{name}: the tables: {}", why(&e)));
    tx.batch_execute(&v4).unwrap_or_else(|e| panic!("{name}: v4.0.0's SQL: {}", why(&e)));
    tx.batch_execute(&migration).unwrap_or_else(|e| panic!("{name}: the migration: {}", why(&e)));
    let live = |tx: &mut Transaction<'_>, f: &str| -> bool { tx.query_one("SELECT to_regprocedure($1) IS NOT NULL", &[&f]).expect("the lookup").get(0) };
    let gone: Vec<&String> = previous.functions.iter().filter(|f| !current.functions.contains(*f)).collect();
    for f in &gone {
        assert!(!live(&mut tx, f), "{name}: {f}, which v5.0.0 does not emit, is left after the migration");
    }
    for f in &current.functions {
        assert!(live(&mut tx, f), "{name}: {f} is missing after the migration");
    }
    let searches_pg_temp_last = |tx: &mut Transaction<'_>, f: &str| -> bool {
        tx.query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_proc p, unnest(p.proconfig) c WHERE p.oid = to_regprocedure($1) AND c LIKE 'search_path=%, pg_temp')",
            &[&f],
        )
        .expect("the search path")
        .get(0)
    };
    let unsafe_path: Vec<&String> = current.functions.iter().filter(|f| !searches_pg_temp_last(&mut tx, f)).collect();
    assert!(unsafe_path.is_empty(), "{name}: after the migration every function searches pg_temp last: {unsafe_path:?}");
    tx.rollback().expect("rollback");
    Some((gone.len(), current.functions.len()))
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn upgrading_from_v4_0_0_by_migrating_leaves_no_function_v5_0_0_does_not_emit() {
    let url = require_env("DEMESNE_PG_URL");
    let (config, scratch) = scratch_database(&url, "upgrade_by_migrating");
    config
        .connect(NoTls)
        .expect("connect to the scratch database")
        .batch_execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$",
        )
        .expect("the role");
    let (mut specs, mut dropped, mut kept) = (0, 0, 0);
    let mut pruned_example = false;
    let mut by_diff = Vec::new();
    for (name, src) in every_spec().into_iter().filter(|(name, _)| !UUID_SPECS_WHOSE_DEFINERS_TAKE_TEXT.contains(&name.as_str())) {
        if ddl_now(&src).is_some() && matches!(ddl_v4(&src), Some((_, None))) {
            by_diff.push((name, src));
            continue;
        }
        let Some((gone, now)) = upgrade_from_v4(&config, &name, &src) else { continue };
        specs += 1;
        dropped += gone;
        kept += now;
        pruned_example |= name == "examples/example.demesne" && gone > 0;
    }
    eprintln!("v4.0.0 to v5.0.0 by migrating: {specs} specs, {dropped} functions dropped, {kept} kept");
    let mut admin: Client = url.parse::<Config>().expect("$DEMESNE_PG_URL parses").connect(NoTls).expect("connect");
    admin.batch_execute(&format!("DROP DATABASE IF EXISTS {}", ident(&scratch))).expect("drop the scratch database");
    let names: Vec<&str> = by_diff.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["examples/changelog.demesne"], "v4.0.0 writes no manifest for a spec that declares `changelog checked`, and only for that");
    for (name, src) in &by_diff {
        let spare = format!("{src}\nclosure spare_paths(ancestor_id, descendant_id)\n");
        let (orphans, with_spare) = (upgrade_by_diff(&url, name, src), upgrade_by_diff(&url, name, &spare));
        eprintln!("{name}: v4.0.0 to v5.0.0 by diff, {orphans} orphans dropped, {with_spare} with a closure no relation reads");
        assert!(with_spare > 0, "{name}: the functions of a closure no relation reads are orphans diff names");
    }
    assert!(specs > 150 && dropped > 50 && kept > 400, "{specs} specs, {dropped} dropped, {kept} kept");
    assert!(pruned_example, "examples/example.demesne loses has_org_role, among others");
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn specs_with_integer_and_uuid_ids_apply_and_answer_through_every_generator_taking_an_id() {
    let url = require_env("DEMESNE_PG_URL");
    for name in ["testdata/ids/integer.demesne", "testdata/ids/uuid.demesne"] {
        let src = std::fs::read_to_string(root().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let (s, now) = ddl_now(&src).unwrap_or_else(|| panic!("{name}: the spec emits"));
        let keys = claim_keys(&[&now]);
        let pools = Pools::new(s.id_type(), &[&now], &keys.all);
        let setting = s.claims.as_ref().map_or_else(|| "request.jwt.claims".to_string(), |c| c.setting.clone());
        let mut setup = Setup { spec: &s, tables: tables_of(&s), setting, role: "authenticated".to_string() };
        let (config, scratch) = scratch_database(&url, "ids");
        let mut db = config.connect(NoTls).expect("connect to the scratch database");
        db.batch_execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$",
        )
        .expect("the role");
        install(&mut db, &mut setup, &pools, &now).unwrap_or_else(|e| panic!("{name}: the SQL applies on tables of its id type: {e}"));
        let governed: Vec<String> = s.objects.iter().map(|o| o.table.clone()).collect();
        let claims = claim_sets(&keys, &pools, &setup.tables, &governed);
        let judged = judge(&mut db, &setup, &pools, &now, &claims).unwrap_or_else(|e| panic!("{name}: {e}"));
        let outcomes: Vec<&Outcome> = judged.rules.values().chain(judged.visible.values()).flatten().collect();
        let errors: Vec<&String> = outcomes.iter().filter_map(|o| o.as_ref().err()).collect();
        assert!(errors.is_empty(), "{name}: every policy answers: {errors:?}");
        let admitted = outcomes.iter().filter(|o| o.as_ref().is_ok_and(|rows| !rows.is_empty())).count();
        assert!(admitted > 0 && admitted < outcomes.len(), "{name}: the policies both admit and refuse: {admitted} of {}", outcomes.len());
        drop(db);
        let mut admin: Client = url.parse::<Config>().expect("$DEMESNE_PG_URL parses").connect(NoTls).expect("connect");
        admin.batch_execute(&format!("DROP DATABASE IF EXISTS {}", ident(&scratch))).expect("drop the scratch database");
    }
}

fn require_env(var: &str) -> String {
    std::env::var(var).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| panic!("set ${var} to run the claim-read checks against a live Postgres"))
}

fn scratch_database(url: &str, what: &str) -> (Config, String) {
    let mut config: Config = url.parse().expect("$DEMESNE_PG_URL parses");
    let name = format!("{}_{what}_{}", config.get_dbname().unwrap_or("demesne"), std::process::id());
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
    newly_accepted: Vec<String>,
    uninstallable: Vec<String>,
    rules: usize,
    both_ways: usize,
    checks: usize,
    one_way: BTreeMap<String, Vec<String>>,
    differing: Vec<String>,
    narrowed: Vec<String>,
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
    let Some(before) = ddl_before(src) else {
        tally.newly_accepted.push(name.to_string());
        return;
    };
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
    let bound = terms_now_bind_a_reach(name);
    for (rule, outcomes) in &old.rules {
        if new.rules.get(rule) != Some(outcomes) {
            let at = outcomes.iter().zip(&new.rules[rule]).position(|(a, b)| a != b).unwrap_or(0);
            let what = format!("{name}: rule {rule} under claims {:?}: before {:?}, now {:?}", claims[at], outcomes[at], new.rules[rule][at]);
            if bound && admits_no_row_more(outcomes, &new.rules[rule]) {
                tally.narrowed.push(what);
            } else {
                tally.differing.push(what);
            }
        }
    }
    if old.visible != new.visible {
        let narrower = old.visible.len() == new.visible.len()
            && old.visible.iter().all(|(table, before)| new.visible.get(table).is_some_and(|now| admits_no_row_more(before, now)));
        if bound && narrower {
            tally.narrowed.push(format!("{name}: the role sees fewer rows"));
        } else {
            tally.differing.push(format!("{name}: the rows the role sees differ"));
        }
    }
    if old.checks != new.checks {
        if bound {
            tally.narrowed.push(format!("{name}: a point check answers differently"));
        } else {
            tally.differing.push(format!("{name}: a point check answers differently"));
        }
    }
}

fn read_per_row(sql: &str) -> String {
    sql.replace("(SELECT current_setting(", "(current_setting(").replace("(SELECT NULLIF(current_setting(", "(NULLIF(current_setting(")
}

fn calls_per_row(sql: &str) -> String {
    const WRAP: &str = "(SELECT ";
    let mut out = sql.to_string();
    let mut from = 0;
    while let Some(found) = out[from..].find(WRAP) {
        let open = from + found;
        let call = open + WRAP.len();
        from = call;
        let name = out[call..].find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')).unwrap_or(0);
        if !out[call..call + name].contains('.') || !out[call + name..].starts_with('(') {
            continue;
        }
        let end = call + name + bound_ends(&out[call + name..]);
        if !out[end..].starts_with(')') {
            continue;
        }
        out.replace_range(end..=end, "");
        out.replace_range(open..call, "");
        from = open;
    }
    out
}

const OWN: [&str; 5] = [" AND user_id = ", " AND user_id IN ", " AND p_node = ", " AND p_node IN ", " AND (p_ancestor "];

fn bound_ends(rest: &str) -> usize {
    let mut depth = 0_usize;
    let mut end = rest.len();
    for (at, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' if depth == 1 => {
                end = at + 1;
                break;
            }
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    while let Some(cast) = rest[end..].strip_prefix("::") {
        end += 2 + cast.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(cast.len());
    }
    end
}

fn guard_start(text: &str, read: usize) -> Option<usize> {
    let head = text[..read].strip_suffix(" = ").or_else(|| text[..read].strip_suffix(" IN ("))?;
    let name = head.len() - head.chars().rev().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').count();
    (name < head.len()).then_some(name)
}

fn without_leading_guards(sql: &str) -> String {
    const READ: &str = "(NULLIF(current_setting(";
    let mut out = sql.to_string();
    let mut from = 0;
    while let Some(found) = out[from..].find(READ) {
        let read = from + found;
        from = read + READ.len();
        let Some(name) = guard_start(&out, read) else { continue };
        let either_side = out[..name].ends_with('(') && out[name - 1 + bound_ends(&out[name - 1..])..].starts_with(" AND (");
        let (start, group) = if either_side { (name - 1, name - 1) } else { (name, if out[..read].ends_with('(') { read - 1 } else { read }) };
        let guarded = group + bound_ends(&out[group..]);
        if !out[guarded..].starts_with(" AND (") {
            continue;
        }
        let open = guarded + " AND ".len();
        let close = open + bound_ends(&out[open..]) - 1;
        out.replace_range(close..=close, "");
        out.replace_range(start..=open, "");
        from = start;
    }
    out
}

fn answering_any_caller(sql: &str, before: &str) -> String {
    let sql = &without_leading_guards(sql);
    let stated_since = |line: &&str| {
        (line.starts_with("REVOKE EXECUTE ON FUNCTION ") || line.starts_with("GRANT EXECUTE ON FUNCTION ")) && !before.lines().any(|kept| kept == *line)
    };
    let mut out = sql.replace(" AND false", "");
    for line in sql.lines().filter(stated_since) {
        out = out.replace(&format!("\n{line}"), "");
    }
    for prefix in OWN {
        while let Some(at) = out.find(prefix) {
            let from = at + prefix.rfind('(').unwrap_or(prefix.len());
            let end = from + bound_ends(&out[from..]);
            out.replace_range(at..end, "");
        }
    }
    out
}

#[test]
fn the_sql_differs_from_v1_1_0_only_in_its_claim_reads_and_in_whose_node_a_set_answers_for() {
    let (mut compared, mut refused, mut reads, mut bound) = (0, 0, 0, 0);
    for (name, src) in specs() {
        match (ddl_now(&src), ddl_before(&src)) {
            (Some((_, now)), Some(before)) => {
                if terms_now_bind_a_reach(&name) {
                    assert_ne!(
                        calls_per_row(&answering_any_caller(&read_per_row(&now), &before)),
                        calls_per_row(&before),
                        "{name}: no term binds a grant's reach here any more"
                    );
                    bound += 1;
                } else {
                    assert_eq!(
                        calls_per_row(&answering_any_caller(&read_per_row(&now), &before)),
                        calls_per_row(&before),
                        "{name}: the SQL changed beyond its claim reads and the callers its sets answer"
                    );
                }
                compared += 1;
                reads += now.matches("(SELECT current_setting(").count() + now.matches("(SELECT NULLIF(current_setting(").count();
            }
            (None, None) => refused += 1,
            (now, before) => panic!("{name}: emitted now {}, by v1.1.0 {}", now.is_some(), before.is_some()),
        }
    }
    assert_eq!((compared, refused), (158, 188), "the specs both releases emit, and those both refuse");
    assert_eq!(bound, SPECS_WHERE_TERMS_NOW_BIND_A_GRANTS_REACH.len(), "every spec listed as changed is in the corpus");
    assert!(reads > compared, "{reads} claim reads over {compared} specs");
}

#[test]
fn a_grant_named_where_it_already_widens_a_level_added_nothing_in_v1_1_0_and_is_refused_now() {
    let name = "testdata/corpus/fixtures/9f89b69b6515b612.demesne";
    let all = every_spec();
    let (_, src) = all.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("{name} is not in the corpus"));
    assert!(!src.contains("+ via grant orgreach"), "{name} no longer names the grant in a permission");
    let plain = "permission view   = owner @rls maps select";
    let at = src.rfind(plain).unwrap_or_else(|| panic!("{name} has the permission the grant was named in"));
    let mut named = src.clone();
    named.replace_range(at..at + plain.len(), "permission view   = owner + via grant orgreach @rls maps select");
    assert_eq!(named.matches("+ via grant orgreach").count(), 1, "the grant is named in one permission");
    assert_eq!(ddl_before(&named), ddl_before(src), "v1.1.0 emitted the same SQL with the grant named and without");
    assert!(ddl_before(src).is_some());
    let s = demesne_syntax::parse(&named).expect("the spec parses");
    let refused = demesne_emit_sql::validate(&s).expect_err("naming the grant there is refused").to_string();
    assert!(refused.contains("`via grant orgreach` adds nothing here") && refused.contains("level \"org\""), "{refused}");
}

#[test]
fn a_spec_left_out_of_the_comparison_is_one_only_this_release_reads() {
    let all = every_spec();
    for name in SPECS_V1_1_0_CANNOT_PARSE {
        let (_, src) = all.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("{name} is not in the corpus"));
        assert!(ddl_now(src).is_some(), "{name}: this release emits it");
        assert!(demesne_syntax_v1_1::parse(src).is_err(), "{name}: v1.1.0 parses it, so it belongs in the comparison");
    }
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn every_rule_admits_the_rows_v1_1_0_admitted() {
    let url = require_env("DEMESNE_PG_URL");
    let (config, name) = scratch_database(&url, "claim_reads");
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
    eprintln!(
        "v1.1.0 differential: {} specs, {} compared, {} rules, {} both admitted and refused a row, {} checks, {} differing, {} narrowed where terms now bind a grant's reach",
        tally.specs,
        tally.compared,
        tally.rules,
        tally.both_ways,
        tally.checks,
        tally.differing.len(),
        tally.narrowed.len()
    );
    assert!(!tally.narrowed.is_empty(), "no rule narrowed, so nothing shows the terms binding a reach:\n{summary}");
    assert!(tally.differing.is_empty(), "rules admit different rows:\n{summary}");
    let stuck: Vec<&str> = tally.uninstallable.iter().map(|u| u.split(": ").next().unwrap_or(u)).collect();
    assert_eq!(stuck, UUID_SPECS_WHOSE_DEFINERS_TAKE_TEXT, "the specs whose SQL no schema can hold:\n{summary}");
    assert_eq!(
        tally.newly_accepted,
        ["testdata/corpus/fixtures/bed6930cc54d3a21.demesne", "testdata/corpus/fixtures/fda4c3fcab458614.demesne"],
        "the specs v1.1.0 refused and this release compiles: a closure relation on an object with no owner subject, refused then for want of the owner's claim:\n{summary}"
    );
    assert_eq!(tally.compared + stuck.len(), tally.specs - tally.invalid.len() - tally.newly_accepted.len(), "every spec both compile is compared:\n{summary}");
    assert!(tally.both_ways * 100 >= tally.rules * 85, "too few rules both admitted and refused a row to prove anything:\n{summary}");
}
