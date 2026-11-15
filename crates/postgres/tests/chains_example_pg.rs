use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const ROWS: &str = "demesne_chains_example_rows";
const AUTH: &str = "demesne_chains_example_auth";
const CALLER: &str = "demesne_chains_example_caller";

const TABLES: &str = "
CREATE TABLE docs (id text PRIMARY KEY, estate_id text NOT NULL, rules_live text[] NOT NULL);
CREATE TABLE rule_slots (rule text, role text, kind text, param text);
CREATE TABLE doc_shares (member_id text, doc_id text, rule text);
CREATE TABLE doc_terms (doc_id text, rule text, term text, op text, num double precision, txt text, at timestamptz);
CREATE TABLE doc_lends (borrower_id text, lender_id text, field text, trail text);
CREATE TABLE trail_hops (trail text, doc_id text, rule text, kind text, field text);
CREATE TABLE spaces (id text PRIMARY KEY, estate_id text NOT NULL);
CREATE TABLE roles (id text PRIMARY KEY, key text, permissions text[]);
CREATE TABLE role_grants (id text PRIMARY KEY, principal_kind text, principal_id text, estate_id text, space_id text, role_id text, revoked_at timestamptz);
CREATE TABLE keeper_profiles (id text PRIMARY KEY, estate_id text NOT NULL);
CREATE TABLE folders (id text PRIMARY KEY, estate_id text NOT NULL, space_id text NOT NULL, parent_id text);
CREATE TABLE paths (ancestor_id text NOT NULL, descendant_id text NOT NULL, space_id text NOT NULL, depth integer NOT NULL, PRIMARY KEY (ancestor_id, descendant_id));
CREATE TABLE skins (id text PRIMARY KEY, estate_id text NOT NULL, space_id text NOT NULL, folder_id text, status text NOT NULL);
CREATE TABLE banners (id text PRIMARY KEY, estate_id text NOT NULL, space_id text NOT NULL, skin_id text);";

const SEED: &str = "
INSERT INTO rule_slots VALUES ('read.share', 'require', 'share', ''), ('read.lend', 'require', 'lend', 'f1');
INSERT INTO docs VALUES ('d_own', 'e1', '{read.share}'), ('d_lent', 'e1', '{read.lend}'), ('d_terms', 'e1', '{read.share}'), ('d_far', 'e2', '{read.share}');
INSERT INTO doc_shares VALUES ('ann', 'd_own', 'read.share'), ('ann', 'd_terms', 'read.share'), ('ann', 'd_far', 'read.share');
INSERT INTO doc_terms VALUES ('d_terms', 'read.share', 'team', 'eq', NULL, 'red', NULL);
INSERT INTO doc_lends VALUES ('d_lent', 'd_own', 'f1', 'lend:d_lent:d_own');
INSERT INTO spaces VALUES ('s1', 'e1'), ('s2', 'e1');
INSERT INTO roles VALUES ('r1', 'space_keeper', '{docs:read}');
INSERT INTO role_grants VALUES ('g1', 'keeper', 'kay', 'e1', 's1', 'r1', NULL), ('g2', 'keeper', 'kim', 'e1', 's1', 'r1', NULL), ('g3', 'keeper', 'ken', 'e1', 's2', 'r1', NULL);
INSERT INTO keeper_profiles VALUES ('kay', 'e1'), ('kim', 'e1'), ('ken', 'e1');
INSERT INTO folders VALUES ('a', 'e1', 's1', NULL);
INSERT INTO folders VALUES ('b', 'e1', 's1', 'a');
INSERT INTO skins VALUES ('sk_a', 'e1', 's1', 'a', 'live'), ('sk_b', 'e1', 's1', 'b', 'retired');
INSERT INTO banners VALUES ('bn_a', 'e1', 's1', 'sk_a'), ('bn_b', 'e1', 's1', 'sk_b');";

const ANN: &str = r#"{"sub":"ann","estate_id":"e1","rules_held":["read.share","read.lend"],"facts":{"team":"red"}}"#;
const ANN_ON_BLUE: &str = r#"{"sub":"ann","estate_id":"e1","rules_held":["read.share","read.lend"],"facts":{"team":"blue"}}"#;
const ANN_WITH_NO_TEAM: &str = r#"{"sub":"ann","estate_id":"e1","rules_held":["read.share","read.lend"],"facts":{}}"#;
const ANN_HOLDING_SHARES: &str = r#"{"sub":"ann","estate_id":"e1","rules_held":["read.share"],"facts":{"team":"red"}}"#;
const BOB: &str = r#"{"sub":"bob","estate_id":"e1","rules_held":["read.share","read.lend"],"facts":{"team":"red"}}"#;
const KAY: &str = r#"{"sub":"kay","estate_id":"e1"}"#;
const KAY_IN_S1: &str = r#"{"sub":"kay","estate_id":"e1","space_id":"s1"}"#;
const KEN_IN_S2: &str = r#"{"sub":"ken","estate_id":"e1","space_id":"s2"}"#;
const AT_A: &str = r#"{"sub":"ann","estate_id":"e1","space_id":"s1","folder_id":"a"}"#;
const AT_B: &str = r#"{"sub":"ann","estate_id":"e1","space_id":"s1","folder_id":"b"}"#;
const IN_S1: &str = r#"{"sub":"ann","estate_id":"e1","space_id":"s1"}"#;

const CELLS: [(&str, &str, &[&str], &str); 16] = [
    ("docs", ANN, &["d_own", "d_lent", "d_terms"], "her shares, the doc lent from one she reads, and the doc whose stored condition her claim meets"),
    ("docs", ANN_ON_BLUE, &["d_own", "d_lent"], "the stored condition is decided false"),
    ("docs", ANN_WITH_NO_TEAM, &["d_own", "d_lent"], "the stored condition cannot be decided, so it does not admit"),
    ("docs", ANN_HOLDING_SHARES, &["d_own", "d_terms"], "a rule the credential does not hold is never tried, so the chain is not followed"),
    ("docs", BOB, &[], "no share, so nothing at the end of the chain either"),
    ("spaces", KAY, &["s1"], "the space she keeps"),
    ("spaces", KEN_IN_S2, &["s2"], "the space he keeps"),
    ("spaces", ANN, &[], "she keeps no space"),
    ("keeper_profiles", KAY, &["kay"], "her own profile, standing in no space"),
    ("keeper_profiles", KAY_IN_S1, &["kay", "kim"], "the keepers of the space she stands in"),
    ("keeper_profiles", KEN_IN_S2, &["ken"], "the keepers of the space he stands in"),
    ("keeper_profiles", IN_S1, &["kay", "kim"], "the keepers of the space the caller stands in, whoever the caller is"),
    ("keeper_profiles", ANN, &[], "standing in no space, a caller who keeps none sees no keeper"),
    ("banners", AT_A, &["bn_a"], "the live skin at her folder"),
    ("banners", AT_B, &["bn_a"], "her folder's own skin is retired, so the nearest live one above serves"),
    ("banners", IN_S1, &["bn_a", "bn_b"], "confined to no folder, she is outside the floor"),
];

fn connect() -> Client {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the example's checks against a live Postgres");
    Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL")
}

fn install(db: &mut Client) {
    let path = format!("{}/../../examples/chains.demesne", env!("CARGO_MANIFEST_DIR"));
    let example = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let s = demesne_syntax::parse(&format!("definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\n{example}")).expect("the example parses");
    demesne_emit_sql::validate(&s).expect("the example validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    assert_eq!(rls.unsupported, [] as [String; 0]);
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS}; {TABLES} RESET search_path;"
    ))
    .expect("fresh schemas and tables");
    for stmt in [demesne_emit_sql::definers_sql(&defs), sql.triggers_sql(), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT ON {ROWS}.docs, {ROWS}.spaces, {ROWS}.keeper_profiles, {ROWS}.skins, {ROWS}.banners TO {CALLER}; SET search_path = {ROWS}; {SEED}"
    ))
    .expect("grants and rows");
}

fn read(db: &mut Client, claims: &str, sql: &str) -> BTreeSet<String> {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&claims]).expect("the claims");
    let got = tx.query(sql, &[]).unwrap_or_else(|e| panic!("{sql}: {e}")).iter().map(|r| r.get(0)).collect();
    tx.rollback().expect("rollback");
    got
}

fn is_member(db: &mut Client, claims: &str, principal: &str, space: &str) -> bool {
    !read(db, claims, &format!("SELECT 'yes' WHERE {AUTH}.keeper_memberin_space('{principal}', '{space}')")).is_empty()
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn the_chains_example_admits_whom_its_rules_say() {
    let mut db = connect();
    install(&mut db);
    let (mut admitted, mut refused) = (0, 0);
    for (table, claims, wanted, why) in CELLS {
        let total: i64 = db.query_one(&format!("SELECT count(*) FROM {table}"), &[]).expect("the rows").get(0);
        let wanted: BTreeSet<String> = wanted.iter().map(ToString::to_string).collect();
        assert_eq!(read(&mut db, claims, &format!("SELECT id FROM {table}")), wanted, "{table} as {claims}: {why}");
        admitted += wanted.len();
        refused += usize::try_from(total).expect("a count") - wanted.len();
    }
    eprintln!("chains example: {} cells, {admitted} rows admitted, {refused} refused", CELLS.len());

    db.batch_execute("DELETE FROM doc_shares WHERE member_id = 'ann' AND doc_id = 'd_own'").expect("end the share");
    assert_eq!(read(&mut db, ANN, "SELECT id FROM docs"), BTreeSet::from(["d_terms".to_string()]), "the chain ends with the share at its far end");
    db.batch_execute("UPDATE skins SET status = 'retired' WHERE id = 'sk_a'").expect("retire the skin");
    assert_eq!(read(&mut db, AT_B, "SELECT id FROM banners"), BTreeSet::new(), "with no live skin at or above the folder the floor admits nothing");

    for (claims, principal, space, wanted, why) in [
        (KAY, "kay", "s1", true, "her own membership"),
        (KAY, "kim", "s1", false, "another keeper, asked from no space"),
        (KAY_IN_S1, "kim", "s1", true, "another keeper of the space she stands in, as the profile rule shows her"),
        (KAY_IN_S1, "ken", "s2", false, "another keeper of another space"),
        (KEN_IN_S2, "kay", "s1", false, "another keeper of another space"),
    ] {
        assert_eq!(is_member(&mut db, claims, principal, space), wanted, "{claims} asks whether {principal} keeps {space}: {why}");
    }
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
