use postgres::{Client, NoTls};

const ROWS: &str = "demesne_form_rows";
const AUTH: &str = "demesne_form_auth";
const CALLER: &str = "demesne_form_caller";

const SPEC: &str = "topology { level estate level space parent estate }
vocabulary staff { permission docs:read permission docs:write preset editor @ space = docs:read }
rolestore staff {
  assignments role_grants
  subject     grantee_id
  scope       estate_id space_id
  rolejoin    role_id roles id key
  permissions permissions
  form claim channel = \"draft\" base
  form claim channel = \"live\" permissions live_permissions
  absent claim reads \"live\"
  unversioned estate_id null
  active disabled_at null
}
subject staff { anchor estate; reach descendants; identifies sub; roles configurable staff; binds admin }
object doc {
  table docs
  scoped estate > space wildcard
  permission view = @holds(docs:read) @rls maps select
  permission edit = @holds(docs:write) and @holds(docs:read) @rls maps update
}
object note {
  table notes
  scoped estate > space wildcard
  relation member: staff via role
  permission view = member @rls maps select
}
";

type Role = (&'static str, Option<&'static str>, &'static [&'static str], Option<&'static [&'static str]>);

const READ: &[&str] = &["docs:read"];
const BOTH: &[&str] = &["docs:read", "docs:write"];

const ROLES: [Role; 6] = [
    ("never_released", Some("e1"), BOTH, None),
    ("released", Some("e1"), READ, Some(READ)),
    ("released_then_edited", Some("e1"), BOTH, Some(READ)),
    ("released_wider_than_the_draft", Some("e1"), READ, Some(BOTH)),
    ("released_with_nothing", Some("e1"), BOTH, Some(&[])),
    ("unversioned", None, BOTH, None),
];

const CHANNELS: [Option<&str>; 4] = [None, Some("draft"), Some("live"), Some("other")];

fn form((_, estate, base, live): Role, disabled: bool, channel: Option<&str>) -> Option<&'static [&'static str]> {
    if disabled {
        return None;
    }
    if estate.is_none() {
        return Some(base);
    }
    match channel.unwrap_or("live") {
        "draft" => Some(base),
        "live" => live,
        _ => None,
    }
}

fn install(db: &mut Client) {
    let s = demesne_syntax::parse(&format!("definers schema \"{AUTH}\"\ntables schema \"{ROWS}\"\n{SPEC}")).expect("the spec parses");
    demesne_emit_sql::validate(&s).expect("the spec validates");
    let sql = demesne_emit_sql::Sql::new(&s);
    let (defs, rls) = (sql.emit_definers().expect("the definers compile"), sql.emit_rls().expect("the policies compile"));
    assert_eq!(rls.unsupported, [] as [String; 0]);
    db.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {ROWS} CASCADE; DROP SCHEMA IF EXISTS {AUTH} CASCADE; CREATE SCHEMA {ROWS}; CREATE SCHEMA {AUTH};
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CALLER}') THEN CREATE ROLE {CALLER} NOLOGIN; END IF; END $$;
         SET search_path = {ROWS};
         CREATE TABLE roles (id text PRIMARY KEY, key text, estate_id text, permissions text[], live_permissions text[], disabled_at timestamptz);
         CREATE TABLE role_grants (grantee_id text, estate_id text, space_id text, role_id text);
         CREATE TABLE docs (id text PRIMARY KEY, estate_id text, space_id text, body text);
         CREATE TABLE notes (id text PRIMARY KEY, estate_id text, space_id text);
         INSERT INTO docs VALUES ('d1', 'e1', NULL, 'first');
         INSERT INTO notes VALUES ('n1', 'e1', 's1');
         RESET search_path;"
    ))
    .expect("fresh schemas and tables");
    for stmt in [demesne_emit_sql::definers_sql(&defs), rls.enablement_sql(), rls.policy_sql(CALLER)] {
        db.batch_execute(&stmt).unwrap_or_else(|e| panic!("apply: {e}\n{stmt}"));
    }
    db.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA {ROWS}, {AUTH} TO {CALLER}; GRANT SELECT, UPDATE ON {ROWS}.docs, {ROWS}.notes TO {CALLER}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {AUTH} TO {CALLER}; SET search_path = {ROWS};"
    ))
    .expect("grants");
    for (name, estate, base, live) in ROLES {
        for disabled in [false, true] {
            let id = format!("{name}{}", if disabled { ":disabled" } else { "" });
            let (base, live): (Vec<&str>, Option<Vec<&str>>) = (base.to_vec(), live.map(<[&str]>::to_vec));
            db.execute("INSERT INTO roles VALUES ($1, 'editor', $2, $3, $4, CASE WHEN $5 THEN now() END)", &[&id, &estate, &base, &live, &disabled])
                .expect("a role");
            db.execute("INSERT INTO role_grants VALUES ($1, 'e1', NULL, $1), ($1, 'e1', 's1', $1)", &[&id]).expect("the assignments");
        }
    }
}

fn counted(db: &mut Client, who: &str, channel: Option<&str>, statement: &str) -> u64 {
    let mut tx = db.transaction().expect("a transaction");
    tx.batch_execute(&format!("SET LOCAL ROLE {CALLER}")).expect("the caller role");
    let channel = channel.map(|c| format!(",\"channel\":\"{c}\"")).unwrap_or_default();
    tx.execute("SELECT set_config('request.jwt.claims', $1, true)", &[&format!("{{\"sub\":\"{who}\",\"estate_id\":\"e1\",\"space_id\":\"s1\"{channel}}}")])
        .expect("the claims");
    let n = tx.execute(statement, &[]).unwrap_or_else(|e| panic!("{statement}: {e}"));
    tx.rollback().expect("rollback");
    n
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn a_role_is_read_in_the_form_the_sessions_claim_picks() {
    let url = std::env::var("DEMESNE_PG_URL").ok().filter(|v| !v.is_empty()).expect("set $DEMESNE_PG_URL to run the role form checks against a live Postgres");
    let mut db = Client::connect(&url, NoTls).expect("connect to $DEMESNE_PG_URL");
    install(&mut db);
    let mut outcomes = [[0, 0]; 3];
    for role in ROLES {
        for disabled in [false, true] {
            let who = format!("{}{}", role.0, if disabled { ":disabled" } else { "" });
            for channel in CHANNELS {
                let held = form(role, disabled, channel);
                let can = |perm: &str| held.is_some_and(|perms| perms.contains(&perm));
                let checks = [
                    ("reads by a permission", "SELECT id FROM docs", can("docs:read")),
                    ("writes by a permission", "UPDATE docs SET body = 'second'", can("docs:read") && can("docs:write")),
                    ("reads by the role's name", "SELECT id FROM notes", held.is_some()),
                ];
                let got = checks.map(|(_, statement, _)| counted(&mut db, &who, channel, statement) == 1);
                assert_eq!(got, checks.map(|(_, _, want)| want), "{who} on channel {channel:?}: {:?}", checks.map(|(what, ..)| what));
                checks.iter().enumerate().for_each(|(i, (.., want))| outcomes[i][usize::from(*want)] += 1);
            }
        }
    }
    assert!(outcomes.iter().all(|o| o[0] > 0 && o[1] > 0), "each check is both admitted and refused: {outcomes:?}");
    assert_eq!(outcomes.iter().flatten().sum::<i32>(), 6 * 2 * 4 * 3);

    assert_eq!(
        counted(&mut db, "released_then_edited", None, "UPDATE docs SET body = 'second'"),
        0,
        "a session that says nothing is not handed what was never released"
    );
    assert_eq!(counted(&mut db, "released_then_edited", Some("draft"), "UPDATE docs SET body = 'second'"), 1);
    db.batch_execute(&format!("RESET search_path; DROP SCHEMA {ROWS} CASCADE; DROP SCHEMA {AUTH} CASCADE;")).expect("drop the schemas");
}
