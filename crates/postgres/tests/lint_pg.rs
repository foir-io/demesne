use demesne_postgres::{Severity, schema_traps};
use postgres::{Client, NoTls};

const SCHEMA: &str = r#"
DROP SCHEMA IF EXISTS d16 CASCADE; CREATE SCHEMA d16;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'd16_reader') THEN CREATE ROLE d16_reader NOLOGIN; END IF; END $$;
CREATE TABLE d16.docs (id uuid PRIMARY KEY, tenant text NOT NULL, ws text, owner text, title text, meta jsonb);
CREATE TABLE d16.other (id text, "odd{ name)" text);
ALTER TABLE d16.docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION d16.can_read(p_id uuid) RETURNS boolean LANGUAGE sql STABLE AS 'SELECT true';
CREATE POLICY clean ON d16.docs FOR SELECT USING (
  tenant = current_setting('app.tenant', true)
  AND (owner = current_setting('app.uid', true) OR d16.can_read(id) OR ws = ANY (string_to_array(current_setting('app.ws', true), ',')))
  AND EXISTS (SELECT 1 FROM d16.other o WHERE coalesce(o.id, '') = owner)
  AND coalesce((SELECT o.id FROM d16.other o LIMIT 1), '') = owner
);
CREATE VIEW d16.invoker_view WITH (security_invoker = true) AS SELECT * FROM d16.docs;
CREATE VIEW d16.unrelated AS SELECT * FROM d16.other;
CREATE UNIQUE INDEX docs_tenant_title ON d16.docs (tenant, title);
CREATE UNIQUE INDEX docs_meta ON d16.docs (tenant, ws, meta) NULLS NOT DISTINCT;
CREATE UNIQUE INDEX docs_code ON d16.docs (tenant, ws, (meta ->> 'code'));
CREATE UNIQUE INDEX docs_code_shared ON d16.docs (tenant, (meta ->> 'code')) WHERE ws IS NULL;
CREATE UNIQUE INDEX docs_owner_shared ON d16.docs (tenant, owner) WHERE ws IS NULL;
CREATE UNIQUE INDEX docs_ws_id ON d16.docs (ws, id);
"#;

const TRAPS: &str = r#"
CREATE VIEW d16.owner_view AS SELECT * FROM d16.docs;
CREATE VIEW d16.reader_view AS SELECT id FROM d16.docs;
ALTER VIEW d16.reader_view OWNER TO d16_reader;
CREATE VIEW d16.stacked AS SELECT * FROM d16.invoker_view;
CREATE MATERIALIZED VIEW d16.snapshot AS SELECT * FROM d16.docs;
CREATE UNIQUE INDEX docs_title ON d16.docs (tenant, ws, title);
CREATE UNIQUE INDEX docs_slug ON d16.docs (tenant, ws, (meta ->> 'slug'));
CREATE UNIQUE INDEX docs_slug_other ON d16.docs (tenant, (meta ->> 'other')) WHERE ws IS NULL;
CREATE UNIQUE INDEX docs_tenant_other ON d16.docs (tenant, (meta ->> 'other'));
CREATE UNIQUE INDEX docs_owner_titled ON d16.docs (owner) WHERE title IS NOT NULL;
CREATE UNIQUE INDEX docs_ws_owner ON d16.docs (ws, owner);
CREATE POLICY wrapped ON d16.docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM d16.other o WHERE o."odd{ name)" = 'q')
  OR coalesce(owner, '') = current_setting('app.uid', true)
  OR nullif(ws, '') = current_setting('app.ws', true)
  OR (CASE WHEN title IS NULL THEN '' ELSE title END) = 'x'
  OR id::text = current_setting('app.id', true)
  OR lower(title) = 'y'
  OR meta ->> 'tenant' = current_setting('app.tenant', true)
);
CREATE POLICY ins ON d16.docs FOR INSERT WITH CHECK (upper(tenant) = 'T');
"#;

fn connect() -> Client {
    let url = std::env::var("DEMESNE_PG_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| panic!("set $DEMESNE_PG_URL to run the schema lints against a live Postgres"));
    Client::connect(&url, NoTls).expect("connect")
}

fn traps(db: &mut Client) -> Vec<(Severity, String)> {
    let scope = [("d16.docs".to_string(), "tenant".to_string()), ("d16.docs".to_string(), "ws".to_string())];
    schema_traps(db, &["d16.docs".to_string()], &scope)
        .expect("the lints run")
        .into_iter()
        .map(|t| (t.severity, t.message.split(", so").next().unwrap_or_default().to_string()))
        .collect()
}

#[test]
#[ignore = "needs DEMESNE_PG_URL; run with -- --ignored"]
fn check_finds_each_schema_trap_around_a_governed_table() {
    let mut db = connect();
    db.batch_execute(SCHEMA).expect("the schema");
    assert_eq!(
        traps(&mut db),
        [],
        "invoker views, NOT NULL or NULLS NOT DISTINCT keys, a mirrored NULL tier, a key the primary key already makes unique, bare comparisons and a definer call are all clean"
    );

    db.batch_execute(TRAPS).expect("the traps");
    let w = |s: &str| (Severity::Warning, s.to_string());
    let d = |s: &str| (Severity::Danger, s.to_string());
    assert_eq!(
        traps(&mut db),
        [
            d("view d16.owner_view over governed d16.docs reads as its owner postgres, who bypasses row level security"),
            w("view d16.reader_view over governed d16.docs reads as its owner d16_reader"),
            d("materialized view d16.snapshot over governed d16.docs holds the rows read at refresh by its owner postgres, who bypasses row level security"),
            d("view d16.stacked over governed d16.docs reads as its owner postgres, who bypasses row level security"),
            w("unique index d16.docs_slug on d16.docs includes the nullable scope column ws without NULLS NOT DISTINCT"),
            w("unique index d16.docs_ws_owner on d16.docs includes the nullable scope column ws without NULLS NOT DISTINCT"),
            w("policy ins on d16.docs compares tenant through upper()"),
            w("policy wrapped on d16.docs compares id through a cast through text"),
            w("policy wrapped on d16.docs compares ws through NULLIF"),
            w("policy wrapped on d16.docs compares owner through COALESCE"),
            w("policy wrapped on d16.docs compares title through CASE"),
            w("policy wrapped on d16.docs compares title through lower()"),
            w("policy wrapped on d16.docs compares meta through the operator ->>"),
        ]
    );
}
