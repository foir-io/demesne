#!/usr/bin/env bash
set -euo pipefail

GO="$1"
RUST="$2"
BASE="$3"
OUT="$4"
ROOT="$(git rev-parse --show-toplevel)"
rm -rf "$OUT"
mkdir -p "$OUT/go" "$OUT/rust" "$OUT/specs"

sql() { psql "$BASE/$1" -v ON_ERROR_STOP=1 -q -X "${@:2}" >/dev/null; }
fresh() {
  psql "$BASE/postgres" -v ON_ERROR_STOP=1 -q -X -c "DROP DATABASE IF EXISTS $1" -c "CREATE DATABASE $1" >/dev/null
}
role() {
  psql "$BASE/postgres" -v ON_ERROR_STOP=1 -q -X -c "DO \$\$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$1') THEN CREATE ROLE $1 NOLOGIN $2; END IF; END\$\$" >/dev/null
}

total=0
same=0
diverged=0
run() {
  local name="$1"
  shift
  total=$((total + 1))
  for side in go rust; do
    local bin="$GO"
    [ "$side" = rust ] && bin="$RUST"
    local rc=0
    env -u DATABASE_URL "$bin" "$@" >"$OUT/$side/$name.out" 2>"$OUT/$side/$name.err" </dev/null || rc=$?
    printf 'exit: %s\n--- stdout ---\n%s\n--- stderr ---\n%s' "$rc" "$(cat "$OUT/$side/$name.out")" "$(cat "$OUT/$side/$name.err")" >"$OUT/$side/$name.txt"
  done
  if cmp -s "$OUT/go/$name.txt" "$OUT/rust/$name.txt"; then
    same=$((same + 1))
  else
    echo "DIFF $name"
    diff "$OUT/go/$name.txt" "$OUT/rust/$name.txt" | head -10 || true
  fi
}

run_driver_error() {
  local name="$1"
  shift
  total=$((total + 1))
  local grc=0 rrc=0
  env -u DATABASE_URL "$GO" "$@" >"$OUT/go/$name.out" 2>"$OUT/go/$name.err" </dev/null || grc=$?
  env -u DATABASE_URL "$RUST" "$@" >"$OUT/rust/$name.out" 2>"$OUT/rust/$name.err" </dev/null || rrc=$?
  if [ "$grc" = "$rrc" ] && cmp -s "$OUT/go/$name.out" "$OUT/rust/$name.out" &&
    head -c 9 "$OUT/go/$name.err" | grep -q '^demesne: ' && head -c 9 "$OUT/rust/$name.err" | grep -q '^demesne: '; then
    diverged=$((diverged + 1))
    echo "NAMED $name: driver error text differs by design"
    echo "  go:   $(cat "$OUT/go/$name.err")"
    echo "  rust: $(cat "$OUT/rust/$name.err")"
  else
    echo "DIFF $name: exit $grc vs $rrc"
  fi
}

role authenticated ""
role bypasser "BYPASSRLS"

fresh demesne_live_example
grep -v '^CREATE ROLE authenticated' "$ROOT/ts/packages/example-app/sql/schema.sql" | sql demesne_live_example
sql demesne_live_example -f "$ROOT/ts/packages/example-app/generated/policies.sql"
EX="$BASE/demesne_live_example"
SPEC="$ROOT/examples/roundtrip.demesne"
run introspect-example introspect "$EX"
run scaffold-example scaffold "$EX"
run check-example check "$SPEC" "$EX"
run diff-example diff "$SPEC" "$EX"
run diff-example-exit diff "$SPEC" "$EX" --exit-code
run coverage-example coverage "$SPEC" "$EX"
run coverage-example-exit coverage --exit-code "$SPEC" "$EX"

fresh demesne_live_drift
grep -v '^CREATE ROLE authenticated' "$ROOT/ts/packages/example-app/sql/schema.sql" | sql demesne_live_drift
sql demesne_live_drift -f "$ROOT/ts/packages/example-app/generated/policies.sql"
sql demesne_live_drift -c "DROP POLICY notes_select ON public.notes" -c "CREATE POLICY rogue ON public.notes FOR SELECT USING (true)" -c "CREATE TABLE stray (id text)"
DR="$BASE/demesne_live_drift"
run diff-drift diff "$SPEC" "$DR"
run diff-drift-exit diff --exit-code "$SPEC" "$DR"
run coverage-drift coverage "$SPEC" "$DR"
run coverage-drift-exit coverage "$SPEC" "$DR" --exit-code

fresh demesne_live_empty
EM="$BASE/demesne_live_empty"
run introspect-empty introspect "$EM"
run scaffold-empty scaffold "$EM"
run check-empty check "$SPEC" "$EM"
run coverage-empty coverage "$SPEC" "$EM"
run diff-empty diff "$SPEC" "$EM"

fresh demesne_live_fk
sql demesne_live_fk -c "
  CREATE TABLE tenants (id text PRIMARY KEY);
  CREATE TABLE projects (id text PRIMARY KEY, tenant_id text REFERENCES tenants(id));
  CREATE TABLE members (id text PRIMARY KEY, tenant_id text REFERENCES tenants(id));
  CREATE TABLE docs (id text PRIMARY KEY, tenant_id text REFERENCES tenants(id), project_id text REFERENCES projects(id), member_id text REFERENCES members(id));
  CREATE TABLE notes (id text PRIMARY KEY, tenant_id text REFERENCES tenants(id), project_id text REFERENCES projects(id));
  CREATE TABLE boards (id text PRIMARY KEY, project_id text REFERENCES projects(id), tenant_id text REFERENCES tenants(id));
  CREATE TABLE cards (id text PRIMARY KEY, project_id text REFERENCES projects(id), member_id text REFERENCES members(id));
  CREATE TABLE audit_log (id bigserial PRIMARY KEY, payload jsonb);
  CREATE TABLE regions (id text PRIMARY KEY);
  CREATE TABLE sites (id text PRIMARY KEY, region_id text REFERENCES regions(id));
  CREATE TABLE racks (id text PRIMARY KEY, region_id text REFERENCES regions(id));
"
FK="$BASE/demesne_live_fk"
run introspect-fk introspect "$FK"
run scaffold-fk scaffold "$FK"
printf 'admin\npublic_v2\napp\n' >"$OUT/specs/answers"
for side in go rust; do
  bin="$GO"
  [ "$side" = rust ] && bin="$RUST"
  rc=0
  env -u DATABASE_URL "$bin" scaffold -i "$FK" <"$OUT/specs/answers" >"$OUT/$side/scaffold-interactive.out" 2>"$OUT/$side/scaffold-interactive.err" || rc=$?
  printf 'exit: %s\n%s\n%s' "$rc" "$(cat "$OUT/$side/scaffold-interactive.out")" "$(cat "$OUT/$side/scaffold-interactive.err")" >"$OUT/$side/scaffold-interactive.txt"
done
total=$((total + 1))
if cmp -s "$OUT/go/scaffold-interactive.txt" "$OUT/rust/scaffold-interactive.txt"; then same=$((same + 1)); else echo "DIFF scaffold-interactive"; diff "$OUT/go/scaffold-interactive.txt" "$OUT/rust/scaffold-interactive.txt" | head -10 || true; fi

cat >"$OUT/specs/bypass.demesne" <<'EOF'
claims via "request.jwt.claims" json role bypasser
topology { level org col org_ref claim org level workspace parent org col ws_ref claim ws }
vocabulary app { permission self:read }
subject member { anchor workspace reach self identifies member_ref roles none binds owner }
object note {
  table notes
  pk note_pk
  scoped org > workspace
  relation owner: member via owner_ref
  permission view = owner @rls maps select
}
EOF
run check-bypass check "$OUT/specs/bypass.demesne" "$EX"
sed 's/role bypasser/role nobody_here/' "$OUT/specs/bypass.demesne" >"$OUT/specs/norole.demesne"
run check-norole check "$OUT/specs/norole.demesne" "$EX"

cat >"$OUT/specs/global.demesne" <<'EOF'
topology { level platform virtual level tenant parent platform level project parent tenant }
vocabulary admin {
  permission docs:read
  permission docs:write
  preset reader @ project = docs:read
  preset owner @ tenant = *
}
rolestore admin {
  assignments role_assignments
  kind principal_kind = "user"
  subject user_id
  scope tenant_id project_id
  rolejoin role_id roles id key
  revoked revoked_at
}
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable admin; binds admin }
object doc {
  table docs
  scoped tenant > project
  relation member: admin via role
  permission view = member + @scoped @rls maps select
}
EOF
sed 's/^rolestore admin {/rolestore admin {/' "$OUT/specs/global.demesne" >"$OUT/specs/plane.demesne"
cat >>"$OUT/specs/plane.demesne" <<'EOF'
vocabulary platform { permission platform:manage }
rolestore platform {
  assignments role_assignments
  kind principal_kind = "user"
  subject user_id
  scope tenant_id project_id
  plane platform
  rolejoin role_id roles id key
  revoked revoked_at
}
EOF
fresh demesne_live_global
sql demesne_live_global -c "
  CREATE TABLE docs (id text PRIMARY KEY, tenant_id text, project_id text);
  CREATE TABLE roles (id text PRIMARY KEY, key text);
  CREATE TABLE role_assignments (id text PRIMARY KEY, principal_kind text, user_id text, tenant_id text, project_id text, role_id text, revoked_at timestamptz);
"
GL="$BASE/demesne_live_global"
run check-global-none check "$OUT/specs/global.demesne" "$GL"
sql demesne_live_global -c "INSERT INTO roles VALUES ('r1', 'owner'); INSERT INTO role_assignments VALUES ('a1', 'user', 'u1', NULL, NULL, 'r1', NULL), ('a2', 'user', 'u2', 't1', NULL, 'r1', NULL), ('a3', 'user', 'u3', NULL, NULL, 'r1', now())"
run check-global-danger check "$OUT/specs/global.demesne" "$GL"
run check-global-plane check "$OUT/specs/plane.demesne" "$GL"

run nodsn-check check "$SPEC"
run nodsn-introspect introspect
run nospec-check check
run_driver_error baddsn-introspect introspect "postgres://postgres@127.0.0.1:1/nowhere?sslmode=disable"
run_driver_error baddb-check check "$SPEC" "$BASE/demesne_no_such_db"

echo "live-db: scenarios $total  identical $same  named-divergence $diverged  differ $((total - same - diverged))"
[ $((total - same - diverged)) -eq 0 ]
