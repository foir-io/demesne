#!/usr/bin/env bash
set -euo pipefail

TAG="$1"
PARITY="$2"
OUT="$3"
ROOT="$(git rev-parse --show-toplevel)"
rm -rf "$OUT"
mkdir -p "$OUT/work"
W="$(cd "$OUT/work" && pwd)"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/ca.key" -out "$W/ca.crt" -subj "/CN=demesne-test-ca" -days 30 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$W/client.key" -out "$W/client.csr" -subj "/CN=postgres" 2>/dev/null
openssl x509 -req -in "$W/client.csr" -CA "$W/ca.crt" -CAkey "$W/ca.key" -CAcreateserial -out "$W/client.crt" -days 30 2>/dev/null
openssl rsa -in "$W/client.key" -traditional -out "$W/client-pkcs1.key" 2>/dev/null
openssl rsa -in "$W/client.key" -traditional -aes128 -passout pass:secret -out "$W/client-enc.key" 2>/dev/null
printf 'not a pem\n' >"$W/garbage.pem"
cat >"$W/pgpass" <<'EOF'
# comment
db.example.com:5432:app:alice:pw-alice
*:6543:*:bob:pw\:bob
localhost:*:*:*:pw-local
EOF
cat >"$W/services.conf" <<'EOF'
# services
[svc]
host=svc.example.com
port=7000
dbname=svcdb
user=svcuser
EOF
printf 'host=nosection\n' >"$W/badservices.conf"
sed "s#\$W#$W#g" "$ROOT/testdata/parity/dsn/cases.txt" >"$OUT/cases.txt"

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/demesne-dsn.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT
git -C "$ROOT" archive "$TAG" | tar -x -C "$SCRATCH"
cp "$ROOT/testdata/parity/go/zz_dsn_dump_test.go" "$SCRATCH/cmd/demesne/"
(cd "$SCRATCH/cmd/demesne" && GOWORK="$SCRATCH/go.work" DSN_CASES="$OUT/cases.txt" DSN_WORK="$W" DSN_OUT="$OUT/go.txt" \
  go test -count=1 -run '^TestZZDSNDump$' . >"$OUT/go.log" 2>&1) || {
  cat "$OUT/go.log" >&2
  exit 1
}
"$PARITY" dsn --cases "$OUT/cases.txt" --work "$W" --go "$OUT/go.txt" --out "$OUT/rust.txt"
