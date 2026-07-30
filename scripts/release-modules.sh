#!/usr/bin/env bash
#
# Tag the nested modules for a release, in dependency order.
#
#   ./scripts/release-modules.sh v0.73.0
#
# The root module is stdlib-only and tags on its own. The nested modules each
# require the ones below them, so their go.mod must name a version that already
# exists on the remote — hence the ordering, and hence one commit per stage.
#
#   1. v<X>              root      (no intra-repo requires)
#   2. pgx/v<X>          requires  demesne@v<X>
#   3. cmd/demesne/v<X>  requires  demesne@v<X> + demesne/pgx@v<X>
#
# go.work supplies local code for development and CI, so the require lines only
# have to resolve for consumers running `go install`.
set -euo pipefail

ver="${1:-}"
if [[ ! "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "usage: $0 vX.Y.Z" >&2
	exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
	echo "working tree is dirty; commit or stash first" >&2
	exit 1
fi

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

tag_exists() { git rev-parse -q --verify "refs/tags/$1" >/dev/null; }

echo "==> 1/3  root $ver"
if ! tag_exists "$ver"; then
	git tag "$ver"
fi
git push origin "$ver"

echo "==> 2/3  pgx/$ver"
go mod edit -require="github.com/foir-io/demesne@$ver" ./pgx/go.mod
git add pgx/go.mod
git commit -m "chore(pgx): require demesne $ver"
git tag "pgx/$ver"
git push origin HEAD "pgx/$ver"

echo "==> 3/3  cmd/demesne/$ver"
go mod edit \
	-require="github.com/foir-io/demesne@$ver" \
	-require="github.com/foir-io/demesne/pgx@$ver" \
	./cmd/demesne/go.mod
git add cmd/demesne/go.mod
git commit -m "chore(cli): require demesne $ver"
git tag "cmd/demesne/$ver"
git push origin HEAD "cmd/demesne/$ver"

cat <<EOF

done. verify with:

  GOFLAGS=-mod=mod go install github.com/foir-io/demesne/cmd/demesne@$ver
EOF
