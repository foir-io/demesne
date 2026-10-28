package example

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func postgres(t *testing.T) *sql.DB {
	t.Helper()
	for _, bin := range []string{"initdb", "pg_ctl"} {
		if _, err := exec.LookPath(bin); err != nil {
			if os.Getenv("DEMESNE_REQUIRE_PG") != "" {
				t.Fatalf("DEMESNE_REQUIRE_PG is set, but %s is not on PATH", bin)
			}
			t.Skipf("%s is not on PATH", bin)
		}
	}
	base, err := os.MkdirTemp("", "demesne-go-")
	if err != nil {
		t.Fatal(err)
	}
	data, sock := filepath.Join(base, "data"), filepath.Join(base, "sock")
	if err := os.Mkdir(sock, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(name string, args ...string) {
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
	}
	run("initdb", "-D", data, "-U", "postgres", "--auth=trust", "-E", "UTF8")
	run("pg_ctl", "-D", data, "-l", filepath.Join(base, "log"), "-o", fmt.Sprintf("-c listen_addresses='' -c unix_socket_directories='%s'", sock), "-w", "start")
	t.Cleanup(func() {
		_ = exec.Command("pg_ctl", "-D", data, "-w", "stop").Run()
		_ = os.RemoveAll(base)
	})
	db, err := sql.Open("pgx", fmt.Sprintf("host=%s user=postgres dbname=postgres", sock))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

func apply(t *testing.T, db *sql.DB, files ...string) {
	t.Helper()
	for _, f := range files {
		text, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(text)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}
