package demesne

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parityWrite(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestZZParityDump(t *testing.T) {
	list := os.Getenv("DEMESNE_PARITY_LIST")
	out := os.Getenv("DEMESNE_PARITY_OUT")
	if list == "" || out == "" {
		t.Skip("DEMESNE_PARITY_LIST and DEMESNE_PARITY_OUT drive the parity dump")
	}
	raw, err := os.ReadFile(list)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		id, path, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("bad list line %q", line)
		}
		dir := filepath.Join(out, filepath.FromSlash(id))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		parityDumpSpec(t, dir, string(src))
	}
}

func parityDumpSpec(t *testing.T, dir, src string) {
	s, err := Parse(src)
	if err != nil {
		parityWrite(t, dir, "ast.json", "parse error: "+err.Error()+"\n")
		return
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	parityWrite(t, dir, "ast.json", string(b)+"\n")
}
