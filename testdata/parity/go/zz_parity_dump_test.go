package demesne

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	if dir := os.Getenv("DEMESNE_PARITY_ORACLE_SPECS"); dir != "" {
		parityWriteOracleSpecs(t, dir)
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
	if err := Validate(s); err != nil {
		return
	}
	entry, err := parityOracleEntry(s)
	if err != nil {
		parityWrite(t, dir, "oracle.json", "error: "+err.Error()+"\n")
	} else {
		ob, err := json.MarshalIndent(entry, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		parityWrite(t, dir, "oracle.json", string(ob)+"\n")
	}
	parityWrite(t, dir, "api.txt", parityAPI(s))
}

func parityOracleEntry(s *Spec) (entry map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			entry, err = nil, fmt.Errorf("panic")
		}
	}()
	return buildOracleEntry(s)
}

func parityWriteOracleSpecs(t *testing.T, dir string) {
	specs := []struct{ name, src string }{
		{"runtime", runtimeSpec},
		{"holds", holdsSpec},
		{"fullGrant", fullGrantSpec},
		{"adminOwner", adminOwnerSpec},
		{"fullRoleStore", fullRoleStoreSpec},
		{"rpScoped", rpScopedRoleStoreSpec},
		{"manage", manageSpecSrc(t)},
		{"planes", planesSpecSrc(t)},
		{"require", requireSpecSrc(t)},
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, sp := range specs {
		order = append(order, sp.name)
		parityWrite(t, dir, sp.name+".demesne", sp.src)
	}
	parityWrite(t, dir, "ORDER", strings.Join(order, "\n")+"\n")
}

func parityErr(err error) string {
	if err == nil {
		return "ok"
	}
	return "error: " + err.Error()
}

func parityAPI(s *Spec) string {
	var b strings.Builder
	names, err := s.DefinerNames()
	fmt.Fprintf(&b, "definer names: %s %s\n", parityErr(err), strings.Join(names, " "))
	for _, o := range s.Objects {
		sql, err := s.PointCheckSQL(o.Name)
		fmt.Fprintf(&b, "pointcheck %s: %s %s\n", o.Name, parityErr(err), sql)
		_, err = s.ResourceAccessSurface(o.Name)
		fmt.Fprintf(&b, "resourceaccess %s: %s\n", o.Name, parityErr(err))
	}
	presets, err := s.ExpandedPresets("")
	fmt.Fprintf(&b, "expanded presets: %s\n", parityErr(err))
	pnames := make([]string, 0, len(presets))
	for k := range presets {
		pnames = append(pnames, k)
	}
	sort.Strings(pnames)
	for _, k := range pnames {
		fmt.Fprintf(&b, "  %s = %s\n", k, strings.Join(presets[k], " "))
	}
	for _, v := range s.Vocabularies() {
		fmt.Fprintf(&b, "vocabulary %s:", v.Name)
		for _, p := range v.Permissions {
			fmt.Fprintf(&b, " %s/%t", p.Name, p.Parameterized)
		}
		b.WriteString("\n")
	}
	ent, err := s.RenderClaimsContractEntriesGo("ClaimsContractEntries")
	fmt.Fprintf(&b, "claims entries go: %s\n%s", parityErr(err), ent)
	fs, err := s.EmitFieldScopes()
	fmt.Fprintf(&b, "field scopes: %s\n", parityErr(err))
	sites := make([]string, 0, len(fs))
	for k := range fs {
		sites = append(sites, k)
	}
	sort.Strings(sites)
	for _, site := range sites {
		fields := make([]string, 0, len(fs[site]))
		for f := range fs[site] {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		for _, f := range fields {
			fmt.Fprintf(&b, "  %s %s -> %s\n", site, f, fs[site][f])
		}
	}
	fa, _ := s.EmitFieldAccess()
	objs := make([]string, 0, len(fa))
	for k := range fa {
		objs = append(objs, k)
	}
	sort.Strings(objs)
	for _, name := range objs {
		table := s.objectByName(name).Table
		fmt.Fprintf(&b, "field access %s go:\n%sfield access %s ts:\n%sfield access %s grants:\n%s", name, fa[name].RenderGo(), name, fa[name].RenderTS(), name, fa[name].RenderGrants(table))
	}
	for _, rg := range s.ReachGrants() {
		fmt.Fprintf(&b, "reach grant %s %s %s\n", rg.EdgeTable(), rg.GranteeColumn(), rg.Granularity())
	}
	surf, err := s.EmitAppSurface()
	fmt.Fprintf(&b, "app surface: %s\n", parityErr(err))
	if err == nil {
		for _, o := range surf.Objects {
			for _, c := range o.Checks {
				fmt.Fprintf(&b, "  check %s.%s: %s\n", o.Object, c.Verb, c.CheckSQL)
			}
		}
	}
	pdps, err := s.EmitPDP()
	fmt.Fprintf(&b, "pdp: %s\n", parityErr(err))
	psites := make([]string, 0, len(pdps))
	for k := range pdps {
		psites = append(psites, k)
	}
	sort.Strings(psites)
	for _, site := range psites {
		b.WriteString(pdps[site].RenderGo(site + "Policy"))
	}
	contract, err := s.ClaimsContract()
	values := map[string]string{}
	for _, k := range contract {
		values[k] = "v<" + k + ">&"
	}
	minted, merr := s.MintClaims(values)
	fmt.Fprintf(&b, "mint: %s %s %s\n", parityErr(err), parityErr(merr), minted)
	for _, sub := range s.Subjects {
		scopes := map[string]string{}
		for _, l := range s.Topology.Levels {
			scopes[l.Name] = "s_" + l.Name
		}
		_, verr := s.BuildClaims(Principal{Subject: sub.Name, ID: "id1", Scopes: scopes})
		nonVirtual := map[string]string{}
		for _, l := range s.Topology.Levels {
			if !l.Virtual {
				nonVirtual[l.Name] = "s_" + l.Name
			}
		}
		out, err := s.MintClaimsFor(Principal{Subject: sub.Name, ID: "id1", Scopes: nonVirtual})
		fmt.Fprintf(&b, "claims for %s: %s | %s %s\n", sub.Name, parityErr(verr), parityErr(err), out)
	}
	for _, rs := range s.RoleStores {
		hr, err := s.HoldsResolver(rs.Name)
		if err != nil {
			fmt.Fprintf(&b, "holds %s: %s\n", rs.Name, parityErr(err))
			continue
		}
		fmt.Fprintf(&b, "holds %s: %s | %s\n", rs.Name, hr.AssignmentsSQL(), hr.GlobalAssignmentsSQL())
	}
	return b.String()
}
