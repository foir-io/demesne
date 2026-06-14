// Command demesne is the product-surface CLI (EID-265 WS7): point it at a spec
// and/or a database and validate, emit, introspect, scaffold, check, and diff.
//
// The engine (github.com/eidestudio/demesne) is a pure stdlib library; this CLI
// is a SEPARATE module that additionally links a Postgres driver for the
// live-database subcommands (introspect/scaffold/check/diff). The engine still
// never touches a database — the CLI introspects information_schema into the
// engine's plain-data Schema and hands it in.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	demesne "github.com/eidestudio/demesne"
)

const usage = `demesne — RLS-compiled ReBAC authorization, point it at your database.

USAGE:
  demesne validate <spec.demesne>              parse + validate a spec
  demesne emit     <spec.demesne> [kind]       print generated SQL/Go
                                               kind: rls|definers|triggers|claims|pdp|all (default all)
  demesne introspect <dsn>                     summarise the live schema (tables/columns/FKs)
  demesne scaffold   <dsn>                     generate a STARTER spec from the schema
  demesne check    <spec.demesne> <dsn>        validate the spec, then bind it to the live schema
  demesne diff     <spec.demesne> <dsn>        report generated-vs-live policy drift (surface)

<dsn> may be omitted to use $DATABASE_URL. A Postgres connection string, e.g.
  postgres://user:pass@host:5432/db
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "emit":
		err = cmdEmit(os.Args[2:])
	case "introspect":
		err = cmdIntrospect(os.Args[2:])
	case "scaffold":
		err = cmdScaffold(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "demesne: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "demesne: "+err.Error())
		os.Exit(1)
	}
}

// loadSpec reads, parses, and validates a spec file.
func loadSpec(path string) (*demesne.Spec, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := demesne.Parse(string(src))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := demesne.Validate(s); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
	}
	return s, nil
}

func need(args []string, n int, what string) error {
	if len(args) < n {
		return fmt.Errorf("missing argument: %s", what)
	}
	return nil
}

// dsnArg returns args[i] or $DATABASE_URL.
func dsnArg(args []string, i int) (string, error) {
	if len(args) > i && args[i] != "" {
		return args[i], nil
	}
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no <dsn> given and $DATABASE_URL is empty")
}

func cmdValidate(args []string) error {
	if err := need(args, 1, "<spec.demesne>"); err != nil {
		return err
	}
	s, err := loadSpec(args[0])
	if err != nil {
		return err
	}
	rls, err := s.EmitRLS()
	if err != nil {
		return err
	}
	fmt.Printf("ok: %d objects, %d levels, %d policies, %d reachability grants\n",
		len(s.Objects), len(s.Topology.Levels), len(rls.Policies), len(s.ReachGrants()))
	return nil
}

func cmdEmit(args []string) error {
	if err := need(args, 1, "<spec.demesne>"); err != nil {
		return err
	}
	s, err := loadSpec(args[0])
	if err != nil {
		return err
	}
	kind := "all"
	if len(args) > 1 {
		kind = args[1]
	}
	emitDefiners := func() error {
		defs, err := s.EmitDefiners()
		if err != nil {
			return err
		}
		fmt.Print(demesne.DefinersSQL(defs))
		return nil
	}
	emitRLS := func() error {
		res, err := s.EmitRLS()
		if err != nil {
			return err
		}
		if len(res.Unsupported) > 0 {
			return fmt.Errorf("spec has uncompilable @rls permissions: %s", strings.Join(res.Unsupported, "; "))
		}
		fmt.Print(res.PolicySQL("authenticated"))
		return nil
	}
	switch kind {
	case "definers":
		return emitDefiners()
	case "rls", "policies":
		return emitRLS()
	case "triggers":
		fmt.Print(s.TriggersSQL())
		return nil
	case "claims":
		out, err := s.RenderClaimsContractGo("ClaimsContract")
		if err != nil {
			return err
		}
		fmt.Print(out)
		return nil
	case "pdp":
		pdps, err := s.EmitPDP()
		if err != nil {
			return err
		}
		sites := make([]string, 0, len(pdps))
		for k := range pdps {
			sites = append(sites, k)
		}
		sort.Strings(sites)
		for _, site := range sites {
			p := pdps[site]
			fmt.Printf("# PDP %q: %d governed, %d ungoverned\n", site, len(p.Policy), len(p.Ungoverned))
			procs := make([]string, 0, len(p.Policy))
			for k := range p.Policy {
				procs = append(procs, k)
			}
			sort.Strings(procs)
			for _, pr := range procs {
				fmt.Printf("%s -> %s\n", pr, p.Policy[pr])
			}
		}
		return nil
	case "all":
		if err := emitDefiners(); err != nil {
			return err
		}
		fmt.Print("\n")
		if err := emitRLS(); err != nil {
			return err
		}
		if t := s.TriggersSQL(); t != "" {
			fmt.Print("\n" + t)
		}
		return nil
	default:
		return fmt.Errorf("unknown emit kind %q (rls|definers|triggers|claims|pdp|all)", kind)
	}
}

func cmdIntrospect(args []string) error {
	dsn, err := dsnArg(args, 0)
	if err != nil {
		return err
	}
	sc, meta, err := introspect(dsn)
	if err != nil {
		return err
	}
	_ = sc
	fmt.Printf("schema: %d tables, %d columns, %d foreign keys\n", meta.tables, meta.columns, meta.fks)
	return nil
}

func cmdScaffold(args []string) error {
	dsn, err := dsnArg(args, 0)
	if err != nil {
		return err
	}
	sc, _, err := introspect(dsn)
	if err != nil {
		return err
	}
	out, err := sc.Scaffold(demesne.ScaffoldOptions{})
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

func cmdCheck(args []string) error {
	if err := need(args, 1, "<spec.demesne>"); err != nil {
		return err
	}
	s, err := loadSpec(args[0])
	if err != nil {
		return err
	}
	dsn, err := dsnArg(args, 1)
	if err != nil {
		return err
	}
	sc, _, err := introspect(dsn)
	if err != nil {
		return err
	}
	if err := s.ValidateAgainst(sc); err != nil {
		return fmt.Errorf("spec does not bind to the live schema:\n%w", err)
	}
	fmt.Println("ok: spec is valid AND binds to the live schema (every referenced table/column exists)")
	return nil
}

func cmdDiff(args []string) error {
	if err := need(args, 1, "<spec.demesne>"); err != nil {
		return err
	}
	s, err := loadSpec(args[0])
	if err != nil {
		return err
	}
	dsn, err := dsnArg(args, 1)
	if err != nil {
		return err
	}
	res, err := s.EmitRLS()
	if err != nil {
		return err
	}
	gen := map[string]bool{}
	governed := map[string]bool{}
	for _, p := range res.Policies {
		gen[p.Table+"."+p.Name] = true
		governed[p.Table] = true
	}
	live, err := livePolicySurface(dsn, keys(governed))
	if err != nil {
		return err
	}
	var missing, orphan []string
	for k := range gen {
		if !live[k] {
			missing = append(missing, k)
		}
	}
	for k := range live {
		if !gen[k] {
			orphan = append(orphan, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(orphan)
	for _, m := range missing {
		fmt.Printf("MISSING  %s — generated but not present live (apply it)\n", m)
	}
	for _, o := range orphan {
		fmt.Printf("ORPHAN   %s — live on a governed table but not generated (remove it, or model it)\n", o)
	}
	if len(missing) == 0 && len(orphan) == 0 {
		fmt.Printf("in sync: %d generated policies all present, no orphans across %d governed tables\n", len(gen), len(governed))
	}
	return nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
