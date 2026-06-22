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
	"bufio"
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
                                               kind: rls|definers|enablement|triggers|claims|pdp|framework|all (default all)
                                               framework [pkg]: typed Go app package (default pkg "authz")
  demesne introspect <dsn>                     summarise the live schema (tables/columns/FKs)
  demesne scaffold   [-i] <dsn>                generate a STARTER spec from the schema (-i: interactive)
  demesne check    <spec.demesne> <dsn>        validate the spec, bind it to the live schema, check the RLS role
  demesne diff     <spec.demesne> <dsn>        report generated-vs-live policy drift (surface)
  demesne coverage <spec.demesne> <dsn>        list live tables with NO governing object (ungoverned → no RLS)

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
	case "coverage":
		err = cmdCoverage(os.Args[2:])
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
	switch kind {
	case "definers":
		return emitDefinersSQL(s)
	case "rls", "policies":
		return emitRLSSQL(s)
	case "enablement":
		return emitEnablementSQL(s)
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
		return emitPDPReport(s)
	case "framework":
		pkg := "authz"
		if len(args) > 2 {
			pkg = args[2]
		}
		out, err := s.EmitFramework(pkg)
		if err != nil {
			return err
		}
		fmt.Print(out)
		return nil
	case "all":
		return emitAllSQL(s)
	default:
		return fmt.Errorf("unknown emit kind %q (rls|definers|enablement|triggers|claims|pdp|framework|all)", kind)
	}
}

func emitDefinersSQL(s *demesne.Spec) error {
	defs, err := s.EmitDefiners()
	if err != nil {
		return err
	}
	fmt.Print(demesne.DefinersSQL(defs))
	return nil
}

func emitRLSSQL(s *demesne.Spec) error {
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

func emitEnablementSQL(s *demesne.Spec) error {
	res, err := s.EmitRLS()
	if err != nil {
		return err
	}
	fmt.Print(res.EnablementSQL())
	return nil
}

func emitPDPReport(s *demesne.Spec) error {
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
}

func emitAllSQL(s *demesne.Spec) error {
	// Materialized flats first: the accessor definers read the flat and the RLS policies
	// call <flat>_member, so the table + functions must already exist. "" (byte-identical)
	// for a spec with no `materialized` relation.
	if f := s.FlatsSQL(); f != "" {
		fmt.Print(f + "\n")
	}
	if err := emitDefinersSQL(s); err != nil {
		return err
	}
	fmt.Print("\n")
	if err := emitEnablementSQL(s); err != nil {
		return err
	}
	fmt.Print("\n")
	if err := emitRLSSQL(s); err != nil {
		return err
	}
	if t := s.TriggersSQL(); t != "" {
		fmt.Print("\n" + t)
	}
	if c := s.ChangelogSQL(); c != "" {
		fmt.Print("\n" + c)
	}
	if a := s.AsyncSQL(); a != "" {
		fmt.Print("\n" + a)
	}
	return nil
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
	interactive := false
	rest := args[:0:0]
	for _, a := range args {
		if a == "-i" || a == "--interactive" {
			interactive = true
			continue
		}
		rest = append(rest, a)
	}
	dsn, err := dsnArg(rest, 0)
	if err != nil {
		return err
	}
	sc, _, err := introspect(dsn)
	if err != nil {
		return err
	}
	if interactive {
		return scaffoldInteractive(sc)
	}
	out, err := sc.Scaffold(demesne.ScaffoldOptions{})
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

// scaffoldInteractive runs the FK-graph scaffold, then asks for the deployment
// details the inference can't know (the RLS role + the definer/table schemas — what
// the engine de-Foired into spec-declared bindings) and surfaces the ungoverned
// tables as fill-in stubs. The combo: introspect (DB) + a short Q&A (you) →
// a more deployment-ready starter spec. Prompts go to stderr so stdout is the spec
// alone (`demesne scaffold -i <dsn> > my.demesne`); empty stdin → all defaults.
func scaffoldInteractive(sc *demesne.Schema) error {
	r := bufio.NewReader(os.Stdin)
	ask := func(label, def string) string {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, def)
		line, _ := r.ReadString('\n')
		if line = strings.TrimSpace(line); line == "" {
			return def
		}
		return line
	}
	fmt.Fprintf(os.Stderr, "Introspected %d tables. A few deployment questions (Enter = default):\n", len(sc.Tables()))
	role := ask("RLS connection role", "authenticated")
	defSchema := ask("definer (function) schema", "auth")
	tblSchema := ask("governed-table schema", "public")

	body, err := sc.Scaffold(demesne.ScaffoldOptions{})
	if err != nil {
		return err
	}

	var b strings.Builder
	// Emit the deployment bindings only when they differ from the engine defaults
	// (so a default run stays byte-identical to plain `scaffold`).
	if role != "authenticated" {
		fmt.Fprintf(&b, "claims via \"request.jwt.claims\" json role %s\n", role)
	}
	if defSchema != "auth" {
		fmt.Fprintf(&b, "definers schema %q\n", defSchema)
	}
	if tblSchema != "public" {
		fmt.Fprintf(&b, "tables schema %q\n", tblSchema)
	}
	if b.Len() > 0 {
		b.WriteString("\n")
	}
	b.WriteString(body)

	// The scaffold output re-parses; run coverage on it to list the tables it could
	// NOT place (no FK path to a container) as TODO object stubs — the operator fills
	// or deletes them.
	if spec, perr := demesne.Parse(body); perr == nil {
		cov := spec.TableCoverage(sc.Tables())
		if len(cov.Ungoverned) > 0 {
			b.WriteString("\n// ── Ungoverned tables (no object → no RLS). Model each, or delete this block. ──\n")
			for _, t := range cov.Ungoverned {
				fmt.Fprintf(&b, "// object %s { table %s; scoped <levels>; use contained }\n", t, t)
			}
		}
	}
	fmt.Print(b.String())
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

	// The moat assumes the RLS connection role is NOT BYPASSRLS — a BYPASSRLS role
	// ignores every policy (incl. FORCE'd ones), silently defeating enforcement.
	role := s.ConnectionRole()
	exists, bypass, err := roleBypassesRLS(dsn, role)
	switch {
	case err != nil:
		fmt.Printf("warning: could not verify the RLS role %q: %v\n", role, err)
	case !exists:
		fmt.Printf("warning: the RLS connection role %q does not exist on this database\n", role)
	case bypass:
		fmt.Printf("DANGER: the RLS connection role %q has BYPASSRLS — it ignores every policy, defeating the moat. Use a non-BYPASSRLS role for sessions.\n", role)
		return fmt.Errorf("RLS role %q is BYPASSRLS", role)
	default:
		fmt.Printf("ok: the RLS connection role %q is not BYPASSRLS\n", role)
	}
	return nil
}

func cmdCoverage(args []string) error {
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
	cov := s.TableCoverage(sc.Tables())
	fmt.Printf("%d governed (RLS), %d referenced (policy-free stores), %d UNGOVERNED\n",
		len(cov.Governed), len(cov.Referenced), len(cov.Ungoverned))
	for _, t := range cov.Ungoverned {
		fmt.Printf("UNGOVERNED  %s — no object in the spec, so no RLS. Model it with an object, or confirm it is intentionally exempt.\n", t)
	}
	if len(cov.Ungoverned) == 0 {
		fmt.Println("ok: every live table is governed by an object or referenced as a policy-free store")
	}
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
