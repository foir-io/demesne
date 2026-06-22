package demesne

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// TypeScript emit target (EID-338) — the target-neutral half of the generated Layer-2 /
// Layer-3 surface. Where the engine ships Go runtime HELPERS (MintClaims, AssignInsert,
// Resolve, …) and only RENDERS data artifacts as Go source (RenderClaimsContractGo,
// PDP.RenderGo), the TypeScript side is the mirror image: the @demesne/runtime library
// hand-writes the helpers, and THIS file renders the per-spec PROJECTION as TypeScript
// source for that library to consume. The projection IS the interface — exactly the data
// ClaimsContractEntries() / EmitAppSurface() / HoldsResolver() / GrantSurface() /
// ResourceAccessSurface() already return — so the emitter never recomputes a builder; it
// only serializes. This keeps the engine stdlib-pure (it is just string/JSON building)
// and the byte-for-byte equivalence is proven by the differential oracle.
//
// The emitted struct field names (json tags) are the wire contract with the TS
// projection interfaces in @demesne/runtime's types.ts; they must stay in lockstep.

// --- the TS projection shapes (json tags == the @demesne/runtime interfaces) -------

type tsClaimEntry struct {
	Key      string   `json:"key"`
	Level    string   `json:"level"`
	Subjects []string `json:"subjects"`
}

type tsSubjectIdentity struct {
	Name       string `json:"name"`
	Identifies string `json:"identifies"`
}

type tsLevelClaim struct {
	Name     string `json:"name"`
	ClaimKey string `json:"claimKey"`
	Virtual  bool   `json:"virtual"`
}

type tsClaimsProj struct {
	Setting  string              `json:"setting"`
	Cast     string              `json:"cast"`
	Role     string              `json:"role"`
	Contract []string            `json:"contract"`
	Entries  []tsClaimEntry      `json:"entries"`
	Subjects []tsSubjectIdentity `json:"subjects"`
	Levels   []tsLevelClaim      `json:"levels"`
}

type tsAppObject struct {
	Object        string `json:"object"`
	Table         string `json:"table"`
	PK            string `json:"pk"`
	FlatListFn    string `json:"flatListFn"`
	AsyncCheckSQL string `json:"asyncCheckSQL"`
	EditCheckSQL  string `json:"editCheckSQL"`
}

type tsPdpProj struct {
	EmitSite   string            `json:"emitSite"`
	Policy     map[string]string `json:"policy"`
	Ungoverned map[string]string `json:"ungoverned"`
}

type tsPreset struct {
	Name string   `json:"name"`
	Star bool     `json:"star"`
	Set  []string `json:"set"`
}

type tsVocabularyProj struct {
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	Presets     []tsPreset `json:"presets"`
	Rank        []string   `json:"rank"`
}

type tsHoldsResolverProj struct {
	Assignments string           `json:"assignments"`
	KindCol     string           `json:"kindCol"`
	KindVal     string           `json:"kindVal"`
	SubjectCol  string           `json:"subjectCol"`
	ScopeCols   []string         `json:"scopeCols"`
	RevokedCol  string           `json:"revokedCol"`
	RoleCol     string           `json:"roleCol"`
	RolesTable  string           `json:"rolesTable"`
	RolesID     string           `json:"rolesId"`
	KeyCol      string           `json:"keyCol"`
	PermsCol    string           `json:"permsCol"`
	Vocab       tsVocabularyProj `json:"vocab"`
}

type tsRoleAssignProj struct {
	Assignments  string   `json:"assignments"`
	PK           string   `json:"pk"`
	KindCol      string   `json:"kindCol"`
	KindVal      string   `json:"kindVal"`
	SubjectCol   string   `json:"subjectCol"`
	RoleCol      string   `json:"roleCol"`
	ScopeCols    []string `json:"scopeCols"`
	RevokedCol   string   `json:"revokedCol"`
	GrantedAtCol string   `json:"grantedAtCol"`
	GrantedByCol string   `json:"grantedByCol"`
	RevokedByCol string   `json:"revokedByCol"`
	ExtraCols    []string `json:"extraCols"`
	RolesTable   string   `json:"rolesTable"`
	RolesID      string   `json:"rolesId"`
	KeyCol       string   `json:"keyCol"`
	PermsCol     string   `json:"permsCol"`
}

type tsGrantProj struct {
	Name         string   `json:"name"`
	Level        string   `json:"level"`
	Table        string   `json:"table"`
	GranteeCol   string   `json:"granteeCol"`
	LevelCol     string   `json:"levelCol"`
	ActiveCol    string   `json:"activeCol"`
	ExpiresCol   string   `json:"expiresCol"`
	PK           string   `json:"pk"`
	GrantedByCol string   `json:"grantedByCol"`
	RevokedByCol string   `json:"revokedByCol"`
	CreatedAtCol string   `json:"createdAtCol"`
	ExtraCols    []string `json:"extraCols"`
}

type tsResourceAccessProj struct {
	Table        string   `json:"table"`
	ScopeCols    []string `json:"scopeCols"`
	ModeCol      string   `json:"modeCol"`
	PK           string   `json:"pk"`
	ReadModes    []string `json:"readModes"`
	GrantKinds   []string `json:"grantKinds"`
	AclTable     string   `json:"aclTable"`
	RecordCol    string   `json:"recordCol"`
	KindCol      string   `json:"kindCol"`
	PrincipalCol string   `json:"principalCol"`
	AccessCol    string   `json:"accessCol"`
	DiscrimCol   string   `json:"discrimCol"`
	DiscrimVal   string   `json:"discrimVal"`
	AccessorFn   string   `json:"accessorFn"`
}

// --- helpers ----------------------------------------------------------------------

// strs returns ss, or an empty (non-nil) slice when ss is nil — so json renders `[]`,
// never `null` (the TS interfaces type these fields as `string[]`, never nullable).
func strs(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// strMap returns m, or an empty (non-nil) map when m is nil — so json renders `{}`.
func strMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// setKeys renders a Go set (map[string]bool) as a sorted slice (deterministic).
func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// tsJSON marshals v as a TypeScript literal: JSON without HTML escaping (so a `>` in an
// SQL string stays literal, not `>`), optionally indented. Valid TS, deterministic.
func tsJSON(v any, indent bool) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(v)
	return strings.TrimRight(buf.String(), "\n")
}

// --- per-surface projections ------------------------------------------------------

func (s *Spec) tsClaimsProjection() (*tsClaimsProj, error) {
	setting, cast := s.claimSetting()
	contract, err := s.ClaimsContract()
	if err != nil {
		return nil, err
	}
	entries, err := s.ClaimsContractEntries()
	if err != nil {
		return nil, err
	}
	te := make([]tsClaimEntry, len(entries))
	for i, e := range entries {
		te[i] = tsClaimEntry{Key: e.Key, Level: e.Level, Subjects: strs(e.Subjects)}
	}
	subs := make([]tsSubjectIdentity, 0, len(s.Subjects))
	for _, sub := range s.Subjects {
		subs = append(subs, tsSubjectIdentity{Name: sub.Name, Identifies: sub.Identifies})
	}
	levels := []tsLevelClaim{}
	if s.Topology != nil {
		for _, l := range s.Topology.Levels {
			levels = append(levels, tsLevelClaim{Name: l.Name, ClaimKey: l.claimKey(), Virtual: l.Virtual})
		}
	}
	return &tsClaimsProj{
		Setting: setting, Cast: cast, Role: s.claimRole(),
		Contract: strs(contract), Entries: te, Subjects: subs, Levels: levels,
	}, nil
}

func tsVocab(v *Vocabulary) tsVocabularyProj {
	presets := make([]tsPreset, len(v.Presets))
	for i, p := range v.Presets {
		presets[i] = tsPreset{Name: p.Name, Star: p.Star, Set: strs(p.Set)}
	}
	return tsVocabularyProj{Name: v.Name, Permissions: strs(v.Permissions), Presets: presets, Rank: strs(v.Rank)}
}

func tsHolds(r *HoldsResolver) tsHoldsResolverProj {
	return tsHoldsResolverProj{
		Assignments: r.Assignments, KindCol: r.KindCol, KindVal: r.KindVal, SubjectCol: r.SubjectCol,
		ScopeCols: strs(r.ScopeCols), RevokedCol: r.RevokedCol, RoleCol: r.RoleCol,
		RolesTable: r.RolesTable, RolesID: r.RolesID, KeyCol: r.KeyCol, PermsCol: r.PermsCol,
		Vocab: tsVocab(r.Vocabulary()),
	}
}

func tsRoleAssign(r *RoleAssignmentSurface) tsRoleAssignProj {
	return tsRoleAssignProj{
		Assignments: r.Assignments, PK: r.PK, KindCol: r.KindCol, KindVal: r.KindVal,
		SubjectCol: r.SubjectCol, RoleCol: r.RoleCol, ScopeCols: strs(r.ScopeCols), RevokedCol: r.RevokedCol,
		GrantedAtCol: r.GrantedAtCol, GrantedByCol: r.GrantedByCol, RevokedByCol: r.RevokedByCol,
		ExtraCols: strs(r.ExtraCols), RolesTable: r.RolesTable, RolesID: r.RolesID, KeyCol: r.KeyCol, PermsCol: r.PermsCol,
	}
}

func tsGrant(g *GrantSurface) tsGrantProj {
	return tsGrantProj{
		Name: g.Name, Level: g.Level, Table: g.Table, GranteeCol: g.GranteeCol, LevelCol: g.LevelCol,
		ActiveCol: g.ActiveCol, ExpiresCol: g.ExpiresCol, PK: g.PK,
		GrantedByCol: g.GrantedByCol, RevokedByCol: g.RevokedByCol, CreatedAtCol: g.CreatedAtCol, ExtraCols: strs(g.ExtraCols),
	}
}

func tsResAccess(r *ResourceAccessSurface) tsResourceAccessProj {
	return tsResourceAccessProj{
		Table: r.Table, ScopeCols: strs(r.ScopeCols), ModeCol: r.ModeCol, PK: r.pk,
		ReadModes: setKeys(r.readModes), GrantKinds: setKeys(r.grantKinds),
		AclTable: r.aclTable, RecordCol: r.recordCol, KindCol: r.kindCol, PrincipalCol: r.principalCol,
		AccessCol: r.accessCol, DiscrimCol: r.discrimCol, DiscrimVal: r.discrimVal, AccessorFn: r.accessorFn,
	}
}

// --- the module emitter -----------------------------------------------------------

type tsDecl struct {
	name string // the exported const name
	typ  string // its TS type annotation
	lit  string // the JSON/TS literal value
}

// EmitTS renders the spec's complete generated projection as a TypeScript module that
// imports @demesne/runtime and exports one typed const per present surface (claims,
// appSurface, pdp, holdsResolver, roleAssignment, grants, resourceAccess). It is the TS
// analogue of the Go RenderGo artifacts — the data half of the generated surface; the
// algorithm half is the hand-written @demesne/runtime. A surface absent from the spec
// (no rolestore, no grants, no ACL object) is simply omitted.
func (s *Spec) EmitTS() (string, error) {
	var decls []tsDecl

	cl, err := s.tsClaimsProjection()
	if err != nil {
		return "", fmt.Errorf("EmitTS claims: %w", err)
	}
	decls = append(decls, tsDecl{"claims", "Claims", tsJSON(cl, true)})

	if surf, err := s.EmitAppSurface(); err == nil {
		objs := make([]tsAppObject, len(surf.Objects))
		for i, o := range surf.Objects {
			objs[i] = tsAppObject{o.Object, o.Table, o.PK, o.FlatListFn, o.AsyncCheckSQL, o.EditCheckSQL}
		}
		decls = append(decls, tsDecl{"appSurface", "AppObjectSurface[]", tsJSON(objs, true)})
	}

	if pdps, err := s.EmitPDP(); err == nil && len(pdps) > 0 {
		m := map[string]tsPdpProj{}
		for name, p := range pdps {
			m[name] = tsPdpProj{EmitSite: p.EmitSite, Policy: strMap(p.Policy), Ungoverned: strMap(p.Ungoverned)}
		}
		decls = append(decls, tsDecl{"pdp", "Record<string, Pdp>", tsJSON(m, true)})
	}

	if len(s.RoleStores) > 0 {
		hr, err := s.HoldsResolver("")
		if err != nil {
			return "", fmt.Errorf("EmitTS holdsResolver: %w", err)
		}
		decls = append(decls, tsDecl{"holdsResolver", "HoldsResolver", tsJSON(tsHolds(hr), true)})
		ra, err := s.RoleAssignmentSurface("")
		if err != nil {
			return "", fmt.Errorf("EmitTS roleAssignment: %w", err)
		}
		decls = append(decls, tsDecl{"roleAssignment", "RoleAssignmentSurface", tsJSON(tsRoleAssign(ra), true)})
	}

	if len(s.Grants) > 0 {
		m := map[string]tsGrantProj{}
		for _, g := range s.Grants {
			gs, err := s.GrantSurface(g.Name)
			if err != nil {
				return "", fmt.Errorf("EmitTS grant %q: %w", g.Name, err)
			}
			m[g.Name] = tsGrant(gs)
		}
		decls = append(decls, tsDecl{"grants", "Record<string, GrantSurface>", tsJSON(m, true)})
	}

	ram := map[string]tsResourceAccessProj{}
	for _, o := range s.Objects {
		if objectGrantEdge(o) == nil {
			continue
		}
		r, err := s.ResourceAccessSurface(o.Name)
		if err != nil {
			return "", fmt.Errorf("EmitTS resourceAccess %q: %w", o.Name, err)
		}
		ram[o.Name] = tsResAccess(r)
	}
	if len(ram) > 0 {
		decls = append(decls, tsDecl{"resourceAccess", "Record<string, ResourceAccessSurface>", tsJSON(ram, true)})
	}

	return renderTSModule(decls), nil
}

// renderTSModule writes the header, the type-only import of exactly the named types, and
// each `export const`.
func renderTSModule(decls []tsDecl) string {
	typeSet := map[string]bool{}
	for _, d := range decls {
		t := strings.TrimSuffix(d.typ, "[]")
		if rest, ok := strings.CutPrefix(t, "Record<string, "); ok {
			t = strings.TrimSuffix(rest, ">")
		}
		typeSet[t] = true
	}
	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}
	sort.Strings(types)

	var b strings.Builder
	b.WriteString("// Code generated by Demesne from the authorization spec. DO NOT EDIT.\n")
	b.WriteString("// The plain-data projection the @demesne/runtime builders reproduce the Go engine over.\n\n")
	fmt.Fprintf(&b, "import type { %s } from \"@demesne/runtime\";\n", strings.Join(types, ", "))
	for _, d := range decls {
		fmt.Fprintf(&b, "\nexport const %s: %s = %s;\n", d.name, d.typ, d.lit)
	}
	return b.String()
}

// --- standalone codegen artifacts (the TS analogues of RenderClaimsContractGo / RenderGo) ---

// RenderClaimsContractTS emits the flat claims contract as a standalone TypeScript const
// (the TS analogue of RenderClaimsContractGo).
func (s *Spec) RenderClaimsContractTS(varName string) (string, error) {
	keys, err := s.ClaimsContract()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("// Code generated by Demesne from the authorization spec. DO NOT EDIT.\n")
	fmt.Fprintf(&b, "export const %s: string[] = %s;\n", varName, tsJSON(strs(keys), false))
	return b.String(), nil
}

// RenderTS emits an emit-site's Policy map as a standalone TypeScript const (the TS
// analogue of PDP.RenderGo). Procedures are sorted (json key order) for stable output.
func (p *PDP) RenderTS(varName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// Code generated by Demesne from the %q emit-site. DO NOT EDIT.\n", p.EmitSite)
	fmt.Fprintf(&b, "export const %s: Record<string, string> = %s;\n", varName, tsJSON(strMap(p.Policy), false))
	return b.String()
}
