package demesne

import (
	"fmt"
	"sort"
)

// Session/claims wrapper (Layer 2, EID-334) — the second load-bearing runtime-glue
// piece. The engine compiles enforcement into RLS and emits the claims CONTRACT (the
// key set a session must present), and runtime.go ships MintClaims/ClaimsSetSQL. But
// nothing told an adopter how to GO FROM a principal to those claims, nor how the
// session envelope (the role + claims set_config a tx runs) is shaped. So every
// adopter hand-maps it: Foir's db/rls.go:BuildRLSClaims hand-maps fields
// (UserID->sub, TenantID->tenant_id, ...) and db.WithRLS hand-writes the
// `SET LOCAL ROLE authenticated` + set_config sequence. Drift risk: a contract key
// added to the spec is silently absent from the blob until someone edits the hand
// map. This file closes it — the principal->claim-key mapping and the session
// envelope are both DERIVED from the spec.
//
// Three pieces, mirroring the read/compute split the rest of the runtime glue uses:
//
//   - CONTRACT (structured) — ClaimsContractEntries() enriches the flat
//     ClaimsContract() []string into [{key, source}], so a caller knows WHERE each
//     key's value comes from (a topology level's scope id, and/or a subject's
//     identity) without hand-mapping field names. ClaimsContract() now delegates to
//     it, so the flat key list is unchanged (byte-identical generated artifact).
//   - BUILD (this engine) — BuildClaims(principal) maps a principal's typed inputs
//     (which subject it is + that subject's id + the scope id it holds per level)
//     onto the contract: subject id -> the subject's `identifies` key, each scope id
//     -> that level's claim key. Pure stdlib, no policy: it is the spec-derived
//     replacement for a hand-written field map. MintClaimsFor pairs it with
//     MintClaims to render the validated blob in one call.
//   - ENVELOPE (this engine) — SetRoleSQL + SessionSetupSQL BUILD the statement
//     sequence a caller runs at the top of an RLS tx (`SET [LOCAL] ROLE <role>` then
//     the claims set_config). The engine never executes them (no driver — the moat);
//     the caller runs them in its own tx, exactly as db.WithRLS does today. The RLS
//     connection role is spec-declared (claims-block `role`), defaulting to
//     "authenticated" the same way the GUC defaults to request.jwt.claims.
//
// Target-neutral by construction. ClaimEntry / Principal are plain exported data;
// BuildClaims is a pure transform over the spec's levels + subjects; the SQL builders
// return strings. A TypeScript emitter reproduces them from the same projection.
// Nothing here names a tenant/project/customer/role: every key and the role itself
// derive from (or default behind) the spec (EID-267 / EID-315).

// --- (1) the contract as a structured artifact ------------------------------

// ClaimEntry is one key of the machine-readable claims contract together with WHERE
// its value comes from. A key is fed by a topology level's scope id (Level != ""),
// by one or more subjects' identity (Subjects non-empty), or — in the uncommon case
// the same key name is reused as both a level claim key and a subject `identifies`
// — both. This is the source map a caller builds a session's claims from without
// hand-mapping; the flat ClaimsContract() is exactly the Keys of these entries.
type ClaimEntry struct {
	Key      string   // the JWT claim key (MintClaims / the RLS policies read this)
	Level    string   // the topology level whose scope id feeds this key, or ""
	Subjects []string // subjects whose `identifies` feeds this key (sorted), or nil
}

// ClaimsContractEntries is the structured (machine-readable) claims contract: one
// ClaimEntry per key — its source(s) — sorted by key. It is the enriched form of
// ClaimsContract(): same key set, plus the provenance a derived claims-builder needs.
// Derived purely from the topology (one entry per non-virtual level's claim key) and
// the subjects (each subject's `identifies` key), so it carries no baked-in field
// names.
func (s *Spec) ClaimsContractEntries() ([]ClaimEntry, error) {
	chain, err := s.nonVirtualChain()
	if err != nil {
		return nil, err
	}
	byKey := map[string]*ClaimEntry{}
	entry := func(k string) *ClaimEntry {
		if e := byKey[k]; e != nil {
			return e
		}
		e := &ClaimEntry{Key: k}
		byKey[k] = e
		return e
	}
	for _, l := range chain {
		entry(l.claimKey()).Level = l.Name
	}
	for _, sub := range s.Subjects {
		if sub.Identifies != "" {
			e := entry(sub.Identifies)
			e.Subjects = append(e.Subjects, sub.Name)
		}
	}
	out := make([]ClaimEntry, 0, len(byKey))
	for _, e := range byKey {
		sort.Strings(e.Subjects)
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// --- (2) the derived claims-builder -----------------------------------------

// Principal is the typed identity a session presents: which subject acts, that
// subject's id, and the scope id it holds at each topology level. It is what a
// caller has after authenticating a request, expressed in SPEC terms (subject /
// level names) — no claim-key knowledge required. BuildClaims maps it onto the
// contract. Scopes is keyed by topology level NAME (e.g. "tenant"), not claim key.
type Principal struct {
	Subject string            // subject NAME (e.g. "admin", "customer")
	ID      string            // the subject's id -> its `identifies` claim key
	Scopes  map[string]string // topology level NAME -> that level's scope id
}

// BuildClaims maps a principal onto the claims contract, producing the `values` map
// MintClaims consumes: the principal's subject id under that subject's `identifies`
// key, and each presented scope id under that level's claim key. It is the
// spec-derived replacement for a hand-written field map (Foir's BuildRLSClaims) —
// every key/value comes from the spec's declared subjects + levels, so a contract
// key added to the spec flows through with no code change. An adopter whose session
// also carries NON-contract keys (e.g. a derived principal-kind discriminator, or
// deployment-specific extras) adds those to the returned map before minting; the
// engine owns only the spec-derived keys (that boundary is what BuildRLSClaims
// blurs and this un-blurs).
//
// Rejections (fail-closed, so a caller never mints a claim no policy reads): an
// unknown subject; a subject with no `identifies` key when an id is supplied; a
// scope for an unknown level or a VIRTUAL level (which carries no scope claim — e.g.
// a platform root). Returns a fresh map the caller may mutate.
func (s *Spec) BuildClaims(p Principal) (map[string]string, error) {
	sub := s.subjectByName(p.Subject)
	if sub == nil {
		return nil, fmt.Errorf("BuildClaims: no subject %q in the spec", p.Subject)
	}
	values := map[string]string{}
	if p.ID != "" {
		if sub.Identifies == "" {
			return nil, fmt.Errorf("BuildClaims: subject %q has no identity key (`identifies`) but an id was supplied", p.Subject)
		}
		values[sub.Identifies] = p.ID
	}
	// Deterministic error order over the presented scopes.
	levels := make([]string, 0, len(p.Scopes))
	for name := range p.Scopes {
		levels = append(levels, name)
	}
	sort.Strings(levels)
	for _, name := range levels {
		l := s.Topology.LevelByName(name)
		if l == nil {
			return nil, fmt.Errorf("BuildClaims: subject %q presents a scope for unknown level %q", p.Subject, name)
		}
		if l.Virtual {
			return nil, fmt.Errorf("BuildClaims: level %q is virtual (no scope claim) — it cannot carry a scope id", name)
		}
		values[l.claimKey()] = p.Scopes[name]
	}
	return values, nil
}

// MintClaimsFor is the one-call path from a principal to the claims blob a session
// presents: BuildClaims (principal -> the contract's `values`) then MintClaims
// (validate against the contract + render the deterministic JSON). Use it when the
// session carries only spec-derived keys; when it also carries non-contract extras,
// call BuildClaims, add them, and call MintClaims yourself.
func (s *Spec) MintClaimsFor(p Principal) (string, error) {
	values, err := s.BuildClaims(p)
	if err != nil {
		return "", err
	}
	return s.MintClaims(values)
}

// --- (3) the WithRLS-shaped session envelope --------------------------------

// claimRole returns the Postgres connection role a session assumes so RLS is in
// force — the spec-declared `claims … role <r>`, else the default "authenticated".
// Mirrors claimSetting()/definerSchema(): a spec-declared value with a defaulting
// fallback, so the engine bakes in no role name and Foir (no `claims` block) renders
// byte-identically.
func (s *Spec) claimRole() string {
	if s.Claims != nil && s.Claims.Role != "" {
		return s.Claims.Role
	}
	return "authenticated"
}

// ConnectionRole returns the Postgres role a session assumes so RLS is in force —
// the spec-declared `claims … role`, default "authenticated". Exposed for tooling
// (e.g. verifying the role is not BYPASSRLS, which would silently bypass the moat).
func (s *Spec) ConnectionRole() string { return s.claimRole() }

// SetRoleSQL renders the role switch a session runs so RLS evaluates under the
// (non-superuser, non-BYPASSRLS) connection role: `SET [LOCAL] ROLE <role>`, the
// role from claimRole(). local=true scopes it to the current transaction (the
// in-tx form db.WithRLS uses); local=false sets it for the session. The role is a
// spec identifier interpolated raw — a compile-time constant, like the definer
// schema and the inlined kind literals — so it carries no bound parameter.
func (s *Spec) SetRoleSQL(local bool) string {
	kw := "SET ROLE"
	if local {
		kw = "SET LOCAL ROLE"
	}
	return fmt.Sprintf("%s %s", kw, s.claimRole())
}

// SessionSetupSQL is the WithRLS-shaped statement sequence: the ordered SQL a caller
// runs at the top of an RLS transaction to enter a principal's session — first
// SetRoleSQL (assume the RLS connection role) then ClaimsSetSQL (install the minted
// claims blob into the GUC the policies read). Run them in order inside one tx; the
// SECOND statement binds the MintClaims/MintClaimsFor result to $1 (the first takes
// no args). The engine BUILDS these; the caller executes them (the moat — no driver
// here), exactly the sequence db.WithRLS hand-writes today. local scopes both to the
// current transaction.
func (s *Spec) SessionSetupSQL(local bool) []string {
	return []string{s.SetRoleSQL(local), s.ClaimsSetSQL(local)}
}
