package demesne

// AST for the Demesne spec language (RFC §8.2). One Spec is the parsed,
// not-yet-validated representation of a platform's authorization model:
// topology (the containment chain), vocabularies (PDP verb grammars),
// subjects (who acts), objects (what is acted upon + the object-relative
// permissions), and the two PDP procedure-binding blocks.

// Pos is a 1-based source line, carried for diagnostics.
type Pos struct{ Line int }

// Spec is a whole parsed authorization model.
type Spec struct {
	Topology    *Topology
	Vocabs      []*Vocabulary
	Subjects    []*Subject
	Objects     []*Object
	Procedures  []*Procedures
	Ungoverned  []*Ungoverned
	FieldScopes []*FieldScopes
	RoleStores  []*RoleStore
	Grants      []*Grant
	Claims      *ClaimsAccessor
	// DefinerSchema is the Postgres schema the generated SECURITY DEFINER kernel
	// lives in (and that the emitted policies qualify their calls with). ""
	// defaults to "auth" — Foir's schema — so a spec that omits the `definers
	// schema` block emits byte-identically. De-Foirs the assumption that trusted
	// functions live in a schema literally named `auth`.
	DefinerSchema string
}

// definerSchema returns the schema for the generated definer kernel (default
// "auth"). Every `auth.<fn>` reference in the emitted SQL is qualified with it.
func (s *Spec) definerSchema() string {
	if s.DefinerSchema != "" {
		return s.DefinerSchema
	}
	return "auth"
}

// ClaimsAccessor declares HOW a claim key is read from the request context — the
// SQL expression every emitted RLS policy uses to read the subject / scope ids.
// It de-Foirs the one assumption baked into every policy: that claims arrive as
// a JSON blob in the `request.jwt.claims` GUC. A different deployment may use a
// jsonb blob or a differently-named setting. Nil ⇒ the default
// (`current_setting('request.jwt.claims', true)::json ->> '<key>'`), so a spec
// that omits the block emits byte-identically to before.
type ClaimsAccessor struct {
	Setting string // GUC name, e.g. "request.jwt.claims"
	Cast    string // "json" | "jsonb"
	Pos     Pos
}

// Grant is a level-scoped reachability grant store: an edge table whose rows
// confer reach into a topology level to a granted subject. It is the general
// form of "a relationship grants access" — where a Descriptor's `grants` edge
// confers reach to one OBJECT ROW (an ACL), a Grant confers reach to a whole
// LEVEL subtree (containment). It compiles to a SECURITY DEFINER `EXISTS` over
// the edge store (`auth.<table>_reach(grantee, <level>_id)`) that is BOTH a
// disjunct of the level's role-resolution definer AND a top-level OR branch on
// every object scoped under that level. This replaces an unconditional
// membership operator (a god-flag) with a scoped, revocable, expiring grant:
// the grantee reaches exactly the levels it holds an active grant for, nothing
// more. Cross-plane management of the store (who may write a grant) is the edge
// table's own object write rule (owner-origination, no self-escalation); the
// root-of-trust bootstrap lives in the BYPASSRLS plane, never in the grammar.
//
// CONVERGENCE NOTE (WS3, EID-265). A Grant and a Descriptor's `grants` edge
// (AclEdge) are the SAME primitive at the concept level: a tuple
// (grantee, target, access, validity) in an edge table, owner-originated,
// conferring reach, enforced by a SECURITY DEFINER EXISTS. They differ only in
// the target node — a Grant reaches a whole LEVEL subtree (cascade; a top branch
// on every object under the level + a disjunct of the level's role definer); an
// AclEdge reaches ONE object row (no cascade; inside one descriptor expansion) —
// and in cost class. Under WS3's "topology is a cost-classed reachability DAG"
// they unify into one declarative notion ("an edge confers reach to a node of
// type X", parameterized by target granularity / access / principal-kind /
// validity). Deliberately KEPT SEPARATE until after the WS1 inversion, so
// today's shapes aren't baked into the general model. CRITICAL: unify the
// declarative CONCEPT, never the physical store — a generic
// grants(grantee, target_kind, target_id, …) tuple table IS the Zanzibar
// relation-tuple the moat rejects; each shape must keep compiling to its
// specialized sargable RLS (inline column / per-object definer / level-cascade
// definer), not a single runtime-checked store.
type Grant struct {
	Name       string // grant name (referenced by `subject … reach via grant <name>`)
	Level      string // the topology level the grant confers reach at
	Table      string // the edge store
	GranteeCol string // the granted-subject id column (matched against the grantee claim)
	LevelCol   string // the level-scope column (e.g. tenant_id)
	ActiveCol  string // revoked/active filter column; "" if none (NULL ⇒ active)
	ExpiresCol string // expiry column; "" if none (> now() ⇒ active)
	Pos        Pos
}

// RoleStore declares where a subject's role assignments live, so the compiler
// can GENERATE the role-resolution SECURITY DEFINER functions (V9 — it owns the
// whole definer surface, no opaque trusted fns). The generated body is the
// uniform EXISTS:
//
//	EXISTS(SELECT 1 FROM <Assignments> ra JOIN <RolesTable> r ON r.<RolesID>=ra.<RoleCol>
//	       WHERE ra.<KindCol>='<KindVal>' AND ra.<SubjectCol>=sub
//	         AND <scope match> AND ra.<RevokedCol> IS NULL AND r.<KeyCol> IN (<keyset>))
//
// The scope match + key set come from the relation (level + rank threshold) and
// the preset @level annotations.
type RoleStore struct {
	Name        string
	Assignments string   // assignment table
	KindCol     string   // principal-kind column
	KindVal     string   // its required value (e.g. "admin")
	SubjectCol  string   // principal-id column
	ScopeCols   []string // scope columns, root→leaf (e.g. tenant_id, project_id)
	RoleCol     string   // FK column → RolesTable
	RolesTable  string
	RolesID     string // PK column on RolesTable
	KeyCol      string // role-key column on RolesTable
	RevokedCol  string
	Pos         Pos
}

// Topology is the containment chain. Exactly one root (V1) — enforced in
// validation, not parsing.
type Topology struct {
	Levels []*Level
	Pos    Pos
}

// Level is one tier of the chain. Parent == "" marks the root. Virtual levels
// emit no scope column / claim key (the operator anchors at a virtual root).
type Level struct {
	Name    string
	Parent  string
	Virtual bool
	Pos     Pos
}

// Vocabulary is a PDP verb grammar: the permission keys, the built-in role
// presets, and (optionally) the delegation rank ladder.
type Vocabulary struct {
	Name        string
	Permissions []string // PERMKEYs, e.g. "content:write"
	Presets     []*Preset
	Rank        []string // high → low; nil if absent
	Pos         Pos
}

// Preset is a built-in role → permission bundle. Star == true is the "*"
// (whole-vocabulary) bundle; otherwise Set lists PERMKEYs and/or preset refs
// (an IDENT naming another preset).
type Preset struct {
	Name  string
	Level string // topology level the role binds at ("" if unscoped); drives role-store scope
	Set   []string
	Star  bool
	Pos   Pos
}

// Subject is an actor class anchored at a topology level with a reach mode.
// Identifies names the claim key (e.g. "customer_id", "sub"); Membership, when
// present, resolves identity through a table+flag the compiler owns (V9).
type Subject struct {
	Name       string
	Anchor     string
	Reach      string // "self" | "descendants" | "grant"
	Identifies string // claim key; "" if unspecified
	Membership *Membership
	Roles      string // vocabulary name; "" if none/unspecified
	RolesNone  bool
	ReachGrant string // grant name when Reach == "grant" (reach conferred by a Grant edge)
	Pos        Pos
}

// Membership is `via membership <Table>(<IDCol>, <FlagCol>) [active <Col> = "<Val>"]`
// — the compiler generates `auth.is_<FlagCol-ish>` as
// EXISTS(<Table> WHERE <IDCol>=sub AND <FlagCol> [AND <ActiveCol>='<ActiveVal>']).
type Membership struct {
	Table     string
	IDCol     string
	FlagCol   string
	ActiveCol string // "" if no active filter
	ActiveVal string
}

// Object is a governed table + its object-relative permissions.
type Object struct {
	Name       string
	Table      string
	Level      string   // non-empty if this object IS a topology level node (its
	                     // own pk = the level; self column is `id`, operator is
	                     // ungated) — the admin/level-entity plane (e.g. projects)
	Scoped     []string // levelchain — the root-anchored prefix of the chain
	Relations  []*Relation
	Descriptor *Descriptor // optional per-record access descriptor (§5.3)
	Perms      []*Perm
	Pos        Pos
}

// IsLevelEntity reports whether the object is the entity for a topology level
// (vs a sub-row carrying the level FK columns).
func (o *Object) IsLevelEntity() bool { return o.Level != "" }

// Descriptor is the per-record ownership / ACL primitive (RFC §5.3) that
// subsumes sharing (EID-263). It declares:
//   - Owner — who may EDIT the descriptor (owner-origination; an inline FK axis,
//     distinct from the grantees);
//   - Modes — the spec-declared access modes the object supports (an owner-only
//     baseline, column read-gates, and explicit principal-kind grant lists), with
//     the per-record selection stored in ModeCol;
//   - Grants — the record_acl edge backing the explicit lists, principal-kind-
//     tagged so admins and customers coexist without merging their stores.
//
// A permission references the whole descriptor via the `@descriptor` term; the
// RLS emitter (step 3) expands it to inline (owner, public) + definer (the
// list) predicates resolved at the permission's access class.
type Descriptor struct {
	Owner   *Relation // the owner axis (typeref via a FK column)
	ModeCol string    // per-record mode column; "" if modes aren't column-driven
	Modes   []Mode    // supported modes
	Grants  *AclEdge  // record_acl edge; nil if no explicit list
	Pos     Pos
}

// Mode is one supported access mode of a descriptor. Modes are spec-declared
// (EID-265 WS2) — the engine carries NO fixed vocabulary (no private/public/
// customers/admins allowlist, no project/world scope words):
//   - "private": the owner-only baseline. Emits no extra predicate (the owner
//     axis already covers it); decorative — documents that the mode column's
//     default value is a recognised mode.
//   - "read":    a column read-gate. Opens READ when ModeCol = Value (the declared
//     sentinel). Generalises the former public(project)/public(world) — the
//     "scope" was only ever a second sentinel string, so it is one now.
//   - "list":    an explicit grant list over the record_acl edge, filtered to the
//     principal kind Value. Opens read/write/delete at the permission's access
//     class. Generalises the former customers/admins list modes.
type Mode struct {
	Kind  string // "private" | "read" | "list"
	Value string // read → the ModeCol sentinel; list → the principal kind; "" for private
	Pos   Pos
}

// AclEdge is the `record_acl(record_col, kind_col, principal_col, access_col)`
// grant store: one row per (record, principal-kind, principal, access level).
type AclEdge struct {
	Table        string
	RecordCol    string
	KindCol      string
	PrincipalCol string
	AccessCol    string
}

// Relation is an edge declaration: a name, the target type(s), how it is
// physically represented, and (for record→record edges) its kind.
type Relation struct {
	Name  string
	Types []string // typeref, e.g. ["customer","service"]
	Repr  Repr
	Kind  string // "composition" | "association" | ""
	Pos   Pos
}

// Repr is how a relation is stored. Exactly one concrete type.
type Repr interface{ isRepr() }

// ViaColumn: `via <fk_column>` — a foreign-key column on this object's table.
type ViaColumn struct{ Column string }

// ViaEdge: `via edge <Table>(<from>,<to>[,<kind>])` — an edge/junction table.
type ViaEdge struct {
	Table string
	Cols  []string // 2 or 3 columns
}

// ViaRole: `via role[(rank >= <Preset>)]` — resolves through role assignments.
type ViaRole struct {
	HasRank bool
	RankMin string
}

// ViaComposition: `via composition <Table>` — 1-hop composition-parent cascade.
type ViaComposition struct{ Table string }

func (ViaColumn) isRepr()      {}
func (ViaEdge) isRepr()        {}
func (ViaRole) isRepr()        {}
func (ViaComposition) isRepr() {}

// Perm is an object permission: a verb, a union expression, the layer tag(s),
// and (optionally) the table-op / pdp-verb it maps to and a row guard.
type Perm struct {
	Verb   string
	Expr   []*Term  // union (∪)
	Layers []string // "rls" | "pdp" | "kernel"
	Maps   string   // mapref; "" if absent
	Guard  *Guard   // optional bounded row-attribute predicate; nil if absent
	Pos    Pos
}

// Guard is the single sanctioned ABAC predicate (otherwise a §8.2 non-goal): a
// bounded row-column comparison to a literal (e.g. `status <> "CHURNED"`),
// applied to the same-level grant branches — used by the admin/level-entity
// plane (a churned project is unreachable via project-role or session, but a
// platform/tenant admin still sees it).
type Guard struct {
	Col string
	Op  string // "=" | "<>"
	Val string
	Pos Pos
}

// Term is one operand of a union. Exactly one of the three forms is set:
//   - Builtin  != ""  → `@<builtin>` (e.g. app_scope)
//   - WalkVerb != ""  → `<Ident>-><WalkVerb>` (a role walk into a parent object)
//   - otherwise        → `<Ident>` (a relation reference)
type Term struct {
	Ident      string
	WalkVerb   string
	Builtin    string
	SessionRel string // for `@session(<rel>)` — a session-self-gated role grant
	Pos        Pos
}

// Procedures binds RPC procedures to required permissions for one PDP emit-site
// (V10): the admin vocabulary → platform authz.Policy; customer → api-public.
type Procedures struct {
	EmitSite string
	Entries  []ProcEntry
	Pos      Pos
}

// ProcEntry is `<PROC> -> <PERMKEY>`.
type ProcEntry struct {
	Proc string
	Perm string
	Pos  Pos
}

// Ungoverned lists RPCs deliberately exempt from a PDP emit-site, each with a
// reason (V8 "no silent caps").
type Ungoverned struct {
	EmitSite string
	Entries  []UngovEntry
	Pos      Pos
}

// UngovEntry is `<PROC> : "<reason>"`.
type UngovEntry struct {
	Proc   string
	Reason string
	Pos    Pos
}

// FieldScopes binds GraphQL root fields to required scopes for one api-public
// emit-site — the customer/scoped-token scope gate (V10's second site). Unlike
// the admin `procedures` (Connect procs → one vocabulary), this is multi-plane
// (customer + api-key + operator scopes) and field-keyed; it carries the STATIC
// (model/operation-independent) table, the per-model rule being a separate
// vocabulary fact (the customer records:<verb>:* perms).
type FieldScopes struct {
	Site    string
	Entries []FieldScopeEntry
	Pos     Pos
}

// FieldScopeEntry is `<field> -> <scope>`.
type FieldScopeEntry struct {
	Field string
	Scope string
	Pos   Pos
}
