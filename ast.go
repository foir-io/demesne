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
	Templates   []*Template
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
	// Role is the Postgres connection role a session assumes so RLS is in force
	// (the LHS of `SET [LOCAL] ROLE <role>`, the first statement of the WithRLS-
	// shaped session envelope — see SessionSetupSQL). It is the RLS-runtime sibling
	// of Setting/Cast: those say HOW claims are read, this says under WHICH role the
	// policies evaluate. "" ⇒ the default ("authenticated", via claimRole), so a spec
	// that omits it (or omits the whole `claims` block) renders byte-identically and
	// the engine bakes in no role name (EID-267 / EID-315 defaulting-fallback rule).
	Role string
	Pos  Pos
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
// validity).
//
// UNIFIED (post-WS1, see grants.go): both *Grant and *AclEdge satisfy the
// ReachGrant interface (EdgeTable / GranteeColumn / Granularity), Spec.ReachGrants
// enumerates the whole grant surface as one concept, and both definer bodies are
// built from the one shared grantEdgeExists shape. CRITICAL and honoured: the
// CONCEPT is unified, the physical store is NOT — a generic
// grants(grantee, target_kind, target_id, …) tuple table IS the Zanzibar
// relation-tuple the moat rejects; each shape keeps compiling to its specialized
// sargable RLS (a level-cascade definer vs a per-row definer, each over its OWN
// edge table), never a single runtime-checked store.
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
	// PermsCol is an OPTIONAL array column on RolesTable holding a role's
	// MATERIALIZED effective permission set (`permissions <col>`). It is the read
	// source the holds-resolver (Layer 2, EID-334) selects so a CUSTOM role — whose
	// permission set is operator-configured, not a vocabulary preset — resolves
	// correctly. "" ⇒ the rolestore carries no materialized column and the
	// holds-resolver expands each assignment's role KEY through the vocabulary
	// (preset → permissions) instead. PURELY ADDITIVE: no SQL emitter (role
	// definers, accessor enumerators, RLS) references it, so declaring it leaves all
	// generated output byte-identical.
	PermsCol string
	// IDCol / GrantedAtCol / GrantedByCol / RevokedByCol describe the
	// role-ASSIGNMENT-management write surface (Layer 3, EID-334) — the columns the
	// generated assign / revoke / list ops touch beyond the read-resolution columns
	// above. IDCol is the assignment's primary key ("" ⇒ the "id" convention, see
	// assignmentPK); GrantedAtCol/GrantedByCol are the grant-audit columns (timestamp
	// + grantor); RevokedByCol is the revoker companion to RevokedCol. Each is
	// OPTIONAL — when "" the generated write simply omits that column — and all are
	// PURELY ADDITIVE: no read emitter (role definers, RLS, accessor enumerators)
	// references them, so declaring them leaves all generated authz output
	// byte-identical (the write builders are a separate, opt-in surface).
	IDCol        string
	GrantedAtCol string
	GrantedByCol string
	RevokedByCol string
	Pos          Pos
}

// assignmentPK returns the role-assignment table's primary-key column — the
// declared override, else the "id" convention.
func (rs *RoleStore) assignmentPK() string {
	if rs.IDCol != "" {
		return rs.IDCol
	}
	return "id"
}

// Topology is the containment chain. Exactly one root (V1) — enforced in
// validation, not parsing.
type Topology struct {
	Levels []*Level
	Pos    Pos
}

// Level is one tier of the topology. A level may have ZERO parents (the root),
// ONE parent (a chain/tree link), or MULTIPLE parents (a DAG — WS3 Phase B: a
// node reachable through more than one container, e.g. an item filed under a team
// OR a folder). Virtual levels emit no scope column / claim key (the operator
// anchors at a virtual root).
type Level struct {
	Name    string
	Parents []string // empty = root; >1 = multi-parent (column-backed OR containment)
	Virtual bool
	// ScopeCol is the physical FK column that pins this level on a scoped sub-row
	// table — the LHS of every containment equality `<col> = claim(<key>)`. ""
	// defaults to the `<Name>_id` convention. Declaring it de-Foirs the assumption
	// that a tenancy FK is named `<level>_id` (EID-278 / v3 WS4).
	ScopeCol string
	// ClaimKey is the JWT claim key that carries this level's id — the RHS of every
	// containment equality, the claims-contract entry, the value a session mints.
	// "" defaults to the `<Name>_id` convention. Declared INDEPENDENTLY of ScopeCol:
	// the table column and the claim that selects it may be named differently
	// (e.g. column `tenant_ref`, claim `tnt`) (EID-278 / v3 WS4).
	ClaimKey string
	Pos      Pos
}

// isRoot reports whether the level has no parent.
func (l *Level) isRoot() bool { return len(l.Parents) == 0 }

// scopeColumn is the physical FK column that pins this level on a scoped sub-row
// table — the declared override, else the `<Name>_id` convention (EID-278).
func (l *Level) scopeColumn() string {
	if l.ScopeCol != "" {
		return l.ScopeCol
	}
	return l.Name + "_id"
}

// claimKey is the JWT claim key carrying this level's id — the declared override,
// else the `<Name>_id` convention (EID-278).
func (l *Level) claimKey() string {
	if l.ClaimKey != "" {
		return l.ClaimKey
	}
	return l.Name + "_id"
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
	// Binds is the subject's distinguished plane role, declared explicitly (EID-265
	// WS2) rather than inferred from shape: "owner" (the per-record owner principal
	// whose claim the descriptor / owner axis resolves against) or "admin" (the
	// role-resolution principal whose claim drives the is_<level>_admin definers).
	// "" for subjects that bind no plane (e.g. the operator, or a no-claim service).
	Binds string
	Pos   Pos
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

// Template is a named, reusable set of object permissions — the GENERIC,
// app-defined replacement for the removed `settings`/`platform` sugar. An object
// applies it with `use <name>` and inherits its permission lines; the object
// supplies its OWN table / scope / relations. A template carries ZERO table,
// scope, relation or domain detail — only permission lines built from the generic
// terms (@scoped, @open, owner/grant/role relations, mode, boolean algebra) — so
// the engine stays domain-word-free and the APP composes and names its own
// access patterns (`contained`, `customer_owned`, …) and applies them uniformly.
// Templates are resolved into the using object's Perms at parse time
// (expandTemplates), so every downstream pass (validation, emission) sees an
// ordinary Object — a template is pure sugar with no effect on emission.
type Template struct {
	Name  string
	Perms []*Perm
	Pos   Pos
}

// Object is a governed table + its object-relative permissions.
type Object struct {
	Name  string
	Table string
	// PK is the object table's primary-key column — the row identity the engine
	// references in edge/grant/kernel predicates, the point-check, and (for a
	// level-entity object) the level self column. "" defaults to the `id`
	// convention. Declaring it de-Foirs the assumption that every governed table's
	// PK is named `id` (EID-278 / v3 WS4).
	PK    string
	Level string // non-empty if this object IS a topology level node (its
	// own pk = the level; self column is the table PK, operator is
	// ungated) — the admin/level-entity plane (e.g. projects)
	Scoped    []string // levelchain — the root-anchored prefix of the chain
	Relations []*Relation
	Perms     []*Perm
	// Use names a Template whose permission lines this object inherits ("" = none).
	// Omit drops named verbs from the inherited template (e.g. an append-only table
	// that wants no update/delete policy). The object's OWN permission lines override
	// the template's same-verb line. All three are reconciled in expandTemplates,
	// which materialises the final Perms before validation/emission.
	Use  string
	Omit []string
	Pos  Pos
}

// IsLevelEntity reports whether the object is the entity for a topology level
// (vs a sub-row carrying the level FK columns).
func (o *Object) IsLevelEntity() bool { return o.Level != "" }

// pk returns the object table's primary-key column — the declared override, else
// the `id` convention (EID-278).
func (o *Object) pk() string {
	if o.PK != "" {
		return o.PK
	}
	return "id"
}

// HasGrantStore reports whether the object is a content object with an access grant
// store — a descriptor `grants` edge OR a `via grant` relation. Such objects get a
// generated accessor enumerator (auth.<table>_accessors) and a ResourceAccessSurface.
// Lets callers (handlers) enumerate grant objects without caring which form is used.
func (o *Object) HasGrantStore() bool { return objectGrantEdge(o) != nil }

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
// An owner ViaColumn may carry an optional discriminator
// (`via <id_col> where <kind_col> = "<val>"`) so several owner kinds share one
// id column gated by a kind column — the unified (owner_id, owner_kind) shape,
// mirroring the AclEdge grant discriminator. DiscrimCol == "" ⇒ plain column.
type ViaColumn struct {
	Column     string
	DiscrimCol string
	DiscrimVal string
}

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

// ViaClosure: `via closure <Closure>(<anc>,<desc>) base <Base>(<id>,<parent>) on <col>`
// — UNBOUNDED-depth reachability over a self-referential hierarchy (WS3 Phase C).
// The base table is the hierarchy (each row's <parent> points at another row's
// <id>); the closure table materialises its transitive-reflexive closure as
// (ancestor, descendant) pairs. The compiler GENERATES the closure-maintenance
// trigger (on the base table) and an indexed reachability lookup definer; the RLS
// term tests `reachable(<subject claim>, <Col>)` — the row's hierarchy column
// <Col> is reachable from the subject's granted node. This is the RLS-native
// analogue of Zanzibar's Leopard index; its write-amplification is an EXPLICIT,
// opt-in spec decision (cost class Closure), never silently emitted.
type ViaClosure struct {
	Closure       string // closure table (ancestor, descendant) pairs
	AncestorCol   string
	DescendantCol string
	Base          string // the self-referential hierarchy table
	BaseID        string // base PK column
	BaseParent    string // base self-FK (points at BaseID); NULL at a root
	Col           string // the object row's column holding its node id (the descendant)
}

// ViaGroup: `via group <Closure>(<group>,<member>) edge <Edge>(<member>,<group>) on <col>`
// — NESTED GROUPS (Demesne v3 WS2): unbounded group-in-group membership over a
// MANY-TO-MANY membership edge (a member may belong to many groups; a group may
// belong to many groups — a DAG, unlike via-closure's single-parent tree). The
// Edge is the direct-membership relation (`member ∈ group`); the Closure
// materialises its transitive closure as (group, member) pairs. The compiler
// GENERATES a statement-level closure-REBUILD trigger on the Edge (a recursive-CTE
// recompute — correct for inserts, deletes, and re-grouping alike) and an indexed
// membership-lookup definer; the RLS term tests `<Closure>_member(<Col>, <claim>)`
// — the caller's claim is a transitive member of the group named by the row's
// <Col>. The RLS-native analogue of a Zanzibar userset-of-usersets; its
// write-amplification is the explicit, opt-in cost class Closure.
type ViaGroup struct {
	Closure    string // transitive-closure table: (group, member) pairs
	GroupCol   string // closure group column
	MemberCol  string // closure (transitive) member column
	Edge       string // the M2M direct-membership edge table
	EdgeMember string // edge member column ("member ∈ group")
	EdgeGroup  string // edge group column
	Col        string // the object row's column naming the granted group
}

// ViaObject: `via object <Object>-><verb> on <col>` — a cross-object permission
// reference (Demesne v3 WS3, the general tuple_to_userset). This object's grant
// is "the caller passes <Object>'s <verb> permission for the RELATED row named by
// this object's <col>." It compiles to a SECURITY DEFINER that runs the OTHER
// object's FULL <verb> RLS predicate for the row at <col> — so the borrowed
// permission may itself be roles / ACLs / groups / boolean, evaluated at the
// related object, still entirely in the database. (Supersedes the never-finished
// ViaComposition.)
type ViaObject struct {
	Object string // the other object whose permission is borrowed
	Verb   string // its permission verb
	Col    string // this object's FK column naming the related row
}

// ViaGrant: `via grant <Table>(record, kind, principal, access) [where <col> = "<v>"]`
// — a 4-column access-class ACL edge as a GENERIC relation: the de-prescribed form
// of the descriptor's `grants` block. The relation's TYPES name the principal
// KINDS it may be granted to (`grantee: customer | admin via grant …`); a
// permission references it with an access class (`grantee:read` / `:write` /
// `:delete`, or bare `grantee` → the op's class). It compiles to one
// EXISTS-over-the-edge SECURITY DEFINER per kind at the requested access —
// auth.<Table>_grants[_<kind>](<principal>, record, access) — the SAME shape and
// names the descriptor emits, discriminated by a constant when several relations
// share one physical store (the unified resource_acl). This is what lets a content
// object drop its `descriptor {}` for plain `owner`/`admin_owner`/`grantee`
// relations with byte-identical generated SQL. Structurally mirrors AclEdge; kept
// a distinct Repr value type so the grammar and emitters treat it as a first-class
// relation, not a descriptor sub-part.
type ViaGrant struct {
	Table        string
	RecordCol    string
	KindCol      string
	PrincipalCol string
	AccessCol    string
	DiscrimCol   string // "" when the store is not shared (single-kind store)
	DiscrimVal   string // the constant this relation's rows carry in DiscrimCol
}

// ArgSrc is one argument of a ViaMemberIn check: either a claim key (`@sub`) or a
// row column (a bare identifier). Exactly one field is set.
type ArgSrc struct {
	Claim string // a claim key, read via the claims accessor
	Col   string // a column on the object's own row
}

// ViaMemberIn: `via memberin <level>(<principal-src>, <scope-src>)` (v3 WS6) — a
// scoped role-membership check: does the PRINCIPAL hold ANY admin role assignment
// at the SCOPE (a topology level, e.g. tenant)? Both args bind to either a claim
// (`@sub`) or a row column. The one primitive expresses two control-plane shapes:
//   - "the caller administers THIS tenant" (tenants picker): principal @sub, scope
//     the row's id — auth.admin_memberin_tenant(<sub claim>, id);
//   - "the row's admin is in MY session tenant" (admin_users co-tenant, the modern
//     session-scoped replacement for the legacy admins_share_tenant peer rule):
//     principal the row's id, scope @tenant_id — admin_memberin_tenant(id, <tenant_id claim>).
//
// Compiles to a SECURITY DEFINER EXISTS over the role store (assignment with the
// scope column = the scope arg, principal = the principal arg, kind = admin, not
// revoked). Cost class Definer.
type ViaMemberIn struct {
	Level     string
	Principal ArgSrc
	Scope     ArgSrc
}

func (ViaMemberIn) isRepr()    {}
func (ViaColumn) isRepr()      {}
func (ViaEdge) isRepr()        {}
func (ViaRole) isRepr()        {}
func (ViaComposition) isRepr() {}
func (ViaGroup) isRepr()       {}
func (ViaObject) isRepr()      {}
func (ViaClosure) isRepr()     {}
func (ViaGrant) isRepr()       {}

// Perm is an object permission: a verb, a union expression, the layer tag(s),
// and (optionally) the table-op / pdp-verb it maps to and a row guard.
type Perm struct {
	Verb   string
	Expr   []*Term   // the flat set of leaf terms (definer generation + validation)
	Tree   *PermNode // the boolean expression structure (emission); leaves are Expr
	Layers []string  // "rls" | "pdp" | "kernel"
	Maps   string    // mapref; "" if absent
	Guard  *Guard    // optional bounded row-attribute predicate; nil if absent
	Pos    Pos
}

// PermNode is a node of a permission's boolean expression (v3 WS1 — Zanzibar-style
// algebra over Postgres RLS): a leaf term, or a union / intersection / negation of
// sub-nodes. A union-only expression (a flat `+`/`or` list) is a single "or" node
// (or a bare leaf) and emits identically to the historical flat OR, so existing
// specs are byte-for-byte unchanged. Intersection emits `AND`; negation emits a
// fail-closed `NOT COALESCE(<pred>, true)` (an indeterminate exclusion denies).
type PermNode struct {
	Op   string      // "leaf" | "or" | "and" | "not"
	Term *Term       // Op == "leaf"
	Kids []*PermNode // Op == "or"/"and" (n-ary); "not" has exactly one child
}

// Leaves returns every leaf Term in the tree (depth-first), so code that needs the
// flat term set (definer generation, validation) is unaffected by the structure.
func (n *PermNode) Leaves() []*Term {
	if n == nil {
		return nil
	}
	if n.Op == "leaf" {
		return []*Term{n.Term}
	}
	var out []*Term
	for _, k := range n.Kids {
		out = append(out, k.Leaves()...)
	}
	return out
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
	// ExcludeRel is set on an `@app_scope(exclude <rel>)` term (the de-prescribed
	// operator-reach): the broad no-claim reach EXCLUDES rows owned via <rel> (an
	// owner ViaColumn), so an admin-owned row stays operator-private. Generalises
	// the descriptor's AdminOwner-coupled @app_scope exclusion into a composable,
	// existence-based term. "" ⇒ plain @app_scope.
	ExcludeRel string
	// A column-condition (visibility) term — `mode <col> = "<v>" [for <subject>]`
	// — the de-prescribed form of the descriptor's read modes. ModeCol != "" marks
	// the term; it admits a row whose ModeCol equals ModeVal (a read-only grant,
	// listed only on the read permission). ModeScope optionally confines it to a
	// principal PLANE (`for admin` → operators only, never a customer / the public
	// API).
	ModeCol   string
	ModeVal   string
	ModeScope string
	// GrantRef names a declared Grant (`via grant <name>`) referenced as a PERMISSION
	// term: the verb is conferred by that grant's reach (e.g. the operator's scoped
	// impersonation), emitted as a top-level branch. When a permission's only grant is
	// grant-references (no @scoped / owner / role term), the containment block is
	// suppressed — so the verb is granted ONLY to the grant's holders, not in-scope
	// members (e.g. an operator-only write that excludes the tenant's own admins). The
	// grant + its reaching subject are app-defined, so no framework domain word leaks
	// in. "" for any other term form.
	GrantRef string
	// KindVal is set on a `@kind("<value>")` term — a TYPED-SUBJECT match on the
	// caller's principal-kind claim (the RLS compilation of Zanzibar's typed wildcard,
	// e.g. `serviceaccount:*`). It admits a caller whose `kind` claim equals KindVal
	// (an app-defined value such as "service"). A containment-scoped grant term, like
	// owner — it replaces ad-hoc subject-string matching (`sub LIKE 'service:%'`) with
	// an exact match on a first-class kind dimension. "" otherwise.
	KindVal string
	Pos     Pos
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
