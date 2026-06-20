/**
 * Projection types — the plain-data wire contract between the Demesne Go engine (which
 * emits these as TypeScript literals) and this runtime (which reproduces the Go
 * builders over them). Each interface mirrors an exported Go projection struct; field
 * names are the lowerCamel of the Go field. NOTHING here is spec-specific: a tenant /
 * project / customer / role only ever appears as a value the emitter fills in.
 *
 * The split is deliberate and matches the Go codebase: these projections are the
 * `ClaimsContractEntries()` / `EmitAppSurface()` / `HoldsResolver()` / `GrantSurface()`
 * etc. outputs serialized to data; the *algorithms* over them live in the sibling
 * modules (claims.ts, holds.ts, …), exactly as Go hand-writes the runtime helpers in
 * the `demesne` library and only the `Render*Go` methods are codegen.
 */

/** A value bound into a parameterized statement. Go passes `[]any` with `nil` → SQL NULL. */
export type SqlArg = string | number | boolean | Date | null;

/**
 * A parameterized statement: the SQL text plus its ordered positional args ($1, $2, …).
 * The TS shape of a Go `(sql string, args []any)` return. The caller executes it under
 * the subject's claims + RLS role; the database decides.
 */
export interface ParamStatement {
  sql: string;
  args: SqlArg[];
}

// --- Claims contract + session (Layer 2) ------------------------------------

/**
 * One key of the machine-readable claims contract with WHERE its value comes from: a
 * topology level's scope id (`level` set) and/or one or more subjects' identity
 * (`subjects` non-empty). Mirrors Go `ClaimEntry`; Go's `nil` Subjects maps to `[]`.
 */
export interface ClaimEntry {
  key: string;
  level: string;
  subjects: string[];
}

/**
 * The typed identity a session presents: which subject acts, that subject's id, and the
 * scope id it holds at each topology level (keyed by level NAME, not claim key). Mirrors
 * Go `Principal`. `buildClaims` maps it onto the contract.
 */
export interface Principal {
  subject: string;
  id: string;
  scopes: Record<string, string>;
}

/**
 * The resolved claims/session envelope config (defaults already applied by the emitter):
 * the GUC the policies read, its cast, and the non-BYPASSRLS connection role a session
 * assumes. Mirrors the Go `claimSetting()` / `claimRole()` defaulting
 * (`request.jwt.claims` / `json` / `authenticated`).
 */
export interface ClaimsConfig {
  setting: string;
  cast: string;
  role: string;
}

// --- Verb PDP + app read surface (Layer 2) ----------------------------------

/** One emit-site's compiled decision table. Mirrors Go `PDP`. */
export interface Pdp {
  emitSite: string;
  /** procedure → required permission. */
  policy: Record<string, string>;
  /** procedure → exemption reason. */
  ungoverned: Record<string, string>;
}

/**
 * One object's app-level read surface — the table + PK its point/batch/list statements
 * reference, plus the EID-350 fast-path/affordance/edit strings the engine precomputes
 * (the runtime templates or passes them through; it never recomputes them). Mirrors Go
 * `AppObjectSurface`. The empty string means "not applicable" for the optional members.
 */
export interface AppObjectSurface {
  object: string;
  table: string;
  pk: string;
  /** Qualified reverse fast-path fn (auth.<flat>_resources), or "". */
  flatListFn: string;
  /** Precomputed async-affordance read SQL, or "". */
  asyncCheckSQL: string;
  /** Precomputed write/edit point-check SQL, or "". */
  editCheckSQL: string;
}

// --- Vocabulary + holds-resolver (Layer 2) ----------------------------------

/** A role preset: a star (whole-vocabulary) preset, or a set of permission/preset refs. Mirrors Go `Preset`. */
export interface Preset {
  name: string;
  star: boolean;
  set: string[];
}

/** A permission vocabulary: its flat permission list, its presets, and its rank ladder (highest authority first). Mirrors Go `Vocabulary` (projected). */
export interface Vocabulary {
  name: string;
  permissions: string[];
  presets: Preset[];
  rank: string[];
}

/**
 * The "principal + scope → effective permission set" read layout, projected from a
 * rolestore plus the vocabulary its roles draw from. Mirrors Go `HoldsResolver` (its
 * private `vocab` is inlined here).
 */
export interface HoldsResolver {
  // Assignment store.
  assignments: string;
  kindCol: string;
  kindVal: string;
  subjectCol: string;
  /** scope columns root→leaf (the containment chain). */
  scopeCols: string[];
  revokedCol: string;
  // Roles join.
  roleCol: string;
  rolesTable: string;
  rolesId: string;
  keyCol: string;
  /** the materialized effective-permission column, or "" when the rolestore declares none. */
  permsCol: string;
  vocab: Vocabulary;
}

/**
 * One active role assignment a principal holds at a scope. `scope` holds the
 * scope-column values root→leaf (an empty string = an unpinned/NULL level). Mirrors Go
 * `RoleAssignment`. `permissions` is consulted only when the resolver materializes perms.
 */
export interface RoleAssignment {
  scope: string[];
  roleKey: string;
  permissions: string[];
}

// --- Role-assignment management (Layer 3) -----------------------------------

/** The rolestore management write layout. Mirrors Go `RoleAssignmentSurface`. Optional audit columns are "" when undeclared. */
export interface RoleAssignmentSurface {
  assignments: string;
  pk: string;
  kindCol: string;
  kindVal: string;
  subjectCol: string;
  roleCol: string;
  scopeCols: string[];
  revokedCol: string;
  grantedAtCol: string;
  grantedByCol: string;
  revokedByCol: string;
  /** adopter context columns on the assignment tuple (written, projected, part of the touch conflict key). */
  extraCols: string[];
  // Roles join (for listForPrincipal).
  rolesTable: string;
  rolesId: string;
  keyCol: string;
  permsCol: string;
}

// --- Level-grant management (Layer 3) ---------------------------------------

/** A `grant … via edge` management write layout. Mirrors Go `GrantSurface`. Optional audit columns are "" when undeclared. */
export interface GrantSurface {
  name: string;
  level: string;
  table: string;
  granteeCol: string;
  levelCol: string;
  /** revoked filter ("" if none; NULL = active). */
  activeCol: string;
  /** expiry ("" if none; > now() = active). */
  expiresCol: string;
  pk: string;
  grantedByCol: string;
  revokedByCol: string;
  createdAtCol: string;
  /** adopter edge columns the grammar does not model (written + projected in declaration order). */
  extraCols: string[];
}

// --- Resource access / per-record ACL (Layer 3) -----------------------------

/**
 * An object's per-record access write/read layout, projected from its grant (ACL) store.
 * Mirrors Go `ResourceAccessSurface` (whose fields are unexported; the engine exposes
 * them via a Projection() accessor for the emitter).
 */
export interface ResourceAccessSurface {
  table: string;
  scopeCols: string[];
  modeCol: string;
  pk: string;
  /** the stored mode sentinels that open public read (the set behind IsReadMode). */
  readModes: string[];
  /** the principal kinds the grant list admits (the set behind GrantKindAllowed). */
  grantKinds: string[];
  aclTable: string;
  recordCol: string;
  kindCol: string;
  principalCol: string;
  accessCol: string;
  /** "" when the grant store is single-kind (not shared). */
  discrimCol: string;
  discrimVal: string;
  /** qualified accessor enumerator, e.g. auth.records_accessors. */
  accessorFn: string;
}

// --- Delegation cap (Layer 3) -----------------------------------------------

/**
 * The outcome of an intersection-cap check: whether a grantor may confer `requested`,
 * and — when not — exactly why. `unknown` and `excess` are disjoint, each sorted +
 * de-duplicated. Mirrors Go `DelegationCap`.
 */
export interface DelegationCap {
  allowed: boolean;
  /** requested permissions NOT in the vocabulary at all (a typo / stale key). */
  unknown: string[];
  /** requested permissions that ARE valid but the grantor does not hold (the cap violation). */
  excess: string[];
}
