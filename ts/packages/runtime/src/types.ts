

export type SqlArg = string | number | boolean | Date | null;

export interface ParamStatement {
  sql: string;
  args: SqlArg[];
}

export interface ClaimEntry {
  key: string;
  level: string;
  subjects: string[];
}

export interface Principal {
  subject: string;
  id: string;
  scopes: Record<string, string>;
}

export interface SubjectIdentity {
  name: string;
  identifies: string;
}

export interface LevelClaim {
  name: string;
  claimKey: string;
  virtual: boolean;
}

export interface Claims {
  setting: string;
  cast: string;
  role: string;
  contract: string[];
  entries: ClaimEntry[];
  subjects: SubjectIdentity[];
  levels: LevelClaim[];
}

export interface Pdp {
  emitSite: string;

  policy: Record<string, string>;

  ungoverned: Record<string, string>;
}

export interface AppObjectSurface {
  object: string;
  table: string;
  pk: string;

  flatListFn: string;

  asyncCheckSQL: string;

  editCheckSQL: string;
}

export interface Preset {
  name: string;
  star: boolean;
  set: string[];
}

export interface Vocabulary {
  name: string;
  permissions: string[];
  presets: Preset[];
  rank: string[];
}

export interface HoldsResolver {

  assignments: string;
  kindCol: string;
  kindVal: string;
  subjectCol: string;

  scopeCols: string[];
  revokedCol: string;

  roleCol: string;
  rolesTable: string;
  rolesId: string;
  keyCol: string;

  permsCol: string;
  vocab: Vocabulary;
}

export interface RoleAssignment {
  scope: string[];
  roleKey: string;
  permissions: string[];
}

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

  extraCols: string[];

  rolesTable: string;
  rolesId: string;
  keyCol: string;
  permsCol: string;
}

export interface GrantSurface {
  name: string;
  level: string;
  table: string;
  granteeCol: string;
  levelCol: string;

  activeCol: string;

  expiresCol: string;
  pk: string;
  grantedByCol: string;
  revokedByCol: string;
  createdAtCol: string;

  extraCols: string[];
}

export interface ResourceAccessSurface {
  table: string;
  scopeCols: string[];
  modeCol: string;
  pk: string;

  readModes: string[];

  grantKinds: string[];
  aclTable: string;
  recordCol: string;
  kindCol: string;
  principalCol: string;
  accessCol: string;

  discrimCol: string;
  discrimVal: string;

  accessorFn: string;
}

export interface DelegationCap {
  allowed: boolean;

  unknown: string[];

  excess: string[];
}
