package demesne

// Decision is the policy decision point's answer for a call.
type Decision string

// The three decisions.
const (
	Allow       Decision = "allow"
	Deny        Decision = "deny"
	NotGoverned Decision = "ungoverned"
)

// ClaimEntry is one key of the claims contract, with the level it scopes and the subjects it identifies.
type ClaimEntry struct {
	Key      string   `json:"key"`
	Level    string   `json:"level"`
	Subjects []string `json:"subjects"`
}

// SubjectIdentity names the claim that identifies a subject.
type SubjectIdentity struct {
	Name       string `json:"name"`
	Identifies string `json:"identifies"`
}

// LevelClaim names the claim that carries a topology level's scope.
type LevelClaim struct {
	Name     string `json:"name"`
	ClaimKey string `json:"claimKey"`
	Virtual  bool   `json:"virtual"`
}

// Claims is a spec's claims projection: the session setting and role, and the contract every minted claim set obeys.
type Claims struct {
	Setting  string            `json:"setting"`
	Cast     string            `json:"cast"`
	Role     string            `json:"role"`
	Contract []string          `json:"contract"`
	Entries  []ClaimEntry      `json:"entries"`
	Subjects []SubjectIdentity `json:"subjects"`
	Levels   []LevelClaim      `json:"levels"`
}

// Principal is who a session acts for: a subject, its id, and its scope at each level.
type Principal struct {
	Subject string            `json:"subject"`
	ID      string            `json:"id"`
	Scopes  map[string]string `json:"scopes"`
}

// PDP is a spec's policy decision point for one emit site: the permission governing each procedure, and the
// procedures it leaves ungoverned, with why.
type PDP struct {
	EmitSite   string            `json:"emitSite"`
	Policy     map[string]string `json:"policy"`
	Ungoverned map[string]string `json:"ungoverned"`
}

// AppObjectSurface is an object's application-level read checks.
type AppObjectSurface struct {
	Object        string `json:"object"`
	Table         string `json:"table"`
	PK            string `json:"pk"`
	FlatListFn    string `json:"flatListFn"`
	AsyncCheckSQL string `json:"asyncCheckSQL"`
	EditCheckSQL  string `json:"editCheckSQL"`
}

// Preset is a vocabulary's named set of permissions.
type Preset struct {
	Name string   `json:"name"`
	Star bool     `json:"star"`
	Set  []string `json:"set"`
}

// Implication is a permission that brings others with it.
type Implication struct {
	Perm string   `json:"perm"`
	Star bool     `json:"star"`
	Set  []string `json:"set"`
}

// Vocabulary is a spec's set of permissions, presets and their ranking.
type Vocabulary struct {
	Name         string        `json:"name"`
	Permissions  []string      `json:"permissions"`
	Implications []Implication `json:"implications,omitempty"`
	Presets      []Preset      `json:"presets"`
	Rank         []string      `json:"rank"`
}

// HoldsResolver is a rolestore's projection: where role assignments are kept, and the vocabulary their roles grant.
type HoldsResolver struct {
	Assignments string     `json:"assignments"`
	KindCol     string     `json:"kindCol"`
	KindVal     string     `json:"kindVal"`
	SubjectCol  string     `json:"subjectCol"`
	ScopeCols   []string   `json:"scopeCols"`
	RevokedCol  string     `json:"revokedCol"`
	Plane       string     `json:"plane,omitempty"`
	PlaneDepth  *int       `json:"planeDepth,omitempty"`
	RoleCol     string     `json:"roleCol"`
	RolesTable  string     `json:"rolesTable"`
	RolesID     string     `json:"rolesId"`
	KeyCol      string     `json:"keyCol"`
	PermsCol    string     `json:"permsCol"`
	Vocab       Vocabulary `json:"vocab"`
}

// RoleAssignment is one role a subject holds, at a scope, with the permissions the role grants.
type RoleAssignment struct {
	Scope       []string `json:"scope"`
	RoleKey     string   `json:"roleKey"`
	Permissions []string `json:"permissions"`
}

// RoleAssignmentSurface is where a rolestore's assignments are written.
type RoleAssignmentSurface struct {
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

// GrantSurface is where a reach grant's edges are written.
type GrantSurface struct {
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

// ResourceAccessSurface is an object's grants, visibility mode and reader listing.
type ResourceAccessSurface struct {
	Table                string   `json:"table"`
	ScopeCols            []string `json:"scopeCols"`
	ModeCol              string   `json:"modeCol"`
	PK                   string   `json:"pk"`
	ReadModes            []string `json:"readModes"`
	GrantKinds           []string `json:"grantKinds"`
	ACLTable             string   `json:"aclTable"`
	RecordCol            string   `json:"recordCol"`
	KindCol              string   `json:"kindCol"`
	PrincipalCol         string   `json:"principalCol"`
	AccessCol            string   `json:"accessCol"`
	DiscrimCol           string   `json:"discrimCol"`
	DiscrimVal           string   `json:"discrimVal"`
	AccessorFn           string   `json:"accessorFn"`
	AdmitsFn             string   `json:"admitsFn"`
	AccessorsConditional bool     `json:"accessorsConditional"`
}

// DelegationCap is whether a holder may grant what they ask to: permissions the vocabulary doesn't know, and ones
// beyond what they hold, are named.
type DelegationCap struct {
	Allowed bool     `json:"allowed"`
	Unknown []string `json:"unknown"`
	Excess  []string `json:"excess"`
}

// Statement is SQL with its arguments, ready for a driver. An argument a caller supplied, such as a time for an
// expiry, comes back as the same value.
type Statement struct {
	SQL  string
	Args []any
}

// EffectivePerms is the set of permissions a subject holds at a scope.
type EffectivePerms struct {
	perms []string
	held  map[string]bool
}

// Holds reports whether perm is held.
func (e EffectivePerms) Holds(perm string) bool {
	return e.held[perm]
}

// Permissions returns every permission held, in the runtime's order.
func (e EffectivePerms) Permissions() []string {
	return append(make([]string, 0, len(e.perms)), e.perms...)
}

// EffectiveRoles is the set of roles a subject holds at a scope.
type EffectiveRoles struct {
	roles []string
	held  map[string]bool
}

// Holds reports whether the role keyed roleKey is held.
func (e EffectiveRoles) Holds(roleKey string) bool {
	return e.held[roleKey]
}

// Roles returns every role held, in the runtime's order.
func (e EffectiveRoles) Roles() []string {
	return append(make([]string, 0, len(e.roles)), e.roles...)
}

func setOf(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
