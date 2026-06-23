package demesne

type Pos struct{ Line int }

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

	DefinerSchema string

	TableSchema string
}

func (s *Spec) definerSchema() string {
	if s.DefinerSchema != "" {
		return s.DefinerSchema
	}
	return "auth"
}

func (s *Spec) tableSchema() string {
	if s.TableSchema != "" {
		return s.TableSchema
	}
	return "public"
}

type ClaimsAccessor struct {
	Setting string
	Cast    string

	Role string
	Pos  Pos
}

type Grant struct {
	Name       string
	Level      string
	Table      string
	GranteeCol string
	LevelCol   string
	ActiveCol  string
	ExpiresCol string

	IDCol        string
	GrantedByCol string
	RevokedByCol string
	CreatedAtCol string

	ExtraCols []string
	Pos       Pos
}

func (g *Grant) grantPK() string {
	if g.IDCol != "" {
		return g.IDCol
	}
	return "id"
}

type RoleStore struct {
	Name        string
	Assignments string
	KindCol     string
	KindVal     string
	SubjectCol  string
	ScopeCols   []string
	RoleCol     string
	RolesTable  string
	RolesID     string
	KeyCol      string
	RevokedCol  string

	PermsCol string

	IDCol        string
	GrantedAtCol string
	GrantedByCol string
	RevokedByCol string

	ExtraCols []string
	Pos       Pos
}

func (rs *RoleStore) assignmentPK() string {
	if rs.IDCol != "" {
		return rs.IDCol
	}
	return "id"
}

type Topology struct {
	Levels []*Level
	Pos    Pos
}

type Level struct {
	Name    string
	Parents []string
	Virtual bool

	ScopeCol string

	ClaimKey string
	Pos      Pos
}

func (l *Level) isRoot() bool { return len(l.Parents) == 0 }

func (l *Level) scopeColumn() string {
	if l.ScopeCol != "" {
		return l.ScopeCol
	}
	return l.Name + "_id"
}

func (l *Level) claimKey() string {
	if l.ClaimKey != "" {
		return l.ClaimKey
	}
	return l.Name + "_id"
}

type Vocabulary struct {
	Name        string
	Permissions []string
	Presets     []*Preset
	Rank        []string
	Pos         Pos
}

type Preset struct {
	Name  string
	Level string
	Set   []string
	Star  bool
	Pos   Pos
}

type Subject struct {
	Name       string
	Anchor     string
	Reach      string
	Identifies string
	Membership *Membership
	Roles      string
	RolesNone  bool
	ReachGrant string

	Binds string
	Pos   Pos
}

type Membership struct {
	Table     string
	IDCol     string
	FlagCol   string
	ActiveCol string
	ActiveVal string
}

type Template struct {
	Name  string
	Perms []*Perm
	Pos   Pos
}

type Gate struct {
	Verb     string
	Relation string
	Perm     string
	Pos      Pos
}

type Object struct {
	Name  string
	Table string

	PK string

	PKCols []string
	Level  string

	Scoped    []string
	Relations []*Relation
	Perms     []*Perm
	Gates     []*Gate

	Use  string
	Omit []string

	TrackOwner      bool
	TrackVisibility bool
	Pos             Pos
}

func (o *Object) ownerChangelogCols() (idCol, kindCol string, ok bool) {
	for _, r := range o.Relations {
		if vc, isVC := r.Repr.(ViaColumn); isVC && vc.DiscrimCol != "" {
			return vc.Column, vc.DiscrimCol, true
		}
	}
	return "", "", false
}

func (o *Object) modeChangelogCol() (col string, ok bool) {
	for _, pm := range o.Perms {
		for _, t := range pm.Expr {
			if t.ModeCol != "" {
				return t.ModeCol, true
			}
		}
	}
	return "", false
}

func (o *Object) IsLevelEntity() bool { return o.Level != "" }

func (o *Object) pk() string {
	if o.PK != "" {
		return o.PK
	}
	return "id"
}

func (o *Object) pointCheckable() bool { return len(o.PKCols) == 0 }

func (o *Object) HasGrantStore() bool { return objectGrantEdge(o) != nil }

type Relation struct {
	Name  string
	Types []string
	Repr  Repr
	Kind  string
	Pos   Pos
}

type Repr interface{ isRepr() }

type ViaColumn struct {
	Column     string
	DiscrimCol string
	DiscrimVal string
}

type ViaEdge struct {
	Table string
	Cols  []string
}

type ViaRole struct {
	HasRank bool
	RankMin string
}

type ViaComposition struct {
	Table     string
	ChildCol  string
	ParentCol string
	KindCol   string
	KindVal   string
}

type ViaClosure struct {
	Closure       string
	AncestorCol   string
	DescendantCol string
	Base          string
	BaseID        string
	BaseParent    string
	Col           string
}

type ViaGroup struct {
	Closure    string
	GroupCol   string
	MemberCol  string
	Edge       string
	EdgeMember string
	EdgeGroup  string
	Col        string

	Materialized bool
}

type ViaObject struct {
	Object string
	Verb   string
	Col    string
}

type ViaGrant struct {
	Table        string
	RecordCol    string
	KindCol      string
	PrincipalCol string
	AccessCol    string
	DiscrimCol   string
	DiscrimVal   string

	Tracked bool

	Async bool
}

type ArgSrc struct {
	Claim string
	Col   string
}

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

type Perm struct {
	Verb   string
	Expr   []*Term
	Tree   *PermNode
	Layers []string
	Maps   string
	Guard  *Guard
	Pos    Pos
}

type PermNode struct {
	Op   string
	Term *Term
	Kids []*PermNode
}

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

type Guard struct {
	Col string
	Op  string
	Val string
	Pos Pos
}

type Term struct {
	Ident      string
	WalkVerb   string
	Builtin    string
	SessionRel string

	ExcludeRel string

	ModeCol   string
	ModeVal   string
	ModeScope string

	GrantRef string

	KindVal string
	Pos     Pos
}

type Procedures struct {
	EmitSite string
	Entries  []ProcEntry
	Pos      Pos
}

type ProcEntry struct {
	Proc string
	Perm string
	Pos  Pos
}

type Ungoverned struct {
	EmitSite string
	Entries  []UngovEntry
	Pos      Pos
}

type UngovEntry struct {
	Proc   string
	Reason string
	Pos    Pos
}

type FieldScopes struct {
	Site    string
	Entries []FieldScopeEntry
	Pos     Pos
}

type FieldScopeEntry struct {
	Field string
	Scope string
	Pos   Pos
}
