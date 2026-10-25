use demesne_gocompat::json::Value;
use demesne_syntax::{
    Admit, ArgSrc, ClaimsAccessor, External, FieldRule, FieldScopes, Gate, Grant, GrantUse, Level, Object, Perm, PermNode, PermissionExport, Pos, Procedures,
    Relation, RelationKind, Repr, Require, RoleStore, Spec, Subject, Template, Term, Topology, Ungoverned, Vocabulary,
};

fn s(v: &str) -> Value {
    Value::str(v)
}

fn o(v: Option<&str>) -> Value {
    Value::str(v.unwrap_or(""))
}

fn b(v: bool) -> Value {
    Value::Bool(v)
}

fn strs(v: &[String]) -> Value {
    if v.is_empty() { Value::Null } else { Value::strings(v) }
}

fn list<T>(v: &[T], f: impl Fn(&T) -> Value) -> Value {
    if v.is_empty() { Value::Null } else { Value::Array(v.iter().map(f).collect()) }
}

fn refs(v: &[&Term]) -> Value {
    if v.is_empty() { Value::Null } else { Value::Array(v.iter().map(|t| term(t)).collect()) }
}

fn pos(p: Pos) -> Value {
    Value::Struct(vec![("Line".into(), Value::Int(i64::try_from(p.line).expect("a line number fits in i64")))])
}

fn obj(fields: Vec<(&str, Value)>) -> Value {
    Value::Struct(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

pub fn spec(sp: &Spec) -> Value {
    obj(vec![
        ("Topology", sp.topology.as_ref().map_or(Value::Null, topology)),
        ("Vocabs", list(&sp.vocabs, vocab)),
        ("Subjects", list(&sp.subjects, subject)),
        ("Objects", list(&sp.objects, object)),
        ("Procedures", list(&sp.procedures, procedures)),
        ("Ungoverned", list(&sp.ungoverned, ungoverned)),
        ("FieldScopes", list(&sp.field_scopes, field_scopes)),
        ("RoleStores", list(&sp.role_stores, role_store)),
        ("Grants", list(&sp.grants, grant)),
        ("Templates", list(&sp.templates, template)),
        ("Externals", list(&sp.externals, external)),
        ("Claims", sp.claims.as_ref().map_or(Value::Null, claims)),
        ("DefinerSchema", o(sp.definer_schema.as_deref())),
        ("TableSchema", o(sp.table_schema.as_deref())),
        ("Identifiers", o(sp.identifiers.as_deref())),
    ])
}

fn topology(t: &Topology) -> Value {
    obj(vec![("Levels", list(&t.levels, level)), ("Pos", pos(t.pos))])
}

fn level(l: &Level) -> Value {
    obj(vec![
        ("Name", s(&l.name)),
        ("Parents", strs(&l.parents)),
        ("Virtual", b(l.is_virtual)),
        ("ScopeCol", o(l.scope_col.as_deref())),
        ("ClaimKey", o(l.claim_key.as_deref())),
        ("Pos", pos(l.pos)),
    ])
}

fn vocab(v: &Vocabulary) -> Value {
    obj(vec![
        ("Name", s(&v.name)),
        ("Permissions", strs(&v.permissions)),
        ("Implications", list(&v.implications, |im| obj(vec![("Perm", s(&im.perm)), ("Set", strs(&im.set)), ("Star", b(im.star)), ("Pos", pos(im.pos))]))),
        (
            "Presets",
            list(&v.presets, |pr| {
                obj(vec![("Name", s(&pr.name)), ("Level", o(pr.level.as_deref())), ("Set", strs(&pr.set)), ("Star", b(pr.star)), ("Pos", pos(pr.pos))])
            }),
        ),
        ("Rank", strs(&v.rank)),
        ("Pos", pos(v.pos)),
    ])
}

fn subject(sub: &Subject) -> Value {
    obj(vec![
        ("Name", s(&sub.name)),
        ("Anchor", o(sub.anchor.as_deref())),
        ("Reach", o(sub.reach.as_deref())),
        ("Identifies", o(sub.identifies.as_deref())),
        (
            "Membership",
            sub.membership.as_ref().map_or(Value::Null, |m| {
                obj(vec![
                    ("Table", s(&m.table)),
                    ("IDCol", s(&m.id_col)),
                    ("FlagCol", s(&m.flag_col)),
                    ("ActiveCol", o(m.active_col.as_deref())),
                    ("ActiveVal", o(m.active_val.as_deref())),
                ])
            }),
        ),
        ("Roles", o(sub.roles.as_deref())),
        ("RolesNone", b(sub.roles_none)),
        ("ReachGrant", o(sub.reach_grant.as_deref())),
        ("Binds", o(sub.binds.as_deref())),
        ("Transient", b(sub.transient)),
        ("TransientSet", b(sub.transient_set)),
        ("Pos", pos(sub.pos)),
    ])
}

fn object(ob: &Object) -> Value {
    let verbs =
        if ob.scope_wildcard_verbs.is_empty() { Value::Null } else { Value::Map(ob.scope_wildcard_verbs.iter().map(|(k, v)| (k.clone(), strs(v))).collect()) };
    obj(vec![
        ("Name", s(&ob.name)),
        ("Table", s(&ob.table)),
        ("PK", o(ob.pk.as_deref())),
        ("PKCols", strs(&ob.pk_cols)),
        ("Level", o(ob.level.as_deref())),
        ("Scoped", strs(&ob.scoped)),
        ("ScopeWildcards", strs(&ob.scope_wildcards)),
        ("ScopeWildcardVerbs", verbs),
        ("ReachUses", list(&ob.reach_uses, grant_use)),
        ("Admits", list(&ob.admits, admit)),
        ("Exports", list(&ob.exports, export)),
        ("Relations", list(&ob.relations, relation)),
        ("Perms", list(&ob.perms, perm)),
        ("Requires", list(&ob.requires, require)),
        ("Gates", list(&ob.gates, gate)),
        ("FieldPrincipals", strs(&ob.field_principals)),
        ("Fields", list(&ob.fields, field_rule)),
        ("Use", o(ob.use_template.as_deref())),
        ("Omit", strs(&ob.omit)),
        ("TrackOwner", b(ob.track_owner)),
        ("TrackVisibility", b(ob.track_visibility)),
        ("Pos", pos(ob.pos)),
    ])
}

fn grant_use(u: &GrantUse) -> Value {
    obj(vec![
        ("Grant", s(&u.grant)),
        ("Via", o(u.via.as_deref())),
        ("Bound", o(u.bound.as_deref())),
        ("Unscoped", b(u.unscoped)),
        ("Ops", strs(&u.ops)),
        ("Pos", pos(u.pos)),
    ])
}

fn admit(a: &Admit) -> Value {
    obj(vec![("Ops", strs(&a.ops)), ("Expr", refs(&a.tree.leaves())), ("Tree", perm_node(&a.tree)), ("Pos", pos(a.pos))])
}

fn export(e: &PermissionExport) -> Value {
    obj(vec![
        ("Verb", s(&e.verb)),
        ("Name", s(&e.name)),
        ("Params", list(&e.params, |p| obj(vec![("Column", s(&p.column)), ("Type", s(&p.ty)), ("Name", o(p.name.as_deref()))]))),
        ("Pos", pos(e.pos)),
    ])
}

fn require(r: &Require) -> Value {
    obj(vec![("Verb", s(&r.verb)), ("Expr", refs(&r.tree.leaves())), ("Tree", perm_node(&r.tree)), ("Pos", pos(r.pos))])
}

fn gate(g: &Gate) -> Value {
    obj(vec![("Verb", s(&g.verb)), ("Relation", s(&g.relation)), ("Perm", s(&g.perm)), ("Pos", pos(g.pos))])
}

fn field_rule(f: &FieldRule) -> Value {
    obj(vec![("Name", s(&f.name)), ("Read", strs(&f.read)), ("Write", strs(&f.write)), ("Column", o(f.column.as_deref())), ("Pos", pos(f.pos))])
}

fn arg_src(a: &ArgSrc) -> Value {
    obj(vec![("Claim", s(a.claim())), ("Col", s(a.col()))])
}

fn repr(r: &Repr) -> Value {
    match r {
        Repr::Column(v) => obj(vec![("Column", s(&v.column)), ("DiscrimCol", o(v.discrim_col.as_deref())), ("DiscrimVal", o(v.discrim_val.as_deref()))]),
        Repr::Edge(v) => obj(vec![("Table", s(&v.table)), ("Cols", strs(&v.cols))]),
        Repr::Role => obj(vec![]),
        Repr::Composition(v) => obj(vec![
            ("Table", s(&v.table)),
            ("ChildCol", s(&v.child_col)),
            ("ParentCol", s(&v.parent_col)),
            ("KindCol", o(v.kind_col.as_deref())),
            ("KindVal", o(v.kind_val.as_deref())),
        ]),
        Repr::Closure(v) => obj(vec![
            ("Closure", s(&v.closure)),
            ("AncestorCol", s(&v.ancestor_col)),
            ("DescendantCol", s(&v.descendant_col)),
            ("Base", o(v.base.as_deref())),
            ("BaseID", o(v.base_id.as_deref())),
            ("BaseParent", o(v.base_parent.as_deref())),
            ("Col", s(&v.col)),
            ("Claim", o(v.claim.as_deref())),
            ("Missing", o(v.missing.as_deref())),
        ]),
        Repr::Group(v) => obj(vec![
            ("Closure", s(&v.closure)),
            ("GroupCol", s(&v.group_col)),
            ("MemberCol", s(&v.member_col)),
            ("Edge", s(&v.edge)),
            ("EdgeMember", s(&v.edge_member)),
            ("EdgeGroup", s(&v.edge_group)),
            ("Col", s(&v.col)),
            ("Materialized", b(v.materialized)),
        ]),
        Repr::Object(v) => obj(vec![("Object", s(&v.object)), ("Verb", s(&v.verb)), ("Col", s(&v.col)), ("Op", o(v.op.as_deref()))]),
        Repr::MemberIn(v) => obj(vec![
            ("Level", s(&v.level)),
            ("Principal", arg_src(&v.principal)),
            ("Scope", arg_src(&v.scope)),
            ("ReachedBy", b(v.reached_by)),
            ("ReachMember", b(v.reach_member)),
        ]),
        Repr::Grant(v) => obj(vec![
            ("Table", s(&v.table)),
            ("RecordCol", s(&v.record_col)),
            ("KindCol", s(&v.kind_col)),
            ("PrincipalCol", s(&v.principal_col)),
            ("AccessCol", s(&v.access_col)),
            ("DiscrimCol", o(v.discrim_col.as_deref())),
            ("DiscrimVal", o(v.discrim_val.as_deref())),
            ("GroupKindVal", o(v.group_kind_val.as_deref())),
            ("GroupClosure", o(v.group_closure.as_deref())),
            ("GroupGroupCol", o(v.group_group_col.as_deref())),
            ("GroupMemberCol", o(v.group_member_col.as_deref())),
            ("GroupEdge", o(v.group_edge.as_deref())),
            ("GroupEdgeMember", o(v.group_edge_member.as_deref())),
            ("GroupEdgeGroup", o(v.group_edge_group.as_deref())),
            ("Tracked", b(v.tracked)),
            ("Async", b(v.is_async)),
        ]),
    }
}

fn relation(r: &Relation) -> Value {
    obj(vec![
        ("Name", s(&r.name)),
        ("Types", strs(&r.types)),
        ("Repr", repr(&r.repr)),
        ("Kind", s(r.kind.map_or("", RelationKind::as_str))),
        ("Pos", pos(r.pos)),
    ])
}

fn perm(p: &Perm) -> Value {
    obj(vec![
        ("Verb", s(&p.verb)),
        ("Expr", refs(&p.tree.leaves())),
        ("Tree", perm_node(&p.tree)),
        ("Layers", strs(&p.layers)),
        ("Maps", o(p.maps.as_deref())),
        ("Guard", p.guard.as_ref().map_or(Value::Null, |g| obj(vec![("Col", s(&g.col)), ("Op", s(g.op.as_str())), ("Val", s(&g.val)), ("Pos", pos(g.pos))]))),
        ("SelfCheck", o(p.self_check.as_deref())),
        ("PredicateOnly", b(p.predicate_only)),
        ("Pos", pos(p.pos)),
    ])
}

fn perm_node(n: &PermNode) -> Value {
    let kids = n.kids();
    obj(vec![
        ("Op", s(n.op())),
        ("Term", n.term().map_or(Value::Null, term)),
        ("Kids", if kids.is_empty() { Value::Null } else { Value::Array(kids.into_iter().map(perm_node).collect()) }),
    ])
}

fn term(t: &Term) -> Value {
    obj(vec![
        ("Ident", s(t.ident())),
        ("WalkVerb", s(t.walk_verb())),
        ("Builtin", s(t.builtin())),
        ("SessionRel", s(t.session_rel())),
        ("ExcludeRels", strs(t.exclude_rels())),
        ("ModeCol", s(t.mode_col().unwrap_or(""))),
        ("ModeVal", s(t.mode_val())),
        ("ModeScope", s(t.mode_scope())),
        ("GrantRef", s(t.grant_ref())),
        ("KindVal", s(t.kind_val())),
        ("SelfCol", s(t.self_col())),
        ("ClaimKey", s(t.claim_key())),
        ("ClaimVal", s(t.claim_val())),
        ("RowCol", s(t.row_col())),
        ("RowVal", s(t.row_val())),
        ("WithinLevel", s(t.within_level())),
        ("WithinNullable", b(t.within_nullable())),
        ("HoldsPerm", s(t.holds_perm())),
        ("ExternalFn", s(t.external_fn())),
        ("ExternalArgs", list(t.external_args(), |a| obj(vec![("Col", s(a.col())), ("Claim", s(a.claim())), ("Lit", s(a.lit()))]))),
        ("Pos", pos(t.pos)),
    ])
}

fn procedures(p: &Procedures) -> Value {
    obj(vec![
        ("EmitSite", s(&p.emit_site)),
        ("Entries", list(&p.entries, |e| obj(vec![("Proc", s(&e.proc_)), ("Perm", s(&e.perm)), ("Pos", pos(e.pos))]))),
        ("Pos", pos(p.pos)),
    ])
}

fn ungoverned(u: &Ungoverned) -> Value {
    obj(vec![
        ("EmitSite", s(&u.emit_site)),
        ("Entries", list(&u.entries, |e| obj(vec![("Proc", s(&e.proc_)), ("Reason", s(&e.reason)), ("Pos", pos(e.pos))]))),
        ("Pos", pos(u.pos)),
    ])
}

fn field_scopes(f: &FieldScopes) -> Value {
    obj(vec![
        ("Site", s(&f.site)),
        ("Entries", list(&f.entries, |e| obj(vec![("Field", s(&e.field)), ("Scope", s(&e.scope)), ("Pos", pos(e.pos))]))),
        ("Pos", pos(f.pos)),
    ])
}

fn role_store(r: &RoleStore) -> Value {
    obj(vec![
        ("Name", s(&r.name)),
        ("Assignments", o(r.assignments.as_deref())),
        ("KindCol", o(r.kind_col.as_deref())),
        ("KindVal", o(r.kind_val.as_deref())),
        ("SubjectCol", o(r.subject_col.as_deref())),
        ("ScopeCols", strs(&r.scope_cols)),
        ("Plane", o(r.plane.as_deref())),
        ("RoleCol", o(r.role_col.as_deref())),
        ("RolesTable", o(r.roles_table.as_deref())),
        ("RolesID", o(r.roles_id.as_deref())),
        ("KeyCol", o(r.key_col.as_deref())),
        ("RevokedCol", o(r.revoked_col.as_deref())),
        ("PermsCol", o(r.perms_col.as_deref())),
        ("IDCol", o(r.id_col.as_deref())),
        ("GrantedAtCol", o(r.granted_at_col.as_deref())),
        ("GrantedByCol", o(r.granted_by_col.as_deref())),
        ("RevokedByCol", o(r.revoked_by_col.as_deref())),
        ("ExtraCols", strs(&r.extra_cols)),
        ("Pos", pos(r.pos)),
    ])
}

fn grant(g: &Grant) -> Value {
    obj(vec![
        ("Name", s(&g.name)),
        ("Level", s(&g.level)),
        ("Table", o(g.table.as_deref())),
        ("GranteeCol", o(g.grantee_col.as_deref())),
        ("LevelCol", o(g.level_col.as_deref())),
        ("ActiveCol", o(g.active_col.as_deref())),
        ("ExpiresCol", o(g.expires_col.as_deref())),
        ("IDCol", o(g.id_col.as_deref())),
        ("GrantedByCol", o(g.granted_by_col.as_deref())),
        ("RevokedByCol", o(g.revoked_by_col.as_deref())),
        ("CreatedAtCol", o(g.created_at_col.as_deref())),
        ("Verbs", strs(&g.verbs)),
        ("ExtraCols", strs(&g.extra_cols)),
        ("Named", o(g.named.as_deref())),
        ("Scopes", list(&g.scopes, |sc| obj(vec![("Level", s(&sc.level)), ("Column", s(&sc.column)), ("Missing", s(&sc.missing))]))),
        ("ClaimKey", o(g.claim_key.as_deref())),
        ("ClaimValue", o(g.claim_value.as_deref())),
        ("Pos", pos(g.pos)),
    ])
}

fn template(t: &Template) -> Value {
    obj(vec![("Name", s(&t.name)), ("Perms", list(&t.perms, perm)), ("Pos", pos(t.pos))])
}

fn external(e: &External) -> Value {
    obj(vec![("Name", s(&e.name)), ("ArgTypes", strs(&e.arg_types)), ("Pos", pos(e.pos))])
}

fn claims(c: &ClaimsAccessor) -> Value {
    obj(vec![("Setting", s(&c.setting)), ("Cast", s(&c.cast)), ("Role", o(c.role.as_deref())), ("Pos", pos(c.pos))])
}
