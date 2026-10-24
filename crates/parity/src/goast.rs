use demesne_gocompat::json::Value;
use demesne_syntax::*;

fn s(v: &str) -> Value {
    Value::str(v)
}

fn o(v: &Option<String>) -> Value {
    Value::str(v.as_deref().unwrap_or(""))
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
    Value::Struct(vec![("Line".into(), Value::Int(p.line as i64))])
}

fn obj(fields: Vec<(&str, Value)>) -> Value {
    Value::Struct(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

pub fn spec(sp: &Spec) -> Value {
    obj(vec![
        ("Topology", sp.topology.as_ref().map(topology).unwrap_or(Value::Null)),
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
        ("Claims", sp.claims.as_ref().map(claims).unwrap_or(Value::Null)),
        ("DefinerSchema", o(&sp.definer_schema)),
        ("TableSchema", o(&sp.table_schema)),
        ("Identifiers", o(&sp.identifiers)),
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
        ("ScopeCol", o(&l.scope_col)),
        ("ClaimKey", o(&l.claim_key)),
        ("Pos", pos(l.pos)),
    ])
}

fn vocab(v: &Vocabulary) -> Value {
    obj(vec![
        ("Name", s(&v.name)),
        ("Permissions", strs(&v.permissions)),
        (
            "Implications",
            list(&v.implications, |im| {
                obj(vec![("Perm", s(&im.perm)), ("Set", strs(&im.set)), ("Star", b(im.star)), ("Pos", pos(im.pos))])
            }),
        ),
        (
            "Presets",
            list(&v.presets, |pr| {
                obj(vec![
                    ("Name", s(&pr.name)),
                    ("Level", o(&pr.level)),
                    ("Set", strs(&pr.set)),
                    ("Star", b(pr.star)),
                    ("Pos", pos(pr.pos)),
                ])
            }),
        ),
        ("Rank", strs(&v.rank)),
        ("Pos", pos(v.pos)),
    ])
}

fn subject(sub: &Subject) -> Value {
    obj(vec![
        ("Name", s(&sub.name)),
        ("Anchor", o(&sub.anchor)),
        ("Reach", o(&sub.reach)),
        ("Identifies", o(&sub.identifies)),
        (
            "Membership",
            sub.membership
                .as_ref()
                .map(|m| {
                    obj(vec![
                        ("Table", s(&m.table)),
                        ("IDCol", s(&m.id_col)),
                        ("FlagCol", s(&m.flag_col)),
                        ("ActiveCol", o(&m.active_col)),
                        ("ActiveVal", o(&m.active_val)),
                    ])
                })
                .unwrap_or(Value::Null),
        ),
        ("Roles", o(&sub.roles)),
        ("RolesNone", b(sub.roles_none)),
        ("ReachGrant", o(&sub.reach_grant)),
        ("Binds", o(&sub.binds)),
        ("Transient", b(sub.transient)),
        ("TransientSet", b(sub.transient_set)),
        ("Pos", pos(sub.pos)),
    ])
}

fn object(ob: &Object) -> Value {
    let verbs = if ob.scope_wildcard_verbs.is_empty() {
        Value::Null
    } else {
        Value::Map(ob.scope_wildcard_verbs.iter().map(|(k, v)| (k.clone(), strs(v))).collect())
    };
    obj(vec![
        ("Name", s(&ob.name)),
        ("Table", s(&ob.table)),
        ("PK", o(&ob.pk)),
        ("PKCols", strs(&ob.pk_cols)),
        ("Level", o(&ob.level)),
        ("Scoped", strs(&ob.scoped)),
        ("ScopeWildcards", strs(&ob.scope_wildcards)),
        ("ScopeWildcardVerbs", verbs),
        (
            "ReachUses",
            list(&ob.reach_uses, |u| {
                obj(vec![
                    ("Grant", s(&u.grant)),
                    ("Via", o(&u.via)),
                    ("Bound", o(&u.bound)),
                    ("Unscoped", b(u.unscoped)),
                    ("Ops", strs(&u.ops)),
                    ("Pos", pos(u.pos)),
                ])
            }),
        ),
        (
            "Admits",
            list(&ob.admits, |a| {
                obj(vec![
                    ("Ops", strs(&a.ops)),
                    ("Expr", refs(&a.tree.leaves())),
                    ("Tree", perm_node(&a.tree)),
                    ("Pos", pos(a.pos)),
                ])
            }),
        ),
        (
            "Exports",
            list(&ob.exports, |e| {
                obj(vec![
                    ("Verb", s(&e.verb)),
                    ("Name", s(&e.name)),
                    (
                        "Params",
                        list(&e.params, |p| obj(vec![("Column", s(&p.column)), ("Type", s(&p.ty)), ("Name", o(&p.name))])),
                    ),
                    ("Pos", pos(e.pos)),
                ])
            }),
        ),
        ("Relations", list(&ob.relations, relation)),
        ("Perms", list(&ob.perms, perm)),
        (
            "Requires",
            list(&ob.requires, |r| {
                obj(vec![
                    ("Verb", s(&r.verb)),
                    ("Expr", refs(&r.tree.leaves())),
                    ("Tree", perm_node(&r.tree)),
                    ("Pos", pos(r.pos)),
                ])
            }),
        ),
        (
            "Gates",
            list(&ob.gates, |g| {
                obj(vec![("Verb", s(&g.verb)), ("Relation", s(&g.relation)), ("Perm", s(&g.perm)), ("Pos", pos(g.pos))])
            }),
        ),
        ("FieldPrincipals", strs(&ob.field_principals)),
        (
            "Fields",
            list(&ob.fields, |f| {
                obj(vec![
                    ("Name", s(&f.name)),
                    ("Read", strs(&f.read)),
                    ("Write", strs(&f.write)),
                    ("Column", o(&f.column)),
                    ("Pos", pos(f.pos)),
                ])
            }),
        ),
        ("Use", o(&ob.use_template)),
        ("Omit", strs(&ob.omit)),
        ("TrackOwner", b(ob.track_owner)),
        ("TrackVisibility", b(ob.track_visibility)),
        ("Pos", pos(ob.pos)),
    ])
}

fn arg_src(a: &ArgSrc) -> Value {
    obj(vec![("Claim", s(a.claim())), ("Col", s(a.col()))])
}

fn repr(r: &Repr) -> Value {
    match r {
        Repr::Column(v) => obj(vec![("Column", s(&v.column)), ("DiscrimCol", o(&v.discrim_col)), ("DiscrimVal", o(&v.discrim_val))]),
        Repr::Edge(v) => obj(vec![("Table", s(&v.table)), ("Cols", strs(&v.cols))]),
        Repr::Role => obj(vec![]),
        Repr::Composition(v) => obj(vec![
            ("Table", s(&v.table)),
            ("ChildCol", s(&v.child_col)),
            ("ParentCol", s(&v.parent_col)),
            ("KindCol", o(&v.kind_col)),
            ("KindVal", o(&v.kind_val)),
        ]),
        Repr::Closure(v) => obj(vec![
            ("Closure", s(&v.closure)),
            ("AncestorCol", s(&v.ancestor_col)),
            ("DescendantCol", s(&v.descendant_col)),
            ("Base", o(&v.base)),
            ("BaseID", o(&v.base_id)),
            ("BaseParent", o(&v.base_parent)),
            ("Col", s(&v.col)),
            ("Claim", o(&v.claim)),
            ("Missing", o(&v.missing)),
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
        Repr::Object(v) => obj(vec![("Object", s(&v.object)), ("Verb", s(&v.verb)), ("Col", s(&v.col)), ("Op", o(&v.op))]),
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
            ("DiscrimCol", o(&v.discrim_col)),
            ("DiscrimVal", o(&v.discrim_val)),
            ("GroupKindVal", o(&v.group_kind_val)),
            ("GroupClosure", o(&v.group_closure)),
            ("GroupGroupCol", o(&v.group_group_col)),
            ("GroupMemberCol", o(&v.group_member_col)),
            ("GroupEdge", o(&v.group_edge)),
            ("GroupEdgeMember", o(&v.group_edge_member)),
            ("GroupEdgeGroup", o(&v.group_edge_group)),
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
        ("Kind", s(r.kind.map(RelationKind::as_str).unwrap_or(""))),
        ("Pos", pos(r.pos)),
    ])
}

fn perm(p: &Perm) -> Value {
    obj(vec![
        ("Verb", s(&p.verb)),
        ("Expr", refs(&p.tree.leaves())),
        ("Tree", perm_node(&p.tree)),
        ("Layers", strs(&p.layers)),
        ("Maps", o(&p.maps)),
        (
            "Guard",
            p.guard
                .as_ref()
                .map(|g| obj(vec![("Col", s(&g.col)), ("Op", s(g.op.as_str())), ("Val", s(&g.val)), ("Pos", pos(g.pos))]))
                .unwrap_or(Value::Null),
        ),
        ("SelfCheck", o(&p.self_check)),
        ("PredicateOnly", b(p.predicate_only)),
        ("Pos", pos(p.pos)),
    ])
}

fn perm_node(n: &PermNode) -> Value {
    let kids = n.kids();
    obj(vec![
        ("Op", s(n.op())),
        ("Term", n.term().map(term).unwrap_or(Value::Null)),
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
        (
            "ExternalArgs",
            list(t.external_args(), |a| obj(vec![("Col", s(a.col())), ("Claim", s(a.claim())), ("Lit", s(a.lit()))])),
        ),
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
        ("Assignments", o(&r.assignments)),
        ("KindCol", o(&r.kind_col)),
        ("KindVal", o(&r.kind_val)),
        ("SubjectCol", o(&r.subject_col)),
        ("ScopeCols", strs(&r.scope_cols)),
        ("Plane", o(&r.plane)),
        ("RoleCol", o(&r.role_col)),
        ("RolesTable", o(&r.roles_table)),
        ("RolesID", o(&r.roles_id)),
        ("KeyCol", o(&r.key_col)),
        ("RevokedCol", o(&r.revoked_col)),
        ("PermsCol", o(&r.perms_col)),
        ("IDCol", o(&r.id_col)),
        ("GrantedAtCol", o(&r.granted_at_col)),
        ("GrantedByCol", o(&r.granted_by_col)),
        ("RevokedByCol", o(&r.revoked_by_col)),
        ("ExtraCols", strs(&r.extra_cols)),
        ("Pos", pos(r.pos)),
    ])
}

fn grant(g: &Grant) -> Value {
    obj(vec![
        ("Name", s(&g.name)),
        ("Level", s(&g.level)),
        ("Table", o(&g.table)),
        ("GranteeCol", o(&g.grantee_col)),
        ("LevelCol", o(&g.level_col)),
        ("ActiveCol", o(&g.active_col)),
        ("ExpiresCol", o(&g.expires_col)),
        ("IDCol", o(&g.id_col)),
        ("GrantedByCol", o(&g.granted_by_col)),
        ("RevokedByCol", o(&g.revoked_by_col)),
        ("CreatedAtCol", o(&g.created_at_col)),
        ("Verbs", strs(&g.verbs)),
        ("ExtraCols", strs(&g.extra_cols)),
        ("Named", o(&g.named)),
        (
            "Scopes",
            list(&g.scopes, |sc| obj(vec![("Level", s(&sc.level)), ("Column", s(&sc.column)), ("Missing", s(&sc.missing))])),
        ),
        ("ClaimKey", o(&g.claim_key)),
        ("ClaimValue", o(&g.claim_value)),
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
    obj(vec![("Setting", s(&c.setting)), ("Cast", s(&c.cast)), ("Role", o(&c.role)), ("Pos", pos(c.pos))])
}
