use demesne_runtime as rt;
use std::collections::BTreeMap;
use std::fmt::Write as _;

fn s(v: &str) -> String {
    format!("::std::borrow::Cow::Borrowed({v:?})")
}

fn strs(v: &[rt::Str]) -> String {
    if v.is_empty() {
        return "::std::borrow::Cow::Borrowed(&[])".into();
    }
    format!("::std::borrow::Cow::Borrowed(&[{}])", v.iter().map(|x| s(x)).collect::<Vec<_>>().join(", "))
}

pub(crate) fn str_slice<S: AsRef<str>>(v: &[S]) -> String {
    format!("&[{}]", v.iter().map(|x| format!("{:?}", x.as_ref())).collect::<Vec<_>>().join(", "))
}

struct Fields {
    ty: &'static str,
    fields: Vec<(&'static str, String)>,
}

impl Fields {
    fn new(ty: &'static str) -> Self {
        Fields { ty, fields: Vec::new() }
    }

    fn f(mut self, name: &'static str, value: String) -> Self {
        self.fields.push((name, value));
        self
    }

    fn render(self) -> String {
        let mut out = format!("{} {{\n", self.ty);
        for (name, value) in self.fields {
            let value = value.replace('\n', "\n    ");
            writeln!(out, "    {name}: {value},").expect("fmt::Write for String never fails");
        }
        out.push('}');
        out
    }
}

fn list(items: Vec<String>) -> String {
    if items.is_empty() {
        return "::std::borrow::Cow::Borrowed(&[])".into();
    }
    let mut out = String::from("::std::borrow::Cow::Borrowed(&[\n");
    for i in items {
        writeln!(out, "    {},", i.replace('\n', "\n    ")).expect("fmt::Write for String never fails");
    }
    out.push_str("])");
    out
}

pub(crate) fn vocabulary(v: &rt::Vocabulary) -> String {
    Fields::new("::demesne_runtime::Vocabulary")
        .f("name", s(&v.name))
        .f("permissions", strs(&v.permissions))
        .f(
            "implications",
            list(
                v.implications
                    .iter()
                    .map(|i| Fields::new("::demesne_runtime::Implication").f("perm", s(&i.perm)).f("set", strs(&i.set)).f("star", i.star.to_string()).render())
                    .collect(),
            ),
        )
        .f(
            "presets",
            list(
                v.presets
                    .iter()
                    .map(|p| {
                        Fields::new("::demesne_runtime::Preset")
                            .f("name", s(&p.name))
                            .f("level", s(&p.level))
                            .f("set", strs(&p.set))
                            .f("star", p.star.to_string())
                            .render()
                    })
                    .collect(),
            ),
        )
        .f("rank", strs(&v.rank))
        .render()
}

pub(crate) fn holds_resolver(h: &rt::HoldsResolver) -> String {
    Fields::new("::demesne_runtime::HoldsResolver")
        .f("assignments", s(&h.assignments))
        .f("kind_col", s(&h.kind_col))
        .f("kind_val", s(&h.kind_val))
        .f("subject_col", s(&h.subject_col))
        .f("scope_cols", strs(&h.scope_cols))
        .f("revoked_col", s(&h.revoked_col))
        .f("plane", s(&h.plane))
        .f("plane_depth", h.plane_depth.to_string())
        .f("role_col", s(&h.role_col))
        .f("roles_table", s(&h.roles_table))
        .f("roles_id", s(&h.roles_id))
        .f("key_col", s(&h.key_col))
        .f("perms_col", s(&h.perms_col))
        .f("vocab", vocabulary(&h.vocab))
        .render()
}

pub(crate) fn role_assignment(r: &rt::RoleAssignmentSurface) -> String {
    Fields::new("::demesne_runtime::RoleAssignmentSurface")
        .f("assignments", s(&r.assignments))
        .f("pk", s(&r.pk))
        .f("kind_col", s(&r.kind_col))
        .f("kind_val", s(&r.kind_val))
        .f("subject_col", s(&r.subject_col))
        .f("role_col", s(&r.role_col))
        .f("scope_cols", strs(&r.scope_cols))
        .f("revoked_col", s(&r.revoked_col))
        .f("granted_at_col", s(&r.granted_at_col))
        .f("granted_by_col", s(&r.granted_by_col))
        .f("revoked_by_col", s(&r.revoked_by_col))
        .f("extra_cols", strs(&r.extra_cols))
        .f("roles_table", s(&r.roles_table))
        .f("roles_id", s(&r.roles_id))
        .f("key_col", s(&r.key_col))
        .f("perms_col", s(&r.perms_col))
        .render()
}

pub(crate) fn grant(g: &rt::GrantSurface) -> String {
    Fields::new("::demesne_runtime::GrantSurface")
        .f("name", s(&g.name))
        .f("level", s(&g.level))
        .f("table", s(&g.table))
        .f("grantee_col", s(&g.grantee_col))
        .f("level_col", s(&g.level_col))
        .f("active_col", s(&g.active_col))
        .f("expires_col", s(&g.expires_col))
        .f("pk", s(&g.pk))
        .f("granted_by_col", s(&g.granted_by_col))
        .f("revoked_by_col", s(&g.revoked_by_col))
        .f("created_at_col", s(&g.created_at_col))
        .f("extra_cols", strs(&g.extra_cols))
        .render()
}

pub(crate) fn resource_access(r: &rt::ResourceAccessSurface) -> String {
    let nullable = if r.scope_nullable.is_empty() {
        "::std::borrow::Cow::Borrowed(&[])".to_string()
    } else {
        format!("::std::borrow::Cow::Borrowed(&[{}])", r.scope_nullable.iter().map(bool::to_string).collect::<Vec<_>>().join(", "))
    };
    Fields::new("::demesne_runtime::ResourceAccessSurface")
        .f("table", s(&r.table))
        .f("scope_cols", strs(&r.scope_cols))
        .f("scope_nullable", nullable)
        .f("mode_col", s(&r.mode_col))
        .f("pk", s(&r.pk))
        .f("read_modes", strs(&r.read_modes))
        .f("grant_kinds", strs(&r.grant_kinds))
        .f("acl_table", s(&r.acl_table))
        .f("record_col", s(&r.record_col))
        .f("kind_col", s(&r.kind_col))
        .f("principal_col", s(&r.principal_col))
        .f("access_col", s(&r.access_col))
        .f("discrim_col", s(&r.discrim_col))
        .f("discrim_val", s(&r.discrim_val))
        .f("accessor_fn", s(&r.accessor_fn))
        .f("admits_fn", s(&r.admits_fn))
        .f("conditional", r.conditional.to_string())
        .f("conditional_by", s(&r.conditional_by))
        .render()
}

pub(crate) fn app_object(a: &rt::AppObjectSurface) -> String {
    Fields::new("::demesne_runtime::AppObjectSurface")
        .f("object", s(&a.object))
        .f("table", s(&a.table))
        .f("pk", s(&a.pk))
        .f("flat_list_fn", s(&a.flat_list_fn))
        .f("async_check_sql", s(&a.async_check_sql))
        .f("edit_check_sql", s(&a.edit_check_sql))
        .f(
            "checks",
            list(a.checks.iter().map(|c| Fields::new("::demesne_runtime::AppCheck").f("verb", s(&c.verb)).f("check_sql", s(&c.check_sql)).render()).collect()),
        )
        .render()
}

fn pairs(p: &[(rt::Str, rt::Str)]) -> String {
    list(p.iter().map(|(k, v)| format!("({}, {})", s(k), s(v))).collect())
}

pub(crate) fn pdp(p: &rt::Pdp) -> String {
    Fields::new("::demesne_runtime::Pdp").f("emit_site", s(&p.emit_site)).f("policy", pairs(&p.policy)).f("ungoverned", pairs(&p.ungoverned)).render()
}

pub(crate) fn session(x: &rt::Session) -> String {
    Fields::new("::demesne_runtime::Session").f("setting", s(&x.setting)).f("cast", s(&x.cast)).f("role", s(&x.role)).render()
}

pub(crate) fn claim_entries(entries: &[rt::ClaimEntry]) -> String {
    let items: Vec<String> = entries
        .iter()
        .map(|e| Fields::new("::demesne_runtime::ClaimEntry").f("key", s(&e.key)).f("level", s(&e.level)).f("subjects", strs(&e.subjects)).render())
        .collect();
    if items.is_empty() {
        return "&[]".into();
    }
    let mut out = String::from("&[\n");
    for i in items {
        writeln!(out, "    {},", i.replace('\n', "\n    ")).expect("fmt::Write for String never fails");
    }
    out.push(']');
    out
}

pub(crate) fn presets(p: &BTreeMap<String, Vec<String>>) -> String {
    if p.is_empty() {
        return "&[]".into();
    }
    let mut out = String::from("&[\n");
    for (name, set) in p {
        writeln!(out, "    ({name:?}, {}),", str_slice(set)).expect("fmt::Write for String never fails");
    }
    out.push(']');
    out
}
