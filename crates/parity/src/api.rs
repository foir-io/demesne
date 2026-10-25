use demesne_emit_sql::Sql;
use demesne_model::pdp::{emit_field_access, emit_field_scopes, emit_pdp};
use demesne_model::{Principal, SpecExt, SurfaceExt};
use demesne_syntax::Spec;
use std::collections::BTreeMap;
use std::fmt::Write as _;

fn st<T, E: std::fmt::Display>(r: &Result<T, E>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => format!("error: {e}"),
    }
}

/// Dumps the result of every public compiler and surface call on `s`, for diffing against Go.
///
/// # Panics
///
/// If field access names an object the spec does not declare, which would be a compiler bug.
pub fn api_dump(s: &Spec) -> String {
    let mut b = String::new();
    let sql = Sql::new(s);
    let names = sql.definer_names();
    writeln!(b, "definer names: {} {}", st(&names), names.as_ref().map(|n| n.join(" ")).unwrap_or_default()).expect("fmt::Write for String never fails");
    for o in &s.objects {
        let pc = s.point_check_sql(&o.name);
        writeln!(b, "pointcheck {}: {} {}", o.name, st(&pc), pc.as_ref().map_or("", String::as_str)).expect("fmt::Write for String never fails");
        let ra = s.resource_access_surface(&o.name);
        writeln!(b, "resourceaccess {}: {}", o.name, st(&ra)).expect("fmt::Write for String never fails");
    }
    dump_vocabularies(s, &mut b);
    let ent = demesne_emit_go::render_claims_contract_entries_go(s, "ClaimsContractEntries");
    write!(b, "claims entries go: {}\n{}", st(&ent), ent.as_ref().map_or("", String::as_str)).expect("fmt::Write for String never fails");
    dump_fields(s, &mut b);
    for rg in s.reach_grants() {
        writeln!(b, "reach grant {} {} {}", rg.edge_table(), rg.grantee_column(), rg.granularity()).expect("fmt::Write for String never fails");
    }
    dump_checks(s, &sql, &mut b);
    dump_claims(s, &mut b);
    for rs in &s.role_stores {
        match s.holds_resolver(&rs.name) {
            Err(e) => writeln!(b, "holds {}: error: {e}", rs.name).expect("fmt::Write for String never fails"),
            Ok(hr) => writeln!(b, "holds {}: {} | {}", rs.name, hr.assignments_sql(), hr.global_assignments_sql()).expect("fmt::Write for String never fails"),
        }
    }
    b
}

fn dump_vocabularies(s: &Spec, b: &mut String) {
    let presets = s.expanded_presets("");
    writeln!(b, "expanded presets: {}", st(&presets)).expect("fmt::Write for String never fails");
    for (k, v) in presets.iter().flatten() {
        writeln!(b, "  {} = {}", k, v.join(" ")).expect("fmt::Write for String never fails");
    }
    for v in &s.vocabs {
        write!(b, "vocabulary {}:", v.name).expect("fmt::Write for String never fails");
        for p in &v.permissions {
            write!(b, " {}/{}", p, p.contains('*')).expect("fmt::Write for String never fails");
        }
        b.push('\n');
    }
}

fn dump_fields(s: &Spec, b: &mut String) {
    let fs = emit_field_scopes(s);
    writeln!(b, "field scopes: {}", st(&fs)).expect("fmt::Write for String never fails");
    for (site, m) in fs.iter().flatten() {
        for (f, scope) in m {
            writeln!(b, "  {site} {f} -> {scope}").expect("fmt::Write for String never fails");
        }
    }
    for (name, fa) in emit_field_access(s) {
        let table = &s.object_by_name(&name).expect("the name comes from the spec's own objects").table;
        write!(
            b,
            "field access {name} go:\n{}field access {name} ts:\n{}field access {name} grants:\n{}",
            demesne_emit_go::render_field_access_go(&fa),
            demesne_emit_ts::render_field_access_ts(&fa),
            demesne_emit_sql::render_field_grants(&fa, table)
        )
        .expect("fmt::Write for String never fails");
    }
}

fn dump_checks(s: &Spec, sql: &Sql, b: &mut String) {
    let surf = sql.emit_app_surface();
    writeln!(b, "app surface: {}", st(&surf)).expect("fmt::Write for String never fails");
    for o in surf.iter().flat_map(|surf| surf.objects.iter()) {
        for c in o.checks.iter() {
            writeln!(b, "  check {}.{}: {}", o.object, c.verb, c.check_sql).expect("fmt::Write for String never fails");
        }
    }
    let pdps = emit_pdp(s);
    writeln!(b, "pdp: {}", st(&pdps)).expect("fmt::Write for String never fails");
    for (site, p) in pdps.iter().flatten() {
        b.push_str(&demesne_emit_go::render_pdp_go(p, &format!("{site}Policy")));
    }
}

fn dump_claims(s: &Spec, b: &mut String) {
    let contract = s.claims_contract();
    let values: BTreeMap<String, String> = contract.as_ref().map(|c| c.iter().map(|k| (k.clone(), format!("v<{k}>&"))).collect()).unwrap_or_default();
    let minted = s.mint_claims(&values);
    writeln!(b, "mint: {} {} {}", st(&contract), st(&minted), minted.as_ref().map_or("", String::as_str)).expect("fmt::Write for String never fails");
    for sub in &s.subjects {
        let all: BTreeMap<String, String> = s.levels().iter().map(|l| (l.name.clone(), format!("s_{}", l.name))).collect();
        let verr = s.build_claims(&Principal { subject: sub.name.clone(), id: "id1".into(), scopes: all });
        let nv: BTreeMap<String, String> = s.levels().iter().filter(|l| !l.is_virtual).map(|l| (l.name.clone(), format!("s_{}", l.name))).collect();
        let out = s.mint_claims_for(&Principal { subject: sub.name.clone(), id: "id1".into(), scopes: nv });
        writeln!(b, "claims for {}: {} | {} {}", sub.name, st(&verr), st(&out), out.as_ref().map_or("", String::as_str))
            .expect("fmt::Write for String never fails");
    }
}
