use demesne_emit_sql::Sql;
use demesne_model::pdp::{emit_field_access, emit_field_scopes, emit_pdp};
use demesne_model::{Principal, SpecExt, SurfaceExt};
use demesne_syntax::Spec;
use std::collections::BTreeMap;

fn st<T>(r: &Result<T, String>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => format!("error: {e}"),
    }
}

pub fn api_dump(s: &Spec) -> String {
    let mut b = String::new();
    let sql = Sql::new(s);
    let names = sql.definer_names();
    b.push_str(&format!("definer names: {} {}\n", st(&names), names.as_ref().map(|n| n.join(" ")).unwrap_or_default()));
    for o in &s.objects {
        let pc = s.point_check_sql(&o.name);
        b.push_str(&format!("pointcheck {}: {} {}\n", o.name, st(&pc), pc.as_ref().map(String::as_str).unwrap_or("")));
        let ra = s.resource_access_surface(&o.name);
        b.push_str(&format!("resourceaccess {}: {}\n", o.name, st(&ra)));
    }
    let presets = s.expanded_presets("");
    b.push_str(&format!("expanded presets: {}\n", st(&presets)));
    if let Ok(p) = &presets {
        for (k, v) in p {
            b.push_str(&format!("  {} = {}\n", k, v.join(" ")));
        }
    }
    for v in &s.vocabs {
        b.push_str(&format!("vocabulary {}:", v.name));
        for p in &v.permissions {
            b.push_str(&format!(" {}/{}", p, p.contains('*')));
        }
        b.push('\n');
    }
    let ent = demesne_emit_go::render_claims_contract_entries_go(s, "ClaimsContractEntries");
    b.push_str(&format!("claims entries go: {}\n{}", st(&ent), ent.as_ref().map(String::as_str).unwrap_or("")));
    let fs = emit_field_scopes(s);
    b.push_str(&format!("field scopes: {}\n", st(&fs)));
    if let Ok(fs) = &fs {
        for (site, m) in fs {
            for (f, scope) in m {
                b.push_str(&format!("  {site} {f} -> {scope}\n"));
            }
        }
    }
    for (name, fa) in emit_field_access(s) {
        let table = &s.object_by_name(&name).unwrap().table;
        b.push_str(&format!(
            "field access {name} go:\n{}field access {name} ts:\n{}field access {name} grants:\n{}",
            demesne_emit_go::render_field_access_go(&fa),
            demesne_emit_ts::render_field_access_ts(&fa),
            demesne_emit_sql::render_field_grants(&fa, table)
        ));
    }
    for rg in s.reach_grants() {
        b.push_str(&format!("reach grant {} {} {}\n", rg.edge_table(), rg.grantee_column(), rg.granularity()));
    }
    let surf = sql.emit_app_surface();
    b.push_str(&format!("app surface: {}\n", st(&surf)));
    if let Ok(surf) = &surf {
        for o in &surf.objects {
            for c in &o.checks {
                b.push_str(&format!("  check {}.{}: {}\n", o.object, c.verb, c.check_sql));
            }
        }
    }
    let pdps = emit_pdp(s);
    b.push_str(&format!("pdp: {}\n", st(&pdps)));
    if let Ok(pdps) = &pdps {
        for (site, p) in pdps {
            b.push_str(&demesne_emit_go::render_pdp_go(p, &format!("{site}Policy")));
        }
    }
    let contract = s.claims_contract();
    let values: BTreeMap<String, String> =
        contract.as_ref().map(|c| c.iter().map(|k| (k.clone(), format!("v<{k}>&"))).collect()).unwrap_or_default();
    let minted = s.mint_claims(&values);
    b.push_str(&format!("mint: {} {} {}\n", st(&contract), st(&minted), minted.as_ref().map(String::as_str).unwrap_or("")));
    for sub in &s.subjects {
        let all: BTreeMap<String, String> = s.levels().iter().map(|l| (l.name.clone(), format!("s_{}", l.name))).collect();
        let verr = s.build_claims(&Principal { subject: sub.name.clone(), id: "id1".into(), scopes: all });
        let nv: BTreeMap<String, String> =
            s.levels().iter().filter(|l| !l.is_virtual).map(|l| (l.name.clone(), format!("s_{}", l.name))).collect();
        let out = s.mint_claims_for(&Principal { subject: sub.name.clone(), id: "id1".into(), scopes: nv });
        b.push_str(&format!(
            "claims for {}: {} | {} {}\n",
            sub.name,
            st(&verr),
            st(&out),
            out.as_ref().map(String::as_str).unwrap_or("")
        ));
    }
    for rs in &s.role_stores {
        match s.holds_resolver(&rs.name) {
            Err(e) => b.push_str(&format!("holds {}: error: {e}\n", rs.name)),
            Ok(hr) => b.push_str(&format!("holds {}: {} | {}\n", rs.name, hr.assignments_sql(), hr.global_assignments_sql())),
        }
    }
    b
}
