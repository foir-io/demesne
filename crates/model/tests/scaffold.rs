use demesne_model::Schema;
use demesne_model::scaffold::{ScaffoldOptions, scaffold};

fn tenancy() -> Schema {
    let mut sc = Schema::new();
    for (table, cols) in [
        ("tenants", &["id"][..]),
        ("projects", &["id", "tenant_id"][..]),
        ("members", &["id", "tenant_id"][..]),
        ("docs", &["id", "project_id", "tenant_id", "owner_id"][..]),
        ("comments", &["id", "doc_id", "project_id", "tenant_id"][..]),
        ("files", &["id", "project_id", "tenant_id"][..]),
        ("audit", &["id", "at"][..]),
    ] {
        for c in cols {
            sc.add_column(table, c, if *c == "at" { "timestamptz" } else { "uuid" }, *c == "owner_id");
        }
    }
    for (table, column, target) in [
        ("projects", "tenant_id", "tenants"),
        ("members", "tenant_id", "tenants"),
        ("docs", "project_id", "projects"),
        ("docs", "tenant_id", "tenants"),
        ("docs", "owner_id", "members"),
        ("comments", "doc_id", "docs"),
        ("comments", "project_id", "projects"),
        ("comments", "tenant_id", "tenants"),
        ("files", "project_id", "projects"),
        ("files", "tenant_id", "tenants"),
    ] {
        sc.add_foreign_key(table, column, target, "id");
    }
    sc
}

fn ties() -> Schema {
    let mut sc = Schema::new();
    for (table, cols) in [
        ("regions", &["id"][..]),
        ("zones", &["id"][..]),
        ("sites", &["id", "region_id", "zone_id"][..]),
        ("depots", &["id", "region_id", "area_id", "zone_id"][..]),
        ("crews", &["id", "area_id", "zone_id", "site_id"][..]),
        ("trucks", &["id", "site_id", "depot_id"][..]),
        ("loads", &["id", "site_id", "truck_id"][..]),
    ] {
        for c in cols {
            sc.add_column(table, c, "uuid", matches!(*c, "depot_id" | "truck_id"));
        }
    }
    for (table, column, target) in [
        ("sites", "region_id", "regions"),
        ("sites", "zone_id", "zones"),
        ("depots", "region_id", "regions"),
        ("depots", "area_id", "regions"),
        ("depots", "zone_id", "zones"),
        ("crews", "area_id", "regions"),
        ("crews", "zone_id", "zones"),
        ("crews", "site_id", "sites"),
        ("trucks", "site_id", "sites"),
        ("trucks", "depot_id", "depots"),
        ("loads", "site_id", "sites"),
        ("loads", "truck_id", "trucks"),
    ] {
        sc.add_foreign_key(table, column, target, "id");
    }
    sc
}

fn deeper() -> Schema {
    let mut sc = Schema::new();
    for (table, cols) in [
        ("alphas", &["id"][..]),
        ("betas", &["id", "alpha_id"][..]),
        ("gammas", &["id", "alpha_id", "beta_id"][..]),
        ("items", &["id", "alpha_id", "beta_id", "gamma_id", "aux_gamma_id"][..]),
        ("marks", &["id", "alpha_id", "beta_id", "gamma_id"][..]),
        ("tags", &["id", "beta_id", "gamma_id"][..]),
    ] {
        for c in cols {
            sc.add_column(table, c, "uuid", *c == "aux_gamma_id");
        }
    }
    for (table, column, target) in [
        ("betas", "alpha_id", "alphas"),
        ("gammas", "alpha_id", "alphas"),
        ("gammas", "beta_id", "betas"),
        ("items", "alpha_id", "alphas"),
        ("items", "beta_id", "betas"),
        ("items", "gamma_id", "gammas"),
        ("items", "aux_gamma_id", "gammas"),
        ("marks", "alpha_id", "alphas"),
        ("marks", "beta_id", "betas"),
        ("marks", "gamma_id", "gammas"),
        ("tags", "beta_id", "betas"),
        ("tags", "gamma_id", "gammas"),
    ] {
        sc.add_foreign_key(table, column, target, "id");
    }
    sc
}

#[test]
fn the_deepest_parent_and_the_most_used_column_name_win() {
    insta::assert_snapshot!("deeper", scaffold(&deeper(), ScaffoldOptions::default()).expect("alphas, betas and gammas are containers"));
}

#[test]
fn ties_break_by_name_and_a_second_root_is_named_not_forked() {
    insta::assert_snapshot!("ties", scaffold(&ties(), ScaffoldOptions::default()).expect("regions, zones and sites are containers"));
}

#[test]
fn tables_most_others_reference_become_the_topology() {
    insta::assert_snapshot!("default_threshold", scaffold(&tenancy(), ScaffoldOptions::default()).expect("tenants and projects are containers"));
    insta::assert_snapshot!("threshold_four", scaffold(&tenancy(), ScaffoldOptions { min_container_refs: 4 }).expect("tenants is still a container"));
}

#[test]
fn a_schema_with_no_container_is_refused() {
    let err = scaffold(&tenancy(), ScaffoldOptions { min_container_refs: 6 }).expect_err("no table has six referrers");
    insta::assert_snapshot!("no_container", err.to_string());
}
