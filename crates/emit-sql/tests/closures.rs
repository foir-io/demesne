use demesne_emit_sql::{ClosureTrigger, GenFn, Policy, RlsResult, Sql};
use demesne_syntax::Spec;

const HEAD: &str = "topology { level estate level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none }\n";
const DOWN: &str = "member via closure paths(anc, des) on folder_id from claim folder_id missing allow";
const UP: &str = "member via closure paths(des, anc) on folder_id from claim folder_id missing deny";

fn compile(src: &str) -> Spec {
    let s = demesne_syntax::parse(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    demesne_emit_sql::validate(&s).unwrap_or_else(|e| panic!("{e}\n{src}"));
    s
}

fn tree(closures: &str, first: &str, second: &str) -> Spec {
    compile(&format!(
        "{HEAD}{closures}\nobject doc {{\n  table docs\n  scoped estate > space\n  relation first: {first}\n  relation second: {second}\n  permission view = @scoped and (first + second) @rls maps select\n  permission edit = @scoped and first @rls maps update\n}}\n"
    ))
}

fn policy<'a>(res: &'a RlsResult, name: &str) -> &'a Policy {
    res.policies.iter().find(|p| p.name == name).unwrap_or_else(|| panic!("no {name} policy (unsupported: {:?})", res.unsupported))
}

fn definer<'a>(defs: &'a [GenFn], name: &str) -> &'a GenFn {
    defs.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name} definer: {:?}", defs.iter().map(|d| &d.name).collect::<Vec<_>>()))
}

fn names(defs: &[GenFn]) -> Vec<&str> {
    defs.iter().map(|d| d.name.as_str()).collect()
}

#[test]
fn an_undeclared_closure_looks_each_row_up_with_the_caller_on_the_side_its_relation_names() {
    let cases = [
        (DOWN, UP, "anc = p_ancestor AND des = p_descendant", "(CLAIM, folder_id)", "(folder_id, CLAIM)"),
        (UP, DOWN, "des = p_ancestor AND anc = p_descendant", "(folder_id, CLAIM)", "(CLAIM, folder_id)"),
    ];
    for (first, second, lookup, down_args, up_args) in cases {
        let s = tree("", first, second);
        let sql = Sql::new(&s);
        let claim = sql.claim("folder_id");
        let down = format!("({claim} IS NULL OR auth.paths_reachable{})", down_args.replace("CLAIM", &claim));
        let up = format!("auth.paths_reachable{}", up_args.replace("CLAIM", &claim));
        let res = sql.emit_rls().expect("the policies compile");
        let view = &policy(&res, "docs_select").using;
        assert!(view.contains(&down) && view.contains(&up), "the read reaches both ways:\n{view}");
        let edit = &policy(&res, "docs_update").using;
        let (wanted, other) = if first == DOWN { (&down, &up) } else { (&up, &down) };
        assert!(edit.contains(wanted.as_str()) && !edit.contains(other.as_str()), "the write reaches one way, the first relation's:\n{edit}");
        let defs = sql.emit_definers().expect("the definers compile");
        assert_eq!(names(&defs), ["paths_reachable"], "an undeclared closure keeps its one lookup");
        let reach = definer(&defs, "paths_reachable");
        assert_eq!(reach.sig, "p_ancestor text, p_descendant text");
        assert_eq!(reach.body, format!("EXISTS (SELECT 1 FROM paths WHERE {lookup})"), "the lookup takes the first relation's columns in its order");
        assert!(reach.strict);
    }
}

#[test]
fn a_declared_closure_reads_each_direction_as_a_set_computed_once() {
    for (closures, base) in [("closure paths(anc, des)", "paths"), ("closure paths(anc, des) named tree", "tree")] {
        for (first, second) in [(DOWN, UP), (UP, DOWN)] {
            let s = tree(closures, first, second);
            let sql = Sql::new(&s);
            let claim = sql.claim("folder_id");
            let down = format!("({claim} IS NULL OR folder_id IN (SELECT auth.{base}_descendants({claim})))");
            let up = format!("folder_id IN (SELECT auth.{base}_ancestors({claim}))");
            let res = sql.emit_rls().expect("the policies compile");
            let view = &policy(&res, "docs_select").using;
            assert!(view.contains(&down) && view.contains(&up), "{closures}: the read reaches both ways:\n{view}");
            assert!(!view.contains("_reachable"), "{closures}: no per-row lookup:\n{view}");
            let edit = policy(&res, "docs_update");
            let (wanted, other) = if first == DOWN { (&down, &up) } else { (&up, &down) };
            for pred in [&edit.using, &edit.check] {
                assert!(pred.contains(wanted.as_str()) && !pred.contains(other.as_str()), "{closures}: the write reaches one way:\n{pred}");
            }
            let defs = sql.emit_definers().expect("the definers compile");
            assert_eq!(names(&defs), [format!("{base}_reachable"), format!("{base}_descendants"), format!("{base}_ancestors")]);
            let (below, above) = (definer(&defs, &format!("{base}_descendants")), definer(&defs, &format!("{base}_ancestors")));
            assert_eq!((below.sig.as_str(), below.returns.as_str(), below.body.as_str()), ("p_node text", "SETOF text", "des FROM paths WHERE anc = p_node"));
            assert_eq!((above.sig.as_str(), above.returns.as_str(), above.body.as_str()), ("p_node text", "SETOF text", "anc FROM paths WHERE des = p_node"));
            assert!(below.strict && above.strict, "a caller with no node reaches the empty set");
            assert_eq!(definer(&defs, &format!("{base}_reachable")).body, "EXISTS (SELECT 1 FROM paths WHERE anc = p_ancestor AND des = p_descendant)");
        }
    }
}

#[test]
fn the_declaration_fixes_the_edge_whatever_order_the_relations_come_in() {
    let s = tree("closure paths(des, anc)", DOWN, UP);
    let sql = Sql::new(&s);
    let claim = sql.claim("folder_id");
    let res = sql.emit_rls().expect("the policies compile");
    let edit = &policy(&res, "docs_update").using;
    assert!(
        edit.contains(&format!("folder_id IN (SELECT auth.paths_ancestors({claim}))")),
        "a relation naming the declared descendant first reaches above:\n{edit}"
    );
    let defs = sql.emit_definers().expect("the definers compile");
    assert_eq!(definer(&defs, "paths_ancestors").body, "des FROM paths WHERE anc = p_node");
}

#[test]
fn a_declared_depth_adds_the_ordered_path_and_an_identifier_type_carries_through() {
    let s = compile(&format!("identifiers uuid\n{HEAD}closure paths(anc, des) depth hops\n"));
    let defs = Sql::new(&s).emit_definers().expect("the definers compile");
    assert_eq!(names(&defs), ["paths_reachable", "paths_descendants", "paths_ancestors", "paths_path"]);
    let path = definer(&defs, "paths_path");
    assert_eq!((path.sig.as_str(), path.returns.as_str()), ("p_node uuid", "TABLE(node uuid, depth integer)"));
    assert_eq!(path.body, "  SELECT anc, hops::integer FROM paths WHERE des = p_node ORDER BY hops DESC, anc;");
    assert!(path.strict && path.raw_body);
    assert_eq!(definer(&defs, "paths_descendants").returns, "SETOF uuid");
    let no_depth = compile(&format!("{HEAD}closure paths(anc, des)\n"));
    assert!(!names(&Sql::new(&no_depth).emit_definers().expect("the definers compile")).contains(&"paths_path"), "no depth column, no path");
}

fn triggers(src: &str) -> Vec<ClosureTrigger> {
    Sql::new(&compile(src)).emit_triggers()
}

fn lacks<'a>(sql: &str, frags: &[&'a str]) -> Vec<&'a str> {
    frags.iter().copied().filter(|f| !sql.contains(f)).collect()
}

#[test]
fn a_relations_base_maintains_as_it_always_has_and_a_reversed_relation_cannot_turn_it_over() {
    let owner_keyed = |cols: &str| format!("member via closure paths({cols}) base folders(id, parent_id) on folder_id");
    let src = |first: &str, second: &str| {
        format!(
            "{HEAD}subject holder {{ anchor space; reach self; identifies holder_id; roles none; binds owner }}\nobject doc {{\n  table docs\n  scoped estate > space\n  relation first: {first}\n  relation second: {second}\n  permission view = first + second @rls maps select\n}}\n"
        )
    };
    let plain = triggers(&src(&owner_keyed("anc, des"), DOWN));
    let reversed_second = triggers(&src(DOWN, &owner_keyed("des, anc")));
    assert_eq!(plain, reversed_second, "the base's relation names the edge upward, and the maintenance is the downward edge's all the same");
    let t = &plain[0];
    assert_eq!((t.closure.as_str(), t.ancestor.as_str(), t.descendant.as_str(), t.base.as_str(), &t.declared), ("paths", "anc", "des", "folders", &None));
    let f = t.function_sql();
    assert_eq!(
        lacks(
            &f,
            &[
                "CREATE OR REPLACE FUNCTION auth.paths_maintain()",
                "INSERT INTO paths (anc, des) VALUES (NEW.id, NEW.id) ON CONFLICT DO NOTHING;",
                "SELECT c.anc, NEW.id FROM paths c WHERE c.des = NEW.parent_id",
                "IF (NEW.parent_id IS DISTINCT FROM OLD.parent_id) THEN",
            ]
        ),
        [] as [&str; 0],
        "{f}"
    );
    assert!(!f.contains("pg_advisory_xact_lock") && !f.contains("RAISE"), "a relation's base takes no lock and refuses nothing:\n{f}");
    assert!(t.trigger_sql().contains("CREATE TRIGGER paths_maintain_upd AFTER UPDATE ON public.folders FOR EACH ROW EXECUTE FUNCTION auth.paths_maintain();"));
}

const FULL: &str = "closure paths(anc, des) base folders(id, parent_id) scope space_id depth hops";

#[test]
fn a_declared_base_maintains_under_a_lock_with_scope_and_depth_and_refuses_what_would_corrupt_it() {
    let t = &triggers(&format!("definers schema \"kernel\"\ntables schema \"app\"\n{HEAD}{FULL} named tree\n"))[0];
    let f = t.function_sql();
    assert_eq!(
        lacks(
            &f,
            &[
                "CREATE OR REPLACE FUNCTION kernel.tree_maintain()",
                "SET search_path = pg_catalog, app",
                "PERFORM pg_advisory_xact_lock(hashtext('paths'), COALESCE(hashtext(OLD.space_id::text), 0));",
                "PERFORM pg_advisory_xact_lock(hashtext('paths'), COALESCE(hashtext(NEW.space_id::text), 0));",
                "DELETE FROM paths WHERE des = OLD.id OR anc = OLD.id;",
                "INSERT INTO paths (anc, des, space_id, hops) VALUES (NEW.id, NEW.id, NEW.space_id, 0) ON CONFLICT DO NOTHING;",
                "SELECT p.anc, sub.des, NEW.space_id, p.hops + sub.hops + 1",
                "WHERE p.des = NEW.parent_id AND sub.anc = NEW.id",
                "IF NEW.space_id IS DISTINCT FROM OLD.space_id THEN",
                "CONSTRAINT = 'tree_scope_fixed', TABLE = 'folders'",
                "IF NEW.parent_id IS NOT NULL AND EXISTS (SELECT 1 FROM paths WHERE anc = NEW.id AND des = NEW.parent_id) THEN",
                "IF NEW.parent_id = NEW.id THEN",
                "USING ERRCODE = 'check_violation', CONSTRAINT = 'tree_acyclic', TABLE = 'folders'",
                "IF NOT EXISTS (SELECT 1 FROM paths WHERE anc = NEW.parent_id AND des = NEW.parent_id AND space_id IS NOT DISTINCT FROM NEW.space_id) THEN",
                "CONSTRAINT = 'tree_parent_known', TABLE = 'folders'",
            ]
        ),
        [] as [&str; 0],
        "{f}"
    );
    assert_eq!(f.matches("pg_advisory_xact_lock").count(), 2, "one lock for the row leaving, one for the row arriving:\n{f}");
    assert!(
        f.find("pg_advisory_xact_lock(hashtext('paths'), COALESCE(hashtext(NEW").expect("a lock") < f.find("IF (TG_OP = 'UPDATE')").expect("an update branch"),
        "the lock comes before any read of the closure:\n{f}"
    );
    let trig = t.trigger_sql();
    assert_eq!(
        lacks(
            &trig,
            &[
                "DROP TRIGGER IF EXISTS tree_maintain_ins ON app.folders;",
                "CREATE TRIGGER tree_maintain_ins AFTER INSERT ON app.folders FOR EACH ROW EXECUTE FUNCTION kernel.tree_maintain();",
                "CREATE TRIGGER tree_maintain_upd AFTER UPDATE ON app.folders FOR EACH ROW WHEN (OLD.parent_id IS DISTINCT FROM NEW.parent_id OR OLD.space_id IS DISTINCT FROM NEW.space_id) EXECUTE FUNCTION kernel.tree_maintain();",
                "CREATE TRIGGER tree_maintain_del AFTER DELETE ON app.folders FOR EACH ROW EXECUTE FUNCTION kernel.tree_maintain();",
            ]
        ),
        [] as [&str; 0],
        "{trig}"
    );
}

#[test]
fn a_declared_base_with_no_scope_or_depth_writes_neither() {
    let t = &triggers(&format!("{HEAD}closure paths(anc, des) base folders(id, parent_id)\n"))[0];
    let f = t.function_sql();
    assert_eq!(
        lacks(
            &f,
            &[
                "CREATE OR REPLACE FUNCTION auth.paths_maintain()",
                "PERFORM pg_advisory_xact_lock(hashtext('paths'), 0);",
                "INSERT INTO paths (anc, des) VALUES (NEW.id, NEW.id) ON CONFLICT DO NOTHING;",
                "SELECT p.anc, sub.des\n",
                "IF NOT EXISTS (SELECT 1 FROM paths WHERE anc = NEW.parent_id AND des = NEW.parent_id) THEN",
                "CONSTRAINT = 'paths_acyclic'",
            ]
        ),
        [] as [&str; 0],
        "{f}"
    );
    assert!(!f.contains("scope_fixed"), "{f}");
    assert!(t.trigger_sql().contains("FOR EACH ROW WHEN (OLD.parent_id IS DISTINCT FROM NEW.parent_id) EXECUTE FUNCTION auth.paths_maintain();"));
    assert!(triggers(&format!("{HEAD}closure paths(anc, des) depth hops\n")).is_empty(), "no base, no maintenance");
}

#[test]
fn the_trigger_listing_names_the_declared_maintenance_in_the_migration() {
    let s = compile(&format!("{HEAD}{FULL}\n"));
    let all = Sql::new(&s).triggers_sql();
    assert!(all.contains("auth.paths_maintain()") && all.contains("paths_maintain_del"), "{all}");
}

fn doc(scoped: &str, body: &str) -> Spec {
    compile(&format!("{HEAD}object doc {{\n  table docs\n  scoped {scoped}\n{body}\n}}\n"))
}

const CRUD: &str = "  permission view = @scoped @rls maps select\n  permission create = @scoped @rls maps insert\n  permission edit = @scoped @rls maps update\n  permission delete = @scoped @rls maps delete";

#[test]
fn an_exact_level_contains_every_operation_by_is_not_distinct_from() {
    let s = doc("estate > space exact", CRUD);
    let sql = Sql::new(&s);
    let res = sql.emit_rls().expect("the policies compile");
    let want = format!("(estate_id = {} AND space_id IS NOT DISTINCT FROM {})", sql.claim("estate_id"), sql.claim("space_id"));
    for (name, using, check) in [("docs_select", true, false), ("docs_insert", false, true), ("docs_update", true, true), ("docs_delete", true, false)] {
        let p = policy(&res, name);
        assert_eq!((p.using.as_str(), p.check.as_str()), (if using { want.as_str() } else { "" }, if check { want.as_str() } else { "" }), "{name}");
    }
    let wild = doc("estate > space wildcard confers select", CRUD);
    let wild_res = Sql::new(&wild).emit_rls().expect("the policies compile");
    for name in ["docs_insert", "docs_update", "docs_delete"] {
        assert_eq!(policy(&wild_res, name), policy(&res, name), "{name}: an exact level is a wildcard that widens no operation");
    }
    assert_ne!(policy(&wild_res, "docs_select").using, want, "the wildcard still widens the operation it confers");
}

#[test]
fn the_null_absent_and_exact_terms_compile_inside_a_require() {
    let require = |expr: &str| -> String {
        let s = doc("estate > space", &format!("  relation owner: member via owner_id\n{CRUD}\n  require edit = {expr}"));
        let res = Sql::new(&s).emit_rls().expect("the policies compile");
        let p = policy(&res, "docs_update_require");
        assert!(p.restrictive);
        assert_eq!(p.using, p.check);
        p.using.clone()
    };
    let probe = doc("estate", CRUD);
    let sql = Sql::new(&probe);
    let (folder, space, sub) = (sql.claim("folder_id"), sql.claim("space_id"), sql.claim("sub"));
    for (expr, want) in [
        ("@row(folder_id, null)", "folder_id IS NULL".to_string()),
        ("not @row(folder_id, null)", "(folder_id IS NULL) IS NOT TRUE".to_string()),
        ("@row(kind, \"note\")", "kind = 'note'".to_string()),
        ("@claim(\"folder_id\", null)", format!("{folder} IS NULL")),
        ("@claim(\"folder_id\", \"f1\")", format!("{folder} = 'f1'")),
        ("@within(space exact)", format!("space_id IS NOT DISTINCT FROM {space}")),
        ("@within(space nullable)", format!("(space_id IS NULL OR space_id = {space})")),
        ("@within(space)", format!("space_id = {space}")),
        ("owner + @row(folder_id, null)", format!("owner_id = {sub} OR folder_id IS NULL")),
        ("owner + not @row(kind, \"private\")", format!("owner_id = {sub} OR (kind = 'private') IS NOT TRUE")),
        (
            "(@claim(\"folder_id\", null) + not @row(folder_id, null)) and @within(space exact)",
            format!("({folder} IS NULL OR (folder_id IS NULL) IS NOT TRUE) AND (space_id IS NOT DISTINCT FROM {space})"),
        ),
    ] {
        assert_eq!(require(expr), want, "{expr}");
    }
}

#[test]
fn a_null_row_test_narrows_a_permission_as_any_row_test_does() {
    let s = doc(
        "estate > space",
        "  permission view = @scoped @rls maps select\n  permission edit = @scoped and @row(archived_at, null) @rls maps update\n  permission delete = @scoped and not @row(archived_at, null) @rls maps delete",
    );
    let res = Sql::new(&s).emit_rls().expect("the policies compile");
    assert!(policy(&res, "docs_update").using.ends_with("AND ((archived_at IS NULL)))"), "{}", policy(&res, "docs_update").using);
    assert!(policy(&res, "docs_delete").using.ends_with("AND (((archived_at IS NULL) IS NOT TRUE)))"), "{}", policy(&res, "docs_delete").using);
}

#[test]
fn a_reach_through_two_grants_contains_by_either_set_on_the_operations_it_names() {
    let s = compile(
        "topology { level estate level folder parent estate }\ngrant down at folder via edge paths(anc, des) confers select\ngrant up at folder via edge paths(des, anc) named paths_up confers select\nsubject viewer { anchor folder; reach via grant down; identifies folder_id; roles none }\nobject atlas {\n  table atlases\n  scoped estate > folder wildcard confers select\n  reach down via down, up for select\n  permission view = @scoped @rls maps select\n  permission edit = @scoped @rls maps update\n}\nobject plain {\n  table plains\n  scoped estate > folder wildcard confers select\n  reach down via up for select\n  permission view = @scoped @rls maps select\n}\n",
    );
    let sql = Sql::new(&s);
    let claim = sql.claim("folder_id");
    let res = sql.emit_rls().expect("the policies compile");
    let (down, up) = (format!("folder_id IN (SELECT auth.paths_reach_set({claim}))"), format!("folder_id IN (SELECT auth.paths_up_reach_set({claim}))"));
    let view = &policy(&res, "atlases_select").using;
    assert!(view.contains(&format!("(folder_id IS NULL OR folder_id = {claim}) OR ({down} OR {up})")), "{view}");
    let edit = &policy(&res, "atlases_update").using;
    assert!(!edit.contains("_reach_set"), "the reach is for the read alone:\n{edit}");
    let one_way = &policy(&res, "plains_select").using;
    assert!(
        one_way.contains(&format!("(folder_id IS NULL OR folder_id = {claim}) OR {up})")) && !one_way.contains(&down),
        "one grant stays unbracketed:\n{one_way}"
    );
}
