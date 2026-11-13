use demesne_emit_sql::{GenFn, Sql};

const HEAD: &str = "topology { level root virtual level estate parent root level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none }\n";

fn spec(scoped: &str, probes: &str) -> String {
    format!("{HEAD}object room {{\n  table rooms\n  scoped {scoped}\n{probes}\n  permission view = @kind(\"member\") @rls maps select\n}}\n")
}

fn definers(src: &str) -> Result<Vec<GenFn>, String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    Sql::new(&s).emit_definers().map_err(|e| e.to_string())
}

fn probe(src: &str, name: &str) -> GenFn {
    let defs = definers(src).unwrap_or_else(|e| panic!("{e}\n{src}"));
    defs.into_iter().find(|d| d.name == name).unwrap_or_else(|| panic!("no {name}"))
}

#[test]
fn a_probe_answers_inside_the_callers_containment_and_takes_only_what_it_matches() {
    let src = spec(
        "estate > space wildcard confers select",
        "  probe room_named(name text, floor integer as on_floor)\n  probe rooms_here() count\n  probe room_by_name(name text) key",
    );
    let s = demesne_syntax::parse(&src).expect("parses");
    let sql = Sql::new(&s);
    let contained = format!("(estate_id = {} AND (space_id IS NULL OR space_id = {}))", sql.claim("estate_id"), sql.claim("space_id"));
    let exists = probe(&src, "room_named");
    assert_eq!((exists.sig.as_str(), exists.returns.as_str(), exists.strict), ("p_name text, on_floor integer", "", true));
    assert_eq!(exists.body, format!("EXISTS (SELECT 1 FROM rooms WHERE {contained} AND name = room_named.p_name AND floor = room_named.on_floor)"));
    let count = probe(&src, "rooms_here");
    assert_eq!((count.sig.as_str(), count.returns.as_str(), count.strict), ("", "bigint", false));
    assert_eq!(count.body, format!("count(*) FROM rooms WHERE {contained}"));
    let key = probe(&src, "room_by_name");
    assert_eq!((key.returns.as_str(), key.strict), ("text", true));
    assert_eq!(key.body, format!("id FROM rooms WHERE {contained} AND name = room_by_name.p_name ORDER BY id LIMIT 1"));
    for f in [&exists, &count, &key] {
        assert!(!f.body.contains("kind"), "a probe carries the object's containment and none of its permission:\n{}", f.body);
    }
}

#[test]
fn a_probe_is_refused_where_it_would_answer_for_the_whole_table_or_clash() {
    let cases = [
        ("an uncontained object", spec("root", "  probe any_room(name text)"), "which no claim contains"),
        (
            "two probes, one name",
            spec("estate", "  probe taken(name text)\n  probe taken(floor integer)"),
            "probe \"taken\" shares its name with another probe or an export",
        ),
        (
            "a probe named as a generated function",
            spec("estate", "  relation r: member via grant acl(room_id, kind, who, access)\n  probe acl_grants(name text)"),
            "probe \"acl_grants\" collides with a generated function",
        ),
        ("one column twice", spec("estate", "  probe taken(name text, name text as other)"), "binds column \"name\" or parameter \"other\" twice"),
        ("one parameter twice", spec("estate", "  probe taken(name text as p, floor integer as p)"), "binds column \"floor\" or parameter \"p\" twice"),
        ("an unknown type", spec("estate", "  probe taken(name varchar)"), "parameter \"p_name\" has unsupported type \"varchar\""),
    ];
    for (what, src, want) in cases {
        let err = definers(&src).map(|defs| defs.iter().map(|d| d.name.clone()).collect::<Vec<_>>()).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
}
