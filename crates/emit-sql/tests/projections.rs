use demesne_emit_sql::{GenFn, Sql};

const HEAD: &str =
    "topology { level estate level space parent estate }\nsubject member { anchor space; reach self; identifies sub; roles none; binds owner }\n";

fn spec(clauses: &str) -> String {
    format!(
        "{HEAD}object card {{\n  table cards\n  scoped estate > space\n  relation owner: member via owner_id\n{clauses}\n  permission view = @scoped and owner @rls maps select\n}}\n"
    )
}

fn definers(src: &str) -> Result<Vec<GenFn>, String> {
    let s = demesne_syntax::parse(src).map_err(|e| e.to_string())?;
    demesne_emit_sql::validate(&s).map_err(|e| e.to_string())?;
    Sql::new(&s).emit_definers().map_err(|e| e.to_string())
}

#[test]
fn a_projection_returns_its_columns_for_the_rows_its_expression_admits_inside_containment() {
    let src = spec("  projection card_faces(id text, label text as title, rank integer) = @kind(\"member\") and not @row(status, \"hidden\")");
    let s = demesne_syntax::parse(&src).expect("parses");
    let sql = Sql::new(&s);
    let f = definers(&src).expect("compiles").into_iter().find(|d| d.name == "card_faces").expect("the projection");
    assert_eq!((f.sig.as_str(), f.returns.as_str(), f.strict), ("", "TABLE(id text, title text, rank integer)", false));
    assert_eq!(
        f.body,
        format!(
            "  SELECT cards.id::text, cards.label::text, cards.rank::integer FROM cards WHERE estate_id = {} AND space_id = {} AND (({} = 'member') AND ((status = 'hidden') IS NOT TRUE));",
            sql.claim("estate_id"),
            sql.claim("space_id"),
            sql.claim("kind")
        )
    );
    assert!(!f.body.contains("owner_id"), "the object's own permission is no part of it:\n{}", f.body);
}

#[test]
fn a_projection_is_checked_as_an_admit_arm_is() {
    let cases = [
        (
            "a row test alone",
            spec("  projection faces(id text) = @row(status, \"open\")"),
            "uses @row(status, \"open\") where it would admit a caller by itself",
        ),
        ("a negation alone", spec("  projection faces(id text) = not owner"), "is not positively gated"),
        ("an unknown relation", spec("  projection faces(id text) = stranger"), "stranger"),
        ("an unsupported type", spec("  projection faces(id varchar) = owner"), "column \"id\" has unsupported type \"varchar\""),
        ("one output twice", spec("  projection faces(id text, label text as id) = owner"), "projection \"faces\" returns \"id\" twice"),
        ("a taken name", spec("  probe faces(id text)\n  projection faces(id text) = owner"), "projection \"faces\" shares its name"),
        (
            "a generated function's name",
            spec("  relation g: member via grant acl(card_id, kind, who, access)\n  projection acl_grants(id text) = owner"),
            "projection \"acl_grants\" collides with a generated function",
        ),
    ];
    for (what, src, want) in cases {
        let err = definers(&src).map(|_| ()).expect_err(what);
        assert!(err.contains(want), "{what}: {err}");
    }
    demesne_syntax::parse(&spec("  projection faces() = owner")).expect_err("a projection names at least one column");
}
