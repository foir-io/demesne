use demesne_emit_sql::validate;

fn spec(view: &str) -> String {
    format!(
        r"topology {{
  level platform virtual
  level tenant   parent platform
}}
grant support at tenant
  via edge support_grants(grantee_id, tenant_id)
  active revoked_at expires expires_at

subject operator {{ anchor platform; reach via grant support; identifies sub; roles none }}
subject member   {{ anchor tenant;   reach descendants; identifies sub; roles none; binds owner }}

object invoice {{
  table  invoices
  scoped tenant
  relation owner: member via owner_id
  permission view = {view} @rls maps select
}}
"
    )
}

fn refusals(view: &str) -> Vec<(Option<usize>, String)> {
    match validate(&demesne_syntax::parse(&spec(view)).expect("the test spec parses")) {
        Ok(()) => Vec::new(),
        Err(e) => e.findings().iter().map(|f| (f.line(), f.message().to_string())).collect(),
    }
}

#[test]
fn scoped_beside_an_ordinary_term_is_refused_with_what_it_compiles_to() {
    assert_eq!(
        refusals("owner + @scoped"),
        [(
            Some(16),
            "permission invoice.view writes `owner + @scoped`, which compiles as `owner`: every term is already held to the row's scope, so `@scoped` beside `owner` adds no one; write `@scoped` alone to admit every caller in scope, or drop it".to_string()
        )]
    );
    let mixed = refusals("owner + @scoped + @self(actor_col)");
    assert!(mixed[0].1.contains("which compiles as `owner + @self(actor_col)`"), "{mixed:?}");
}

#[test]
fn a_term_that_admits_alone_under_and_or_not_is_refused_with_what_it_compiles_to() {
    for (view, inside) in [
        ("owner and @self(actor_col)", "`@self(actor_col)` inside `owner and @self(actor_col)`"),
        ("not @self(actor_col) and owner", "`@self(actor_col)` inside `not @self(actor_col) and owner`"),
        ("owner and (via grant support + @public)", "`via grant support`, `@public` inside `owner and (via grant support + @public)`"),
    ] {
        let got = refusals(view);
        assert_eq!(got.len(), 1, "{view}: {got:?}");
        assert_eq!(got[0].0, Some(16), "{view}");
        assert!(got[0].1.starts_with(&format!("permission invoice.view writes {inside}, but a @self, @public or `via grant` term")), "{view}: {got:?}");
    }
    let got = refusals("not @self(actor_col) and owner");
    assert!(got[0].1.contains("so the permission compiles as `owner + @self(actor_col)`, wider than it reads"), "{got:?}");
    for (view, compiled) in [
        (r#"owner and @row(status, "open") and @self(actor_col)"#, r#"owner and @row(status, "open") + @self(actor_col)"#),
        ("owner and (via grant support + @public)", "owner + via grant support + @public"),
        (r#"owner and (@self(actor_col) + @row(status, "open"))"#, r#"owner and @row(status, "open") + @self(actor_col)"#),
        (
            r#"owner and (@row(status, "open") + @row(kind, "x") + @self(actor_col))"#,
            r#"owner and (@row(status, "open") + @row(kind, "x")) + @self(actor_col)"#,
        ),
    ] {
        let got = refusals(view);
        assert!(got.iter().any(|(_, m)| m.contains(&format!("so the permission compiles as `{compiled}`, wider than it reads"))), "{view}: {got:?}");
    }
}

#[test]
fn each_term_where_it_compiles_as_written_is_accepted() {
    for view in ["@scoped", "@scoped and owner", "@scoped + @self(actor_col)", "@scoped + via grant support", "owner + @self(actor_col) + @public"] {
        assert_eq!(refusals(view), [], "{view}");
    }
}
