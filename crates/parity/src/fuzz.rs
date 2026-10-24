pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }

    pub fn chance(&mut self, pct: u64) -> bool {
        self.next_u64() % 100 < pct
    }

    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

struct Lvl {
    name: String,
    is_virtual: bool,
    col: String,
}

struct World {
    levels: Vec<Lvl>,
    perms: Vec<String>,
    presets: Vec<(String, String)>,
    has_store: bool,
    store_perms_col: bool,
    edge_grants: Vec<(String, String)>,
    claim_grants: Vec<String>,
    owner_anchor: String,
    has_admin: bool,
    has_transient: bool,
    has_member_vocab: bool,
    grant_reached: bool,
    objects: Vec<(String, String)>,
}

const LEVEL_POOL: [&str; 7] = ["org", "tenant", "project", "workspace", "space", "folder", "team"];
const DOMAINS: [&str; 5] = ["docs", "content", "billing", "self", "media"];
const VERBS: [&str; 6] = ["read", "write", "publish", "delete", "manage", "share"];
const OBJECT_POOL: [&str; 8] = ["doc", "record", "asset", "note", "board", "file", "ticket", "page"];
const OPS: [(&str, &str); 4] = [("view", "select"), ("edit", "update"), ("create", "insert"), ("remove", "delete")];

pub fn generate(seed: u64) -> String {
    let mut r = Rng::new(seed);
    let mut w = World {
        levels: Vec::new(),
        perms: Vec::new(),
        presets: Vec::new(),
        has_store: false,
        store_perms_col: false,
        edge_grants: Vec::new(),
        claim_grants: Vec::new(),
        owner_anchor: String::new(),
        has_admin: false,
        has_transient: false,
        has_member_vocab: false,
        grant_reached: false,
        objects: Vec::new(),
    };
    let mut out = String::new();
    topology(&mut r, &mut w, &mut out);
    if r.chance(15) {
        out.push_str(&format!("definers schema \"{}\"\n", r.pick(&["authz", "kernel", "sec"])));
    }
    if r.chance(15) {
        out.push_str(&format!("tables schema \"{}\"\n", r.pick(&["app", "data"])));
    }
    if r.chance(10) {
        out.push_str("identifiers uuid\n");
    }
    if r.chance(15) {
        out.push_str(&format!("claims via \"{}\" {}\n", r.pick(&["request.jwt.claims", "app.claims"]), r.pick(&["json", "jsonb"])));
    }
    vocabularies(&mut r, &mut w, &mut out);
    rolestore(&mut r, &mut w, &mut out);
    grants(&mut r, &mut w, &mut out);
    subjects(&mut r, &mut w, &mut out);
    let n = 1 + r.below(5);
    for i in 0..n {
        object(&mut r, &mut w, &mut out, i);
    }
    if r.chance(40) && !w.perms.is_empty() {
        out.push_str("\nprocedures staff {\n");
        for i in 0..1 + r.below(3) {
            out.push_str(&format!("  api.v1.Service/Call{i} -> {}\n", r.pick(&w.perms)));
        }
        out.push_str("}\n");
        if r.chance(50) {
            out.push_str("ungoverned staff {\n  meta.v1.Meta/Healthz : \"liveness probe\"\n}\n");
        }
    }
    out
}

fn topology(r: &mut Rng, w: &mut World, out: &mut String) {
    out.push_str("topology {\n");
    let mut prev: Option<String> = None;
    if r.chance(55) {
        out.push_str("  level platform virtual\n");
        w.levels.push(Lvl { name: "platform".into(), is_virtual: true, col: String::new() });
        prev = Some("platform".into());
    }
    let n = 1 + r.below(4);
    let mut pool: Vec<&str> = LEVEL_POOL.to_vec();
    for _ in 0..n {
        let name = pool.remove(r.below(pool.len())).to_string();
        let mut line = format!("  level {name}");
        if let Some(p) = &prev {
            line.push_str(&format!(" parent {p}"));
        }
        let mut col = format!("{name}_id");
        if r.chance(8) {
            col = format!("{name}_ref");
            line.push_str(&format!(" col {col}"));
        }
        if r.chance(6) {
            line.push_str(&format!(" claim {name}_claim"));
        }
        out.push_str(&line);
        out.push('\n');
        w.levels.push(Lvl { name: name.clone(), is_virtual: false, col });
        prev = Some(name);
    }
    out.push_str("}\n");
}

fn real_levels(w: &World) -> Vec<&Lvl> {
    w.levels.iter().filter(|l| !l.is_virtual).collect()
}

fn vocabularies(r: &mut Rng, w: &mut World, out: &mut String) {
    let mut perms = Vec::new();
    for _ in 0..2 + r.below(5) {
        let p = format!("{}:{}", r.pick(&DOMAINS), r.pick(&VERBS));
        if !perms.contains(&p) {
            perms.push(p);
        }
    }
    out.push_str("\nvocabulary staff {\n");
    for (i, p) in perms.iter().enumerate() {
        let mut line = format!("  permission {p}");
        if i > 0 && r.chance(20) {
            if r.chance(30) {
                line.push_str(" implies *");
            } else {
                line.push_str(&format!(" implies {}", perms[r.below(i)]));
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    let reals: Vec<String> = real_levels(w).iter().map(|l| l.name.clone()).collect();
    let mut presets: Vec<(String, String)> = Vec::new();
    let mut targets: Vec<String> = reals.clone();
    for _ in 0..r.below(2) {
        targets.push(if r.chance(85) { r.pick(&reals).clone() } else { w.levels[0].name.clone() });
    }
    for (i, lvl) in targets.into_iter().enumerate() {
        let name = format!("{lvl}_role{i}");
        let body = if r.chance(20) {
            "*".to_string()
        } else {
            let mut items = vec![r.pick(&perms).clone()];
            if let Some((prev, _)) = presets.last()
                && r.chance(40)
            {
                items.push(prev.clone());
            }
            items.join(" + ")
        };
        out.push_str(&format!("  preset {name} @ {lvl} = {body}\n"));
        presets.push((name, lvl));
    }
    if presets.len() > 1 && r.chance(40) {
        let names: Vec<&str> = presets.iter().map(|(n, _)| n.as_str()).collect();
        out.push_str(&format!("  rank {}\n", names.join(" > ")));
    }
    out.push_str("}\n");
    if r.chance(40) {
        out.push_str("vocabulary member {\n  permission self:read\n  permission self:write\n}\n");
        w.has_member_vocab = true;
    }
    w.perms = perms;
    w.presets = presets;
}

fn rolestore(r: &mut Rng, w: &mut World, out: &mut String) {
    if !r.chance(70) {
        return;
    }
    w.has_store = true;
    let cols: Vec<String> = real_levels(w).iter().map(|l| l.col.clone()).collect();
    out.push_str("\nrolestore staff {\n  assignments role_assignments\n");
    if r.chance(80) {
        out.push_str("  kind principal_kind = \"staff\"\n");
    }
    out.push_str(&format!("  subject principal_id\n  scope {}\n  rolejoin role_id roles id key\n", cols.join(" ")));
    if r.chance(85) {
        out.push_str("  revoked revoked_at");
        if r.chance(30) {
            out.push_str(" by revoked_by");
        }
        out.push('\n');
    }
    if r.chance(50) {
        out.push_str("  permissions perms\n");
        w.store_perms_col = true;
    }
    if r.chance(20) {
        out.push_str("  granted granted_at by granted_by\n");
    }
    if r.chance(15) {
        out.push_str("  pk assignment_id\n");
    }
    if r.chance(15) {
        out.push_str("  column note\n");
    }
    out.push_str("}\n");
}

fn grants(r: &mut Rng, w: &mut World, out: &mut String) {
    let reals: Vec<(String, String)> = real_levels(w).iter().map(|l| (l.name.clone(), l.col.clone())).collect();
    if r.chance(40) {
        let (lvl, col) = r.pick(&reals).clone();
        let name = "support".to_string();
        let mut line = format!("\ngrant {name} at {lvl}\n  via edge {name}_grants(grantee_id, {col})");
        if r.chance(60) {
            line.push_str("\n  active revoked_at");
        }
        if r.chance(50) {
            line.push_str(" expires expires_at");
        }
        if r.chance(40) {
            line.push_str(&format!(" confers {}", r.pick(&["select", "select, update", "select, insert, update, delete"])));
        }
        let idx = reals.iter().position(|(n, _)| *n == lvl).unwrap();
        if idx + 1 < reals.len() && r.chance(40) {
            let (sl, sc) = &reals[idx + 1];
            line.push_str(&format!("\n  scope {sl} on {sc} missing {}", r.pick(&["allow", "deny"])));
        }
        out.push_str(&line);
        out.push('\n');
        w.edge_grants.push((name, lvl));
    }
    if r.chance(15) {
        let (lvl, _) = r.pick(&reals).clone();
        out.push_str(&format!("grant overview at {lvl} via claim view_mode = \"all\" confers select\n"));
        w.claim_grants.push("overview".into());
    }
}

fn subjects(r: &mut Rng, w: &mut World, out: &mut String) {
    let reals: Vec<String> = real_levels(w).iter().map(|l| l.name.clone()).collect();
    out.push('\n');
    if r.chance(85) {
        let anchor = reals[0].clone();
        let roles = if w.has_store || r.chance(50) { "configurable staff" } else { "none" };
        out.push_str(&format!("subject admin {{ anchor {anchor}; reach descendants; identifies sub; roles {roles}; binds admin }}\n"));
        w.has_admin = true;
    }
    let leaf = reals.last().unwrap().clone();
    out.push_str(&format!(
        "subject customer {{ anchor {leaf}; reach self; identifies customer_id; roles {}; binds owner }}\n",
        if !w.has_member_vocab || r.chance(50) { "none" } else { "configurable member" }
    ));
    w.owner_anchor = leaf.clone();
    if let Some((g, _)) = w.edge_grants.first()
        && w.levels.first().is_some_and(|l| l.is_virtual)
    {
        out.push_str(&format!("subject operator {{ anchor platform; reach via grant {g}; identifies sub; roles none }}\n"));
        w.grant_reached = true;
    }
    if r.chance(12) {
        out.push_str(&format!(
            "subject visitor {{ anchor {leaf}; reach self; identifies visitor_id; roles none; transient{} }}\n",
            if r.chance(30) { " set" } else { "" }
        ));
        w.has_transient = true;
    }
}

fn term(r: &mut Rng, rels: &[(String, String)], w: &World, obj_leaf: &str) -> String {
    let mut opts: Vec<String> = rels.iter().filter(|(_, k)| k != "composition").map(|(n, _)| n.clone()).collect();
    opts.push("@session".into());
    opts.push("@scoped".into());
    if obj_leaf == w.owner_anchor {
        opts.push("@app_scope".into());
    }
    if w.has_admin {
        opts.push("@self(created_by)".into());
    }
    opts.push(format!("@kind(\"{}\")", r.pick(&["service", "admin", "staff"])));
    opts.push("@claim(\"tier\", \"gold\")".into());
    opts.push("mode visibility = \"public\"".into());
    if w.has_store && w.store_perms_col && !w.perms.is_empty() {
        opts.push(format!("@holds({})", r.pick(&w.perms)));
    }
    if let Some((g, _)) = w.edge_grants.first()
        && w.grant_reached
    {
        opts.push(format!("via grant {g}"));
    }
    r.pick(&opts).clone()
}

fn expr(r: &mut Rng, rels: &[(String, String)], w: &World, obj_leaf: &str) -> String {
    let a = term(r, rels, w, obj_leaf);
    match r.below(10) {
        0..=4 => a,
        5..=7 => format!("{a} + {}", term(r, rels, w, obj_leaf)),
        8 => format!("{a} and {}", term(r, rels, w, obj_leaf)),
        _ => format!("{a} and not {}", term(r, rels, w, obj_leaf)),
    }
}

fn object(r: &mut Rng, w: &mut World, out: &mut String, i: usize) {
    let reals: Vec<(String, String)> = real_levels(w).iter().map(|l| (l.name.clone(), l.col.clone())).collect();
    let leaf_idx = if r.chance(60) { reals.len() - 1 } else { r.below(reals.len()) };
    let leaf = reals[leaf_idx].0.clone();
    let name = if i < OBJECT_POOL.len() { OBJECT_POOL[i].to_string() } else { format!("obj{i}") };
    let table = format!("{name}s");
    let level_entity = leaf_idx > 0 && r.chance(15);
    let mut body = format!("\nobject {name} {{\n  table {table}\n");
    if level_entity {
        body.push_str(&format!("  level {leaf}\n"));
    }
    let scoped: Vec<String> = reals[..=leaf_idx]
        .iter()
        .enumerate()
        .map(|(j, (n, _))| if j < leaf_idx && r.chance(10) { format!("{n} wildcard") } else { n.clone() })
        .collect();
    body.push_str(&format!("  scoped {}\n", scoped.join(" > ")));
    let mut rels: Vec<(String, String)> = Vec::new();
    if leaf == w.owner_anchor && r.chance(75) {
        if r.chance(25) {
            body.push_str("  relation owner: customer via owner_id where owner_kind = \"customer\"\n");
        } else {
            body.push_str("  relation owner: customer via owner_id\n");
        }
        rels.push(("owner".into(), "column".into()));
    }
    if w.has_transient && leaf == w.owner_anchor && r.chance(30) {
        body.push_str("  relation guest: visitor via visitor_id\n");
        rels.push(("guest".into(), "column".into()));
    }
    if r.chance(3) && leaf == w.owner_anchor {
        body.push_str(&format!("  relation editor: customer via edge {name}_acl({name}_id, customer_id)\n"));
        rels.push(("editor".into(), "edge".into()));
    }
    if w.has_store && w.has_admin && r.chance(35) {
        body.push_str("  relation member: admin via role\n");
        rels.push(("member".into(), "role".into()));
    }
    if leaf == w.owner_anchor && r.chance(15) {
        let mat = if r.chance(40) { " materialized" } else { "" };
        body.push_str(&format!("  relation team: customer via group team_closure(group_id, member_id) edge team_edges(member_id, group_id) on team_id{mat}\n"));
        rels.push(("team".into(), "group".into()));
    }
    if leaf == w.owner_anchor && r.chance(12) {
        body.push_str("  relation lineage: customer via closure folder_closure(ancestor_id, descendant_id) base folders(id, parent_id) on folder_id\n");
        rels.push(("lineage".into(), "closure".into()));
    }
    if leaf == w.owner_anchor && r.chance(25) {
        let disc = if r.chance(30) { format!(" where kind = \"{name}\"") } else { String::new() };
        let tracked = if r.chance(30) { " tracked" } else { "" };
        let asynch = if !tracked.is_empty() && r.chance(30) { " async" } else { "" };
        body.push_str(&format!("  relation grantee: customer via grant {name}_grants(record_id, principal_kind, principal_id, access){disc}{tracked}{asynch}\n"));
        rels.push(("grantee".into(), "grant".into()));
    }
    if let Some((other, other_leaf)) = w.objects.last()
        && *other_leaf == leaf
        && r.chance(20)
    {
        body.push_str(&format!("  relation parent: {other} via object {other}->view on {other}_id\n"));
        rels.push(("parent".into(), "object".into()));
    }
    if r.chance(10) {
        body.push_str(&format!("  relation link: {name} via composition {name}_links(child_id, parent_id)\n"));
        rels.push(("link".into(), "composition".into()));
    }
    if w.has_store && w.has_admin && r.chance(10) {
        body.push_str(&format!("  relation scope_member: admin via memberin {leaf}(@sub, {})\n", reals[leaf_idx].1));
        rels.push(("scope_member".into(), "memberin".into()));
    }
    let n_ops = 1 + r.below(4);
    for (verb, op) in OPS.iter().take(n_ops) {
        let has_grantee = rels.iter().any(|(n, _)| n == "grantee");
        let mut e = expr(r, &rels, w, &leaf);
        if *op == "select" && has_grantee {
            let enumerable: Vec<&String> =
                rels.iter().filter(|(_, k)| matches!(k.as_str(), "column" | "grant" | "group" | "closure")).map(|(n, _)| n).collect();
            e = format!("{} + grantee:read", r.pick(&enumerable));
        }
        if rels.iter().any(|(n, k)| n == "link" && k == "composition") && r.chance(50) {
            e = format!("{e} + link");
        }
        let mut line = format!("  permission {verb} = {e} @rls maps {op}");
        if r.chance(8) {
            line.push_str(" guard status <> \"archived\"");
        }
        body.push_str(&line);
        body.push('\n');
    }
    if r.chance(15) && !w.perms.is_empty() {
        body.push_str(&format!("  permission publish = {} @pdp\n", r.pick(&w.perms)));
    }
    if r.chance(10) {
        body.push_str(&format!("  permission audit = {} @check\n", term(r, &rels, w, &leaf)));
    }
    if n_ops >= 2 && r.chance(15) {
        body.push_str("  require edit = @self(created_by)\n");
    }
    if r.chance(10) {
        body.push_str("  admit select = @claim(\"support\", \"on\")\n");
    }
    if r.chance(30) && body.contains("mode visibility") {
        body.push_str("  track visibility\n");
    }
    if r.chance(30) && body.contains("where owner_kind") {
        body.push_str("  track owner\n");
    }
    if r.chance(8) {
        body.push_str("  fields { owner staff }\n  field secret { read = owner write = owner column secret_col }\n");
    }
    body.push_str("}\n");
    out.push_str(&body);
    w.objects.push((name, leaf));
}

pub fn mutate(seed: u64, src: &str) -> String {
    let mut r = Rng::new(seed);
    let mut lines: Vec<String> = src.lines().map(String::from).collect();
    if lines.is_empty() {
        return src.to_string();
    }
    let idents: Vec<String> = src
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| t.len() > 2 && t.chars().next().is_some_and(|c| c.is_ascii_alphabetic()))
        .map(String::from)
        .collect();
    for _ in 0..1 + r.below(3) {
        let i = r.below(lines.len());
        match r.below(6) {
            0 => {
                lines.remove(i);
                if lines.is_empty() {
                    break;
                }
            }
            1 => {
                let l = lines[i].clone();
                lines.insert(i, l);
            }
            2 if i + 1 < lines.len() => lines.swap(i, i + 1),
            3 if !idents.is_empty() => {
                let from = r.pick(&idents).clone();
                let to = r.pick(&idents).clone();
                lines[i] = lines[i].replacen(&from, &to, 1);
            }
            4 => {
                let kw = *r.pick(&["wildcard", "materialized", "tracked", "virtual", "and not", "+", "@rls", "maps select", "{", "}"]);
                lines[i].push(' ');
                lines[i].push_str(kw);
            }
            _ => {
                if let Some(pos) = lines[i].rfind(' ') {
                    lines[i].truncate(pos);
                }
            }
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}
