use demesne_cli::{Files, Output, run_pure};
use std::collections::BTreeMap;

struct Mem(BTreeMap<String, Vec<u8>>);

impl Files for Mem {
    fn read(&self, path: &str) -> Result<Vec<u8>, String> {
        self.0.get(path).cloned().ok_or_else(|| format!("open {path}: no such file or directory"))
    }
}

fn spec(edit_suffix: &str) -> String {
    format!(
        r"
topology {{
  level org       col org_ref  claim org
  level workspace parent org col ws_ref claim ws
}}

subject member {{ anchor workspace reach self identifies member_ref roles none binds owner }}

object note {{
  table  notes
  pk     note_pk
  scoped org > workspace
  relation owner:   member via owner_ref
  relation grantee: member via grant note_acl(note_ref, grantee_kind, grantee_ref, perm)
  permission view = owner @rls maps select
  permission edit = owner + grantee:write @rls maps update{edit_suffix}
}}
"
    )
}

fn run(cmd: &str, src: &str) -> Output {
    let files = Mem(BTreeMap::from([("spec.demesne".to_string(), src.as_bytes().to_vec())]));
    run_pure(&[cmd.to_string(), "spec.demesne".to_string()], &files).expect("a pure command")
}

#[test]
fn a_blind_write_validates_and_warns_on_stderr() {
    let o = run("validate", &spec(" blind"));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.code, 0, "{stderr}");
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("ok: 1 objects"));
    assert!(stderr.starts_with("warning: spec.demesne: line 16: permission note.edit maps update, and its term `grantee:write`"), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
}

#[test]
fn emit_carries_the_warning_beside_its_output() {
    let o = run("emit", &spec(" blind"));
    assert_eq!(o.code, 0);
    assert!(String::from_utf8_lossy(&o.stdout).contains("CREATE POLICY notes_update"));
    assert!(String::from_utf8_lossy(&o.stderr).starts_with("warning: spec.demesne:"));
}

#[test]
fn an_unmarked_wider_write_fails_validation() {
    let o = run("validate", &spec(""));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.code, 1);
    assert_eq!(o.stdout, b"");
    assert!(stderr.starts_with("demesne: validate spec.demesne: line 16: permission note.edit maps update"), "{stderr}");
}
