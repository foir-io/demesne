use crate::{Surface, emit_rust};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Builder {
    spec: PathBuf,
    wanted: Vec<Surface>,
    file_name: String,
}

impl Builder {
    pub fn new(spec: impl AsRef<Path>) -> Self {
        Builder { spec: spec.as_ref().to_path_buf(), wanted: Vec::new(), file_name: "demesne.rs".into() }
    }

    pub fn surface(mut self, s: Surface) -> Self {
        if !self.wanted.contains(&s) {
            self.wanted.push(s);
        }
        self
    }

    pub fn vocabulary(self, name: &str) -> Self {
        self.surface(Surface::Vocabulary(name.into()))
    }

    pub fn holds_resolver(self, rolestore: &str) -> Self {
        self.surface(Surface::HoldsResolver(rolestore.into()))
    }

    pub fn role_assignment(self, rolestore: &str) -> Self {
        self.surface(Surface::RoleAssignment(rolestore.into()))
    }

    pub fn expanded_presets(self, rolestore: &str) -> Self {
        self.surface(Surface::ExpandedPresets(rolestore.into()))
    }

    pub fn grant(self, name: &str) -> Self {
        self.surface(Surface::Grant(name.into()))
    }

    pub fn resource_access(self, object: &str) -> Self {
        self.surface(Surface::ResourceAccess(object.into()))
    }

    pub fn conditional_resource_access(self, object: &str) -> Self {
        self.surface(Surface::ConditionalResourceAccess(object.into()))
    }

    pub fn point_check(self, object: &str) -> Self {
        self.surface(Surface::PointCheck(object.into()))
    }

    pub fn app_surface(self, object: &str) -> Self {
        self.surface(Surface::AppSurface(object.into()))
    }

    pub fn check(self, object: &str, verb: &str) -> Self {
        self.surface(Surface::Check(object.into(), verb.into()))
    }

    pub fn pdp(self, emit_site: &str) -> Self {
        self.surface(Surface::Pdp(emit_site.into()))
    }

    pub fn session(self) -> Self {
        self.surface(Surface::Session)
    }

    pub fn claims_contract(self) -> Self {
        self.surface(Surface::ClaimsContract)
    }

    pub fn claims_contract_entries(self) -> Self {
        self.surface(Surface::ClaimsContractEntries)
    }

    pub fn file_name(mut self, name: &str) -> Self {
        self.file_name = name.into();
        self
    }

    pub fn render(&self) -> Result<String, String> {
        let shown = self.spec.display();
        let src = std::fs::read(&self.spec).map_err(|e| format!("{shown}: {e}"))?;
        let spec = demesne_syntax::parse_bytes(&src).map_err(|e| format!("{shown}: {e}"))?;
        demesne_emit_sql::validate(&spec).map_err(|e| format!("{shown}: {e}"))?;
        emit_rust(&spec, &self.wanted).map_err(|e| format!("{shown}:\n{e}"))
    }

    pub fn generate(self) -> Result<PathBuf, String> {
        println!("cargo:rerun-if-changed={}", self.spec.display());
        let out_dir = std::env::var_os("OUT_DIR").ok_or("OUT_DIR is unset; call this from build.rs")?;
        let code = self.render()?;
        let path = Path::new(&out_dir).join(&self.file_name);
        std::fs::write(&path, code).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(path)
    }

    pub fn compile(self) -> PathBuf {
        match self.generate() {
            Ok(p) => p,
            Err(e) => panic!("demesne: {e}"),
        }
    }
}
