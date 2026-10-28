use crate::{Error, Surface, emit_rust};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Builder {
    specs: Vec<PathBuf>,
    wanted: Vec<Surface>,
    file_name: String,
}

impl Builder {
    pub fn new(spec: impl AsRef<Path>) -> Self {
        Builder { specs: vec![spec.as_ref().to_path_buf()], wanted: Vec::new(), file_name: "demesne.rs".into() }
    }

    /// Adds a file after the files given so far, for a spec written in several files.
    ///
    /// The files compile as one model: each may refer to what the files before it declare, and may `replace` a
    /// declaration of theirs. The surfaces are the whole spec's.
    #[must_use]
    pub fn spec(mut self, spec: impl AsRef<Path>) -> Self {
        self.specs.push(spec.as_ref().to_path_buf());
        self
    }

    #[must_use]
    pub fn surface(mut self, s: Surface) -> Self {
        if !self.wanted.contains(&s) {
            self.wanted.push(s);
        }
        self
    }

    #[must_use]
    pub fn vocabulary(self, name: &str) -> Self {
        self.surface(Surface::Vocabulary(name.into()))
    }

    #[must_use]
    pub fn holds_resolver(self, rolestore: &str) -> Self {
        self.surface(Surface::HoldsResolver(rolestore.into()))
    }

    #[must_use]
    pub fn role_assignment(self, rolestore: &str) -> Self {
        self.surface(Surface::RoleAssignment(rolestore.into()))
    }

    #[must_use]
    pub fn expanded_presets(self, rolestore: &str) -> Self {
        self.surface(Surface::ExpandedPresets(rolestore.into()))
    }

    #[must_use]
    pub fn grant(self, name: &str) -> Self {
        self.surface(Surface::Grant(name.into()))
    }

    #[must_use]
    pub fn resource_access(self, object: &str) -> Self {
        self.surface(Surface::ResourceAccess(object.into()))
    }

    #[must_use]
    pub fn conditional_resource_access(self, object: &str) -> Self {
        self.surface(Surface::ConditionalResourceAccess(object.into()))
    }

    #[must_use]
    pub fn point_check(self, object: &str) -> Self {
        self.surface(Surface::PointCheck(object.into()))
    }

    #[must_use]
    pub fn app_surface(self, object: &str) -> Self {
        self.surface(Surface::AppSurface(object.into()))
    }

    #[must_use]
    pub fn check(self, object: &str, verb: &str) -> Self {
        self.surface(Surface::Check(object.into(), verb.into()))
    }

    #[must_use]
    pub fn pdp(self, emit_site: &str) -> Self {
        self.surface(Surface::Pdp(emit_site.into()))
    }

    #[must_use]
    pub fn session(self) -> Self {
        self.surface(Surface::Session)
    }

    #[must_use]
    pub fn claims_contract(self) -> Self {
        self.surface(Surface::ClaimsContract)
    }

    #[must_use]
    pub fn claims_contract_entries(self) -> Self {
        self.surface(Surface::ClaimsContractEntries)
    }

    #[must_use]
    pub fn file_name(mut self, name: &str) -> Self {
        self.file_name = name.into();
        self
    }

    /// Reads, parses and validates the spec, and renders the requested surfaces as Rust source.
    ///
    /// # Errors
    ///
    /// The spec cannot be read, parsed or validated, or a requested surface cannot be built.
    pub fn render(&self) -> Result<String, Error> {
        let names: Vec<String> = self.specs.iter().map(|p| p.display().to_string()).collect();
        let texts =
            self.specs.iter().zip(&names).map(|(p, shown)| std::fs::read(p).map_err(|e| Error::io(format!("{shown}: {e}")))).collect::<Result<Vec<_>, _>>()?;
        if let ([shown], [src]) = (names.as_slice(), texts.as_slice()) {
            let spec = demesne_syntax::parse_bytes(src).map_err(|e| Error::spec(format!("{shown}: {e}")))?;
            demesne_emit_sql::validate(&spec).map_err(|e| Error::spec(format!("{shown}: {e}")))?;
            return emit_rust(&spec, &self.wanted).map_err(|e| Error::surface(format!("{shown}:\n{e}")));
        }
        let files =
            demesne_syntax::parse_files(names.iter().map(String::as_str).zip(texts.iter().map(Vec::as_slice))).map_err(|e| Error::spec(e.to_string()))?;
        demesne_emit_sql::validate_files(&files).map_err(|e| Error::spec(e.to_string()))?;
        emit_rust(files.spec(), &self.wanted).map_err(|e| Error::surface(format!("{}:\n{e}", names.join(", "))))
    }

    /// Renders the surfaces into `OUT_DIR` and tells cargo to rerun when the spec changes.
    ///
    /// # Errors
    ///
    /// `OUT_DIR` is unset, rendering fails, or the file cannot be written.
    #[expect(clippy::print_stdout, reason = "build scripts talk to cargo through `cargo:` lines on stdout")]
    pub fn generate(self) -> Result<PathBuf, Error> {
        for spec in &self.specs {
            println!("cargo:rerun-if-changed={}", spec.display());
        }
        let out_dir = std::env::var_os("OUT_DIR").ok_or_else(|| Error::io("OUT_DIR is unset; call this from build.rs"))?;
        let code = self.render()?;
        let path = Path::new(&out_dir).join(&self.file_name);
        std::fs::write(&path, code).map_err(|e| Error::io(format!("{}: {e}", path.display())))?;
        Ok(path)
    }

    /// Runs [`Self::generate`], failing the build with its error.
    ///
    /// # Panics
    ///
    /// When [`Self::generate`] fails, so the error stops the build script.
    #[expect(clippy::must_use_candidate, reason = "build scripts call compile for its side effect and seldom need the path")]
    pub fn compile(self) -> PathBuf {
        match self.generate() {
            Ok(p) => p,
            Err(e) => panic!("demesne: {e}"),
        }
    }
}
