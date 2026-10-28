#![doc = "The demesne spec language: tokens, the parser and the AST it produces."]
#![forbid(unsafe_code)]

mod ast;
mod error;
mod files;
mod lexer;
mod parser;

pub use ast::{
    Admit, ArgSrc, Builtin, ClaimsAccessor, ExportParameter, External, ExternalArg, FieldRule, FieldScopeEntry, FieldScopes, Gate, Grant, GrantScope, GrantUse,
    Guard, GuardOp, Implication, Level, Membership, Object, Perm, PermNode, PermissionExport, Pos, Preset, ProcEntry, Procedures, Relation, RelationKind, Repr,
    Require, RoleStore, Spec, Subject, Template, Term, TermKind, Topology, UngovEntry, Ungoverned, ViaClosure, ViaColumn, ViaComposition, ViaEdge, ViaGrant,
    ViaGroup, ViaMemberIn, ViaObject, Vocabulary,
};
pub use error::{Error, Finding};
pub use files::{SpecFiles, parse_files};
pub use parser::{MAX_NESTING, parse, parse_bytes};
