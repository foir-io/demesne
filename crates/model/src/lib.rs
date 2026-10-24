#![doc = "The demesne model: topology, the analysis every emitter shares, structural validation, schema binding, and the runtime surfaces a spec compiles to."]

pub mod analysis;
pub mod conditional;
pub mod pdp;
pub mod schema;
pub mod surfaces;
pub mod topology;
pub mod validate;
pub mod vocab;

pub use analysis::{Principal, ReachGrantRef, SpecExt};
pub use conditional::{ConditionalAdmission, ConditionalExt};
pub use schema::{Column, ForeignKey, Schema, TableCoverage, table_coverage, validate_against};
pub use surfaces::SurfaceExt;
pub use validate::{Structure, validate_structure};
