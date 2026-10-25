#![doc = "The demesne model: topology, the analysis every emitter shares, structural validation, schema binding, and the runtime surfaces a spec compiles to."]

pub mod analysis;
pub mod conditional;
mod error;
pub mod pdp;
pub mod scaffold;
pub mod schema;
pub mod surfaces;
pub mod topology;
pub mod validate;
pub mod vocab;

pub use analysis::{Principal, ReachGrantRef, SpecExt};
pub use conditional::{ConditionalAdmission, ConditionalExt};
pub use error::Error;
pub use schema::{Column, ForeignKey, Schema, TableCoverage, table_coverage, validate_against};
pub use surfaces::SurfaceExt;
pub use validate::{Structure, validate_structure};
