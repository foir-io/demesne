#![doc = "The demesne model: topology, the analysis every emitter shares, structural validation, schema binding, and the runtime surfaces a spec compiles to."]

mod admission;
pub mod analysis;
pub mod conditional;
mod error;
pub mod pdp;
pub mod scaffold;
mod schema;
mod spec;
mod surfaces;
pub mod topology;
mod validate;
pub mod vocab;

pub use admission::{ClaimMatch, ClaimValue, ConditionalAdmission, ConditionalExt};
pub use error::Error;
pub use schema::{Column, ForeignKey, Nullability, Schema, TableCoverage, table_coverage, validate_against};
pub use spec::{Principal, ReachGrantRef, SpecExt};
pub use surfaces::SurfaceExt;
pub use validate::{Structure, validate_structure};
