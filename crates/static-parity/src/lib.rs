#![doc = "Every validating corpus spec compiled by build.rs into Rust tables through demesne-emit-rust's Builder, with a registry the tests compare against the compiler."]
#![forbid(unsafe_code)]

use demesne_runtime as rt;

#[derive(Debug, Clone, Copy)]
pub enum Item {
    Vocabulary(&'static str, &'static rt::Vocabulary),
    HoldsResolver(&'static str, &'static rt::HoldsResolver),
    RoleAssignment(&'static str, &'static rt::RoleAssignmentSurface),
    ExpandedPresets(&'static str, &'static [(&'static str, &'static [&'static str])]),
    Grant(&'static str, &'static rt::GrantSurface),
    ResourceAccess(&'static str, &'static rt::ResourceAccessSurface),
    ConditionalResourceAccess(&'static str, &'static rt::ResourceAccessSurface),
    PointCheck(&'static str, &'static str),
    AppSurface(&'static str, &'static rt::AppObjectSurface),
    Check(&'static str, &'static str, &'static str),
    Pdp(&'static str, &'static rt::Pdp),
    Session(&'static rt::Session),
    ClaimsContract(&'static [&'static str]),
    ClaimsContractEntries(&'static [rt::ClaimEntry]),
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub path: &'static str,
    pub items: Vec<Item>,
}

include!(concat!(env!("OUT_DIR"), "/index.rs"));
