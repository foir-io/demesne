#![doc = "Holds a release to the one before it. The tests compare the SQL this release emits, and the rows each rule admits, with the previous release's, which they build from crates.io. The crate is never published: crates.io can't hold two releases of one crate in a single package."]
#![forbid(unsafe_code)]
