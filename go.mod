// Deprecated: demesne's Go engine is frozen at v0.93.1, and v1 and later are Rust. From Go, use v0.93.1; otherwise use the demesne CLI or @foir/demesne.
module github.com/foir-io/demesne

go 1.26.1

retract (
	v0.94.0 // Published in error.
	[v1.0.0, v1.999.999] // Rust releases, which carry no Go code.
)
