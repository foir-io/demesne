# demesne-gocompat

Go-compatible formatting helpers for demesne: `strconv.Quote`, `encoding/json` string escaping and `sort.Slice` tie order, reproduced exactly so the Rust compiler's output is byte-identical to the Go engine it replaces. The rest of demesne is idiomatic Rust; this crate keeps the compatibility shims in one place.

Part of [demesne](https://github.com/foir-io/demesne).
