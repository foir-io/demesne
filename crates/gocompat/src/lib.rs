#![doc = "Byte-exact reproductions of the Go standard library behaviour demesne's output depends on: `strconv.Quote`, `sort.Slice`'s pdqsort, and `encoding/json`'s encoder."]

#[allow(clippy::unreadable_literal, reason = "generated from Go's strconv tables, which print the code points as plain integers")]
mod isprint;
pub mod json;
mod quote;
mod sort;

pub use quote::quote;
pub use sort::sort_slice;
mod naming;

pub use naming::{go_export, unexport};

pub fn fmt_slice<S: AsRef<str>>(xs: &[S]) -> String {
    let parts: Vec<&str> = xs.iter().map(std::convert::AsRef::as_ref).collect();
    format!("[{}]", parts.join(" "))
}

#[cfg(test)]
mod json_roundtrip {
    use crate::json::{marshal_indent, parse};

    #[test]
    fn parses_what_it_writes() {
        let src = "{\n  \"a\": [\n    1,\n    \"x\\u003c\\\"\"\n  ],\n  \"b\": {},\n  \"c\": null\n}";
        assert_eq!(marshal_indent(&parse(src).unwrap(), "", "  "), src);
    }
}
