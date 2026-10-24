#![doc = "Byte-exact reproductions of the Go standard library behaviour demesne's output depends on: `strconv.Quote`, `sort.Slice`'s pdqsort, and `encoding/json`'s encoder."]

mod isprint;
pub mod json;
mod quote;
mod sort;

pub use quote::{is_print, quote};
pub use sort::sort_slice;
mod naming;

pub use naming::{go_export, unexport};

pub fn fmt_slice<S: AsRef<str>>(xs: &[S]) -> String {
    let parts: Vec<&str> = xs.iter().map(|x| x.as_ref()).collect();
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
