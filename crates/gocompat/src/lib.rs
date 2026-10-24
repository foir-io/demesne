#![doc = "Byte-exact reproductions of the Go standard library behaviour demesne's output depends on: `strconv.Quote`, `sort.Slice`'s pdqsort, and `encoding/json`'s encoder."]

mod isprint;
pub mod json;
mod quote;
mod sort;

pub use quote::{is_print, quote};
pub use sort::sort_slice;
