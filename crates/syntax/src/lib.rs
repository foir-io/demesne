#![doc = "The demesne spec language: tokens, the parser and the AST it produces."]

pub mod ast;
mod error;
mod lexer;
mod parser;

pub use ast::*;
pub use error::{Error, Finding};
pub use parser::{parse, parse_bytes};
