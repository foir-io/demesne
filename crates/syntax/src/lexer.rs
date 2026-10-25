use crate::Error;
use demesne_gocompat::quote;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tok {
    Eof,
    Ident,
    PermKey,
    Proc,
    Str,
    LBrace,
    RBrace,
    LParen,
    RParen,
    Gt,
    Ge,
    Ne,
    Plus,
    Pipe,
    Colon,
    Arrow,
    At,
    Eq,
    Comma,
    Star,
}

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Tok::Eof => "EOF",
            Tok::Ident => "IDENT",
            Tok::PermKey => "PERMKEY",
            Tok::Proc => "PROC",
            Tok::Str => "STRING",
            Tok::LBrace => "{",
            Tok::RBrace => "}",
            Tok::LParen => "(",
            Tok::RParen => ")",
            Tok::Gt => ">",
            Tok::Ge => ">=",
            Tok::Ne => "<>",
            Tok::Plus => "+",
            Tok::Pipe => "|",
            Tok::Colon => ":",
            Tok::Arrow => "->",
            Tok::At => "@",
            Tok::Eq => "=",
            Tok::Comma => ",",
            Tok::Star => "*",
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Token {
    pub kind: Tok,
    pub lit: String,
    pub line: usize,
}

fn is_ident_start(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphabetic()
}

fn is_ident(c: u8) -> bool {
    is_ident_start(c) || c.is_ascii_digit()
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: usize,
}

pub(crate) fn lex(src: &[u8]) -> Result<Vec<Token>, Error> {
    let mut l = Lexer { src, pos: 0, line: 1 };
    let mut toks = Vec::new();
    loop {
        let t = l.next()?;
        let eof = t.kind == Tok::Eof;
        toks.push(t);
        if eof {
            return Ok(toks);
        }
    }
}

impl Lexer<'_> {
    fn peek_at(&self, off: usize) -> u8 {
        self.src.get(self.pos + off).copied().unwrap_or(0)
    }

    fn tok(&mut self, kind: Tok, lit: &str, line: usize, width: usize) -> Token {
        self.pos += width;
        Token { kind, lit: lit.to_string(), line }
    }

    fn next(&mut self) -> Result<Token, Error> {
        self.skip_trivia();
        let line = self.line;
        if self.pos >= self.src.len() {
            return Ok(Token { kind: Tok::Eof, lit: String::new(), line });
        }
        let c = self.src[self.pos];
        let t = match c {
            b'{' => self.tok(Tok::LBrace, "{", line, 1),
            b'}' => self.tok(Tok::RBrace, "}", line, 1),
            b'(' => self.tok(Tok::LParen, "(", line, 1),
            b')' => self.tok(Tok::RParen, ")", line, 1),
            b'+' => self.tok(Tok::Plus, "+", line, 1),
            b'|' => self.tok(Tok::Pipe, "|", line, 1),
            b'@' => self.tok(Tok::At, "@", line, 1),
            b'=' => self.tok(Tok::Eq, "=", line, 1),
            b',' => self.tok(Tok::Comma, ",", line, 1),
            b'*' => self.tok(Tok::Star, "*", line, 1),
            b':' => self.tok(Tok::Colon, ":", line, 1),
            b'>' => {
                if self.peek_at(1) == b'=' {
                    self.tok(Tok::Ge, ">=", line, 2)
                } else {
                    self.tok(Tok::Gt, ">", line, 1)
                }
            }
            b'-' => {
                if self.peek_at(1) == b'>' {
                    self.tok(Tok::Arrow, "->", line, 2)
                } else {
                    return Err(Error::at(line, "unexpected '-' (expected '->')"));
                }
            }
            b'<' => {
                if self.peek_at(1) == b'>' {
                    self.tok(Tok::Ne, "<>", line, 2)
                } else {
                    return Err(Error::at(line, "unexpected '<' (expected '<>')"));
                }
            }
            b'"' => return self.lex_string(),
            c if is_ident_start(c) => self.lex_run(),
            c => {
                return Err(Error::at(line, format!("unexpected character {}", quote(&char::from(c).to_string()))));
            }
        };
        Ok(t)
    }

    fn skip_trivia(&mut self) {
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            match c {
                b'\n' => {
                    self.line += 1;
                    self.pos += 1;
                }
                b' ' | b'\t' | b'\r' | b';' => self.pos += 1,
                b'/' if self.peek_at(1) == b'/' => self.skip_line(),
                b'#' => self.skip_line(),
                _ => return,
            }
        }
    }

    fn skip_line(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos] != b'\n' {
            self.pos += 1;
        }
    }

    fn lex_string(&mut self) -> Result<Token, Error> {
        let line = self.line;
        self.pos += 1;
        let mut b: Vec<u8> = Vec::new();
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            if c == b'"' {
                self.pos += 1;
                return string_token(b, line);
            }
            if c == b'\n' {
                break;
            }
            if c == b'\\' && self.peek_at(1) == b'"' {
                b.push(b'"');
                self.pos += 2;
                continue;
            }
            b.push(c);
            self.pos += 1;
        }
        Err(Error::at(line, "unterminated string"))
    }

    fn lex_run(&mut self) -> Token {
        let line = self.line;
        let mut b = String::new();
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            let joins = is_ident(c) || (matches!(c, b'.' | b'/' | b':') && is_ident(self.peek_at(1)));
            if !joins {
                break;
            }
            b.push(c as char);
            self.pos += 1;
        }
        if self.peek_at(0) == b':' && self.peek_at(1) == b'*' {
            b.push_str(":*");
            self.pos += 2;
        }
        if self.peek_at(0) == b'[' && self.peek_at(1) == b']' {
            b.push_str("[]");
            self.pos += 2;
        }
        let kind = if b.contains('/') {
            Tok::Proc
        } else if b.contains(':') {
            Tok::PermKey
        } else {
            Tok::Ident
        };
        Token { kind, lit: b, line }
    }
}

fn string_token(b: Vec<u8>, line: usize) -> Result<Token, Error> {
    let Ok(lit) = String::from_utf8(b) else {
        return Err(Error::at(line, "string literal is not valid UTF-8"));
    };
    Ok(Token { kind: Tok::Str, lit, line })
}
