package demesne

import (
	"fmt"
	"strings"
)

// Lexer for the Demesne spec grammar (RFC §8.2). The grammar is whitespace-
// insensitive; `;` is a cosmetic separator (skipped like whitespace), and both
// `//` and `#` start line comments.
//
// Compound tokens are the subtlety. `content:write` (PERMKEY) and
// `records.v1.RecordsService/CreateRecord` (PROC) must each lex as ONE token,
// while `relation owner: customer` must lex `owner` `:` `customer`. The rule:
// inside an identifier run, a `.` `/` `:` is consumed only when immediately
// followed by an identifier character (and `:*`, for the `self:*` macro);
// otherwise the run stops and the separator is its own token.

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tPermKey // content:write, records:write:product, self:*
	tProc    // svc.v1.Service/Method
	tString  // "…"
	tLBrace
	tRBrace
	tLParen
	tRParen
	tGT    // >
	tGE    // >=
	tNE    // <>
	tPlus  // +
	tPipe  // |
	tColon // : (standalone)
	tArrow // ->
	tAt    // @
	tEq    // =
	tComma // ,
	tStar  // *
)

func (k tokKind) String() string {
	switch k {
	case tEOF:
		return "EOF"
	case tIdent:
		return "IDENT"
	case tPermKey:
		return "PERMKEY"
	case tProc:
		return "PROC"
	case tString:
		return "STRING"
	case tLBrace:
		return "{"
	case tRBrace:
		return "}"
	case tLParen:
		return "("
	case tRParen:
		return ")"
	case tGT:
		return ">"
	case tGE:
		return ">="
	case tNE:
		return "<>"
	case tPlus:
		return "+"
	case tPipe:
		return "|"
	case tColon:
		return ":"
	case tArrow:
		return "->"
	case tAt:
		return "@"
	case tEq:
		return "="
	case tComma:
		return ","
	case tStar:
		return "*"
	}
	return "?"
}

type token struct {
	kind tokKind
	lit  string
	line int
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdent(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

type lexer struct {
	src  string
	pos  int
	line int
}

// lex tokenizes the whole source. Returns an error with a line number on an
// unexpected character or unterminated string.
func lex(src string) ([]token, error) {
	l := &lexer{src: src, line: 1}
	var toks []token
	for {
		t, err := l.next()
		if err != nil {
			return nil, err
		}
		toks = append(toks, t)
		if t.kind == tEOF {
			return toks, nil
		}
	}
}

func (l *lexer) peekAt(off int) byte {
	if l.pos+off >= len(l.src) {
		return 0
	}
	return l.src[l.pos+off]
}

func (l *lexer) next() (token, error) {
	l.skipTrivia()
	if l.pos >= len(l.src) {
		return token{kind: tEOF, line: l.line}, nil
	}
	c := l.src[l.pos]
	line := l.line

	switch c {
	case '{':
		l.pos++
		return token{tLBrace, "{", line}, nil
	case '}':
		l.pos++
		return token{tRBrace, "}", line}, nil
	case '(':
		l.pos++
		return token{tLParen, "(", line}, nil
	case ')':
		l.pos++
		return token{tRParen, ")", line}, nil
	case '+':
		l.pos++
		return token{tPlus, "+", line}, nil
	case '|':
		l.pos++
		return token{tPipe, "|", line}, nil
	case '@':
		l.pos++
		return token{tAt, "@", line}, nil
	case '=':
		l.pos++
		return token{tEq, "=", line}, nil
	case ',':
		l.pos++
		return token{tComma, ",", line}, nil
	case '*':
		l.pos++
		return token{tStar, "*", line}, nil
	case ':':
		l.pos++
		return token{tColon, ":", line}, nil
	case '>':
		l.pos++
		if l.peekAt(0) == '=' {
			l.pos++
			return token{tGE, ">=", line}, nil
		}
		return token{tGT, ">", line}, nil
	case '-':
		if l.peekAt(1) == '>' {
			l.pos += 2
			return token{tArrow, "->", line}, nil
		}
		return token{}, fmt.Errorf("line %d: unexpected '-' (expected '->')", line)
	case '<':
		if l.peekAt(1) == '>' {
			l.pos += 2
			return token{tNE, "<>", line}, nil
		}
		return token{}, fmt.Errorf("line %d: unexpected '<' (expected '<>')", line)
	case '"':
		return l.lexString()
	}

	if isIdentStart(c) {
		return l.lexRun(), nil
	}
	return token{}, fmt.Errorf("line %d: unexpected character %q", line, string(c))
}

func (l *lexer) skipTrivia() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r' || c == ';':
			l.pos++
		case c == '/' && l.peekAt(1) == '/':
			l.skipLine()
		case c == '#':
			l.skipLine()
		default:
			return
		}
	}
}

func (l *lexer) skipLine() {
	for l.pos < len(l.src) && l.src[l.pos] != '\n' {
		l.pos++
	}
}

func (l *lexer) lexString() (token, error) {
	line := l.line
	l.pos++ // opening quote
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '"' {
			l.pos++
			return token{tString, b.String(), line}, nil
		}
		if c == '\n' {
			break
		}
		if c == '\\' && l.peekAt(1) == '"' {
			b.WriteByte('"')
			l.pos += 2
			continue
		}
		b.WriteByte(c)
		l.pos++
	}
	return token{}, fmt.Errorf("line %d: unterminated string", line)
}

func (l *lexer) lexRun() token {
	line := l.line
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if isIdent(c) {
			b.WriteByte(c)
			l.pos++
			continue
		}
		if c == '.' || c == '/' {
			if isIdent(l.peekAt(1)) {
				b.WriteByte(c)
				l.pos++
				continue
			}
			break
		}
		if c == ':' {
			n := l.peekAt(1)
			if isIdent(n) {
				b.WriteByte(c)
				l.pos++
				continue
			}
			if n == '*' {
				b.WriteString(":*")
				l.pos += 2
				break
			}
			break
		}
		break
	}
	s := b.String()
	kind := tIdent
	switch {
	case strings.ContainsRune(s, '/'):
		kind = tProc
	case strings.ContainsRune(s, ':'):
		kind = tPermKey
	}
	return token{kind, s, line}
}
