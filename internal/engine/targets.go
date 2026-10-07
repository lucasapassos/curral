package engine

import (
	"slices"
	"strings"
)

type tokKind int

const (
	tokWord   tokKind = iota // bare word, Text upper-cased in Up
	tokQuoted                // "quoted identifier"
	tokString                // 'string'
	tokPunct                 // single char
	tokNumber                // numeric literal
	tokOther
)

type token struct {
	kind tokKind
	text string // identifier text (unquoted) or punct char
	up   string // upper-cased text for bare words
	pos  int    // byte offset of the token start
	end  int    // byte offset just past the token
}

// tokenize is a minimal SQL lexer: enough to find statement keywords and
// object names. It understands comments, strings and quoted identifiers so
// keywords inside them are never matched.
//
// ok is false when the input uses lexical constructs this lexer does not model
// exactly like DuckDB's parser (dollar-quoted strings, nested block comments,
// E” escape strings, unterminated literals). Those could make it see a
// different statement than DuckDB executes, so callers must fail closed.
func tokenize(s string) (out []token, ok bool) {
	ok = true
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return out, false
			}
			if strings.Contains(s[i+2:i+2+end], "/*") {
				return out, false // nested comment
			}
			i += end + 4
		case c == '$' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			// Positional parameter $1: not a literal.
			start := i
			for i++; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
			}
			out = append(out, token{kind: tokOther, text: s[start:i], pos: start, end: i})
		case c == '$' && dollarQuote(s[i:]):
			return out, false
		case c == '\'' || c == '"':
			if c == '\'' && len(out) > 0 {
				// E'...' strings honour backslash escapes.
				if prev := out[len(out)-1]; prev.kind == tokWord && prev.up == "E" && prev.pos+1 == i {
					return out, false
				}
			}
			start := i
			var b strings.Builder
			closed := false
			i++
			for i < len(s) {
				if s[i] == c {
					if i+1 < len(s) && s[i+1] == c {
						b.WriteByte(c)
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				b.WriteByte(s[i])
				i++
			}
			if !closed {
				return out, false
			}
			k := tokQuoted
			if c == '\'' {
				k = tokString
			}
			out = append(out, token{kind: k, text: b.String(), pos: start, end: i})
		case isWordByte(c):
			start := i
			for i < len(s) && (isWordByte(s[i]) || (s[i] >= '0' && s[i] <= '9') || s[i] == '$') {
				i++
			}
			w := s[start:i]
			out = append(out, token{kind: tokWord, text: w, up: strings.ToUpper(w), pos: start, end: i})
		case c >= '0' && c <= '9' || (c == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9'):
			start := i
			i = scanNumber(s, i)
			out = append(out, token{kind: tokNumber, text: s[start:i], pos: start, end: i})
		case strings.IndexByte("().,;", c) >= 0:
			out = append(out, token{kind: tokPunct, text: string(c), pos: i, end: i + 1})
			i++
		default:
			out = append(out, token{kind: tokOther, text: string(c), pos: i, end: i + 1})
			i++
		}
	}
	return out, ok
}

// scanNumber returns the end of the numeric literal starting at i:
// digits, an optional fraction, an optional exponent, and _ separators.
func scanNumber(s string, i int) int {
	digits := func() {
		for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '_') {
			i++
		}
	}
	if strings.HasPrefix(s[i:], "0x") || strings.HasPrefix(s[i:], "0X") {
		i += 2
		for i < len(s) && strings.IndexByte("0123456789abcdefABCDEF_", s[i]) >= 0 {
			i++
		}
		return i
	}
	digits()
	if i < len(s) && s[i] == '.' {
		i++
		digits()
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		j := i + 1
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++
		}
		if j < len(s) && s[j] >= '0' && s[j] <= '9' {
			i = j
			digits()
		}
	}
	return i
}

// RedactSQL replaces string and numeric literals with ? and drops comments,
// keeping the statement's shape for audit logs without the values (which may
// be personal data). ok is false when the SQL uses constructs the tokenizer
// cannot read safely; callers should then log only a hash.
func RedactSQL(q string) (string, bool) {
	toks, ok := tokenize(q)
	if !ok {
		return "", false
	}
	var b strings.Builder
	prev := 0
	for _, t := range toks {
		gap := q[prev:t.pos]
		if strings.TrimSpace(gap) != "" {
			gap = " " // a comment: drop it
		}
		b.WriteString(gap)
		switch t.kind {
		case tokString, tokNumber:
			b.WriteByte('?')
		default:
			b.WriteString(q[t.pos:t.end])
		}
		prev = t.end
	}
	return strings.TrimSpace(b.String()), true
}

// dollarQuote reports whether s starts a dollar-quoted string: $$ or $tag$.
// A plain $name parameter does not.
func dollarQuote(s string) bool {
	for j := 1; j < len(s); j++ {
		switch c := s[j]; {
		case c == '$':
			return true
		case isWordByte(c) || (j > 1 && c >= '0' && c <= '9'):
			continue
		default:
			return false
		}
	}
	return false
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

type cursor struct {
	toks []token
	i    int
}

func (c *cursor) peek() token {
	if c.i < len(c.toks) {
		return c.toks[c.i]
	}
	return token{kind: tokOther}
}

// accept consumes the next token if it is one of the given keywords.
func (c *cursor) accept(words ...string) bool {
	t := c.peek()
	if t.kind != tokWord {
		return false
	}
	for _, w := range words {
		if t.up == w {
			c.i++
			return true
		}
	}
	return false
}

// name reads a dotted identifier (1-3 parts).
func (c *cursor) name() ([]string, bool) {
	var parts []string
	for {
		t := c.peek()
		if t.kind != tokWord && t.kind != tokQuoted {
			return nil, false
		}
		parts = append(parts, t.text)
		c.i++
		if p := c.peek(); p.kind == tokPunct && p.text == "." {
			c.i++
			continue
		}
		break
	}
	if len(parts) > 3 {
		return nil, false
	}
	return parts, true
}

// stripExplain removes EXPLAIN [ANALYZE] [(options)] and reports whether
// ANALYZE (which executes the statement) was present.
func stripExplain(q string) (inner string, analyze, ok bool) {
	toks, lexOK := tokenize(q)
	if !lexOK {
		return "", false, false
	}
	c := &cursor{toks: toks}
	if !c.accept("EXPLAIN") {
		return "", false, false
	}
	if c.accept("ANALYZE", "ANALYSE") {
		analyze = true
	}
	if p := c.peek(); p.kind == tokPunct && p.text == "(" {
		depth := 0
		for ; c.i < len(c.toks); c.i++ {
			t := c.toks[c.i]
			if t.kind == tokWord && t.up == "ANALYZE" {
				analyze = true
			}
			if t.kind == tokPunct && t.text == "(" {
				depth++
			}
			if t.kind == tokPunct && t.text == ")" {
				depth--
				if depth == 0 {
					c.i++
					break
				}
			}
		}
	}
	if c.i >= len(c.toks) {
		return "", false, false
	}
	return q[c.toks[c.i].pos:], analyze, true
}

// secretMark tags a secret name so qualify renders it as "secret:<name>".
const secretMark = "\x00secret"

var objectKinds = []string{"TABLE", "VIEW", "SCHEMA", "SEQUENCE", "MACRO", "FUNCTION", "TYPE", "INDEX", "SECRET"}

// writeTargets finds the objects a DML/DDL statement writes, plus tables a
// COPY ... TO reads, and the statement verb it found. ok is false when the
// statement shape is not understood.
func writeTargets(q string) (verb string, targets, reads [][]string, ok bool) {
	toks, lexOK := tokenize(q)
	if !lexOK {
		return "", nil, nil, false
	}
	// The verb is the first statement keyword outside parentheses, which
	// skips over a WITH clause's CTE bodies.
	depth, start := 0, -1
	for i, t := range toks {
		if t.kind == tokPunct && t.text == "(" {
			depth++
		} else if t.kind == tokPunct && t.text == ")" {
			depth--
		} else if depth == 0 && t.kind == tokWord {
			switch t.up {
			case "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "CREATE", "DROP", "ALTER", "COPY", "COMMENT":
				start = i
			}
		}
		if start >= 0 {
			break
		}
	}
	if start < 0 {
		return "", nil, nil, false
	}
	verb = toks[start].up
	t, r, ok := parseTarget(&cursor{toks: toks, i: start})
	return verb, t, r, ok
}

func parseTarget(c *cursor) (targets, reads [][]string, ok bool) {
	one := func() ([][]string, [][]string, bool) {
		n, ok := c.name()
		if !ok {
			return nil, nil, false
		}
		return [][]string{n}, nil, true
	}

	switch c.peek().up {
	case "INSERT":
		c.i++
		if c.accept("OR") {
			c.accept("REPLACE", "IGNORE")
		}
		if !c.accept("INTO") {
			return nil, nil, false
		}
		return one()
	case "UPDATE":
		c.i++
		return one()
	case "DELETE":
		c.i++
		if !c.accept("FROM") {
			return nil, nil, false
		}
		return one()
	case "MERGE":
		c.i++
		if !c.accept("INTO") {
			return nil, nil, false
		}
		return one()
	case "TRUNCATE":
		c.i++
		c.accept("TABLE")
		return one()
	case "ALTER":
		c.i++
		if !c.accept("TABLE", "VIEW", "SEQUENCE") {
			return nil, nil, false
		}
		if c.accept("IF") && !c.accept("EXISTS") {
			return nil, nil, false
		}
		n, ok := c.name()
		if !ok {
			return nil, nil, false
		}
		targets = [][]string{n}
		// RENAME TO creates an object under the new name, in the same
		// catalog and schema. (RENAME COLUMN/CONSTRAINT do not.)
		if c.accept("RENAME") && c.accept("TO") {
			to, ok := c.name()
			if !ok || len(to) != 1 {
				return nil, nil, false
			}
			targets = append(targets, append(slices.Clone(n[:len(n)-1]), to[0]))
		}
		return targets, nil, true
	case "COMMENT":
		c.i++
		if !c.accept("ON") {
			return nil, nil, false
		}
		kind := c.peek().up
		if !c.accept("TABLE", "VIEW", "SEQUENCE", "MACRO", "COLUMN") {
			return nil, nil, false // e.g. INDEX: its table is not in the statement
		}
		n, ok := c.name()
		if !ok {
			return nil, nil, false
		}
		if kind == "COLUMN" {
			// [catalog.][schema.]table.column: the table is what changes.
			if len(n) < 2 {
				return nil, nil, false
			}
			n = n[:len(n)-1]
		}
		return [][]string{n}, nil, true
	case "CREATE":
		c.i++
		if c.accept("OR") && !c.accept("REPLACE") {
			return nil, nil, false
		}
		temp := c.accept("TEMP", "TEMPORARY")
		c.accept("PERSISTENT")
		c.accept("UNIQUE")
		kind := c.peek().up
		if !c.accept(objectKinds...) {
			return nil, nil, false
		}
		if c.accept("IF") && !(c.accept("NOT") && c.accept("EXISTS")) {
			return nil, nil, false
		}
		n, ok := c.name()
		if !ok {
			return nil, nil, false
		}
		switch kind {
		case "INDEX":
			// The index lives on its table; that is what gets written.
			if !c.accept("ON") {
				return nil, nil, false
			}
			return one()
		case "SECRET":
			return [][]string{{secretMark, n[len(n)-1]}}, nil, true
		case "SCHEMA":
			return [][]string{append(n, "*")}, nil, true
		}
		if temp && len(n) == 1 {
			n = []string{"temp", "main", n[0]}
		}
		return [][]string{n}, nil, true
	case "DROP":
		c.i++
		kind := c.peek().up
		if !c.accept(objectKinds...) {
			return nil, nil, false
		}
		if c.accept("IF") && !c.accept("EXISTS") {
			return nil, nil, false
		}
		for {
			n, ok := c.name()
			if !ok {
				return nil, nil, false
			}
			switch kind {
			case "SECRET":
				n = []string{secretMark, n[len(n)-1]}
			case "SCHEMA":
				n = append(n, "*")
			}
			targets = append(targets, n)
			if p := c.peek(); p.kind == tokPunct && p.text == "," {
				c.i++
				continue
			}
			return targets, nil, true
		}
	case "COPY":
		c.i++
		if p := c.peek(); p.kind == tokPunct && p.text == "(" {
			// COPY (query) TO ...: the query's reads come from the plan.
			return nil, nil, true
		}
		n, ok := c.name()
		if !ok {
			return nil, nil, false
		}
		if p := c.peek(); p.kind == tokPunct && p.text == "(" {
			for c.i < len(c.toks) && !(c.peek().kind == tokPunct && c.peek().text == ")") {
				c.i++
			}
			c.i++
		}
		switch {
		case c.accept("FROM"):
			return [][]string{n}, nil, true
		case c.accept("TO"):
			return nil, [][]string{n}, true
		}
	}
	return nil, nil, false
}
