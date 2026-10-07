package engine

import "strings"

type tokKind int

const (
	tokWord   tokKind = iota // bare word, Text upper-cased in Up
	tokQuoted                // "quoted identifier"
	tokString                // 'string'
	tokPunct                 // single char
	tokOther
)

type token struct {
	kind tokKind
	text string // identifier text (unquoted) or punct char
	up   string // upper-cased text for bare words
	pos  int    // byte offset of the token start
}

// tokenize is a minimal SQL lexer: enough to find statement keywords and
// object names. It understands comments, strings and quoted identifiers so
// keywords inside them are never matched.
func tokenize(s string) []token {
	var out []token
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
				i = len(s)
			} else {
				i += end + 4
			}
		case c == '\'' || c == '"':
			start := i
			var b strings.Builder
			i++
			for i < len(s) {
				if s[i] == c {
					if i+1 < len(s) && s[i+1] == c {
						b.WriteByte(c)
						i += 2
						continue
					}
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			k := tokQuoted
			if c == '\'' {
				k = tokString
			}
			out = append(out, token{kind: k, text: b.String(), pos: start})
		case isWordByte(c):
			start := i
			for i < len(s) && (isWordByte(s[i]) || (s[i] >= '0' && s[i] <= '9') || s[i] == '$') {
				i++
			}
			w := s[start:i]
			out = append(out, token{kind: tokWord, text: w, up: strings.ToUpper(w), pos: start})
		case strings.IndexByte("().,;", c) >= 0:
			out = append(out, token{kind: tokPunct, text: string(c), pos: i})
			i++
		default:
			out = append(out, token{kind: tokOther, text: string(c), pos: i})
			i++
		}
	}
	return out
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
	c := &cursor{toks: tokenize(q)}
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
// COPY ... TO reads. ok is false when the statement shape is not understood.
func writeTargets(q string) (targets, reads [][]string, ok bool) {
	toks := tokenize(q)
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
			case "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "CREATE", "DROP", "ALTER", "COPY":
				start = i
			}
		}
		if start >= 0 {
			break
		}
	}
	if start < 0 {
		return nil, nil, false
	}
	c := &cursor{toks: toks, i: start}
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
		return one()
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
