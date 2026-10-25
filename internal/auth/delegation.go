package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
)

// ExecutionContext is the effective identity a delegating service asserts
// for one request. Beyond a subject and an optional kind its shape is the
// service's own: Curral keeps it as given and lets the policy judge it.
type ExecutionContext struct {
	Subject string
	Kind    string
	// Fields is the whole decoded object, subject and kind included. It is
	// what the policy sees as input.identity.
	Fields map[string]any
}

// MarshalJSON writes the context as it was received.
func (c *ExecutionContext) MarshalJSON() ([]byte, error) { return json.Marshal(c.Fields) }

const (
	maxContextBytes = 8192
	maxContextDepth = 8
	maxSubjectBytes = 256
)

// The service never asserts roles or anything that reads as a decision:
// roles come from the identities file, and the actor is the key itself.
var reservedFields = []string{"roles", "groups", "actor"}

var ErrExecutionIdentity = errors.New("invalid execution identity")

// DecodeExecutionContext reads unpadded base64url UTF-8 JSON holding a
// single object with a non-empty string "subject".
func DecodeExecutionContext(raw string) (*ExecutionContext, error) {
	if raw == "" || base64.RawURLEncoding.DecodedLen(len(raw)) > maxContextBytes {
		return nil, ErrExecutionIdentity
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, ErrExecutionIdentity
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var fields map[string]any
	if d.Decode(&fields) != nil || fields == nil {
		return nil, ErrExecutionIdentity
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrExecutionIdentity
	}
	if depth(fields) > maxContextDepth {
		return nil, ErrExecutionIdentity
	}
	for _, k := range reservedFields {
		if _, ok := fields[k]; ok {
			return nil, ErrExecutionIdentity
		}
	}
	subject, _ := fields["subject"].(string)
	if !validName(subject) {
		return nil, ErrExecutionIdentity
	}
	kind, isString := fields["kind"].(string)
	if _, ok := fields["kind"]; ok && (!isString || !validName(kind)) {
		return nil, ErrExecutionIdentity
	}
	return &ExecutionContext{Subject: subject, Kind: kind, Fields: fields}, nil
}

func validName(s string) bool {
	if s == "" || len(s) > maxSubjectBytes || strings.TrimSpace(s) != s {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

func depth(v any) int {
	n := 0
	switch v := v.(type) {
	case map[string]any:
		for _, e := range v {
			n = max(n, depth(e))
		}
	case []any:
		for _, e := range v {
			n = max(n, depth(e))
		}
	default:
		return 0
	}
	return n + 1
}

// Delegate returns the effective principal a delegating key asserts. The
// key's roles are dropped: the identity gets only what the identities file
// maps to its subject, and the policy sees the key as input.actor.
func (a *Authenticator) Delegate(actor *Principal, c *ExecutionContext) (*Principal, error) {
	if actor.Method != MethodAPIKey || !actor.Delegation {
		return nil, ErrExecutionIdentity
	}
	return a.MapIdentity(&Principal{Name: c.Subject, Method: actor.Method, Actor: actor.Name,
		Attributes: actor.Attributes, Identity: c}), nil
}
