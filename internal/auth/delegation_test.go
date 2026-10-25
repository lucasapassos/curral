package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/lucasapassos/curral/internal/config"
)

func encode(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestDecodeExecutionContext(t *testing.T) {
	deep := `{"subject":"s","a":` + strings.Repeat(`{"a":`, 9) + `1` + strings.Repeat(`}`, 9) + `}`
	for raw, ok := range map[string]bool{
		encode(`{"subject":"portal:user:42","kind":"user","tenant":{"id":"t1"},"n":12345678901234567890}`): true,
		encode(`{"subject":"portal:page:7"}`): true,
		"":                                    false,
		"not base64!":                         false,
		base64.URLEncoding.EncodeToString([]byte(`{"subject":"ab"}`)):       false, // padded
		encode(`{"kind":"user"}`):                                           false,
		encode(`{"subject":""}`):                                            false,
		encode(`{"subject":" padded"}`):                                     false,
		encode(`{"subject":"a\nb"}`):                                        false,
		encode(`{"subject":42}`):                                            false,
		encode(`{"subject":"a","kind":3}`):                                  false,
		encode(`{"subject":"a","roles":["admin"]}`):                         false,
		encode(`{"subject":"a","groups":[]}`):                               false,
		encode(`{"subject":"a","actor":"x"}`):                               false,
		encode(`{"subject":"a"} {"subject":"b"}`):                           false,
		encode(`[{"subject":"a"}]`):                                         false,
		encode(`null`):                                                      false,
		encode(deep):                                                        false,
		encode(`{"subject":"` + strings.Repeat("x", 300) + `"}`):            false,
		encode(`{"subject":"a","pad":"` + strings.Repeat("x", 9000) + `"}`): false,
	} {
		c, err := DecodeExecutionContext(raw)
		if (err == nil) != ok {
			t.Errorf("%q: got %v, want ok=%v", raw, err, ok)
		}
		if err == nil && c.Subject == "" {
			t.Errorf("%q: empty subject", raw)
		}
	}
	c, _ := DecodeExecutionContext(encode(`{"subject":"s","n":12345678901234567890}`))
	if b, _ := c.MarshalJSON(); string(b) != `{"n":12345678901234567890,"subject":"s"}` {
		t.Fatalf("large numbers must survive: %s", b)
	}
}

func TestDelegate(t *testing.T) {
	_, hash, _ := NewAPIKey()
	a := New(&config.Users{
		APIKeys:    []config.APIKey{{Name: "portal", KeyHash: hash, Roles: []string{"admin"}, Delegation: true, Attributes: map[string]string{"tenant": "t1"}}},
		Identities: []config.Identity{{Match: "portal:user:42", Roles: []string{"analyst"}}},
	}, time.Minute)
	c, _ := DecodeExecutionContext(encode(`{"subject":"portal:user:42"}`))
	actor := &Principal{Name: "portal", Roles: []string{"admin"}, Method: MethodAPIKey, Delegation: true, Attributes: map[string]string{"tenant": "t1"}}
	p, err := a.Delegate(actor, c)
	if err != nil || p.Name != "portal:user:42" || p.Actor != "portal" || len(p.Roles) != 1 || p.Roles[0] != "analyst" || p.Attributes["tenant"] != "t1" {
		t.Fatalf("%+v %v", p, err)
	}
	for _, bad := range []*Principal{
		{Name: "portal", Method: MethodAPIKey},
		{Name: "alice", Method: MethodBasic, Delegation: true},
	} {
		if _, err := a.Delegate(bad, c); err == nil {
			t.Fatalf("%+v must not delegate", bad)
		}
	}
}
