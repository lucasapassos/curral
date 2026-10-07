package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// OIDCConfig configures bearer JWT validation against an OIDC provider.
type OIDCConfig struct {
	Issuer     string        // e.g. https://login.example.com/realms/main
	Audience   string        // required "aud" value
	UserClaim  string        // claim naming the user; default "sub"
	RolesClaim string        // claim with roles (string or list); dotted paths allowed, e.g. realm_access.roles
	Skew       time.Duration // clock skew tolerated for exp/nbf/iat
	HTTPClient *http.Client  // optional
	// RequireEmailVerified rejects tokens whose email_verified claim is not
	// true. Use it whenever users are identified by e-mail, or an account
	// with an unverified address could claim someone else's.
	RequireEmailVerified bool
	// HostedDomains, if set, only accepts tokens whose "hd" claim (Google
	// Workspace domain) is one of them.
	HostedDomains []string
}

// OIDC validates JWTs signed by the provider's keys. Keys come from the
// provider's JWKS, found through OIDC discovery and refreshed in the
// background.
type OIDC struct {
	cfg  OIDCConfig
	keys jwk.Set
}

// NewOIDC runs discovery and fetches the signing keys; it fails if either
// is unreachable, so a misconfigured provider stops startup.
func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDC, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("oidc: issuer and audience are required")
	}
	if cfg.UserClaim == "" {
		cfg.UserClaim = "sub"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	jwksURI, err := discover(ctx, cfg)
	if err != nil {
		return nil, err
	}
	cache, err := jwk.NewCache(ctx, httprc.NewClient(httprc.WithHTTPClient(cfg.HTTPClient)))
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	if err := cache.Register(ctx, jwksURI,
		jwk.WithMinInterval(5*time.Minute), jwk.WithMaxInterval(time.Hour),
	); err != nil {
		return nil, fmt.Errorf("oidc: fetching JWKS %s: %w", jwksURI, err)
	}
	set, err := cache.CachedSet(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	return &OIDC{cfg: cfg, keys: set}, nil
}

func discover(ctx context.Context, cfg OIDCConfig) (string, error) {
	url := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc discovery: %s: %s", url, resp.Status)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("oidc discovery: %w", err)
	}
	if doc.Issuer != cfg.Issuer {
		return "", fmt.Errorf("oidc discovery: issuer %q does not match configured %q", doc.Issuer, cfg.Issuer)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("oidc discovery: no jwks_uri")
	}
	return doc.JWKSURI, nil
}

// Authenticate validates a bearer JWT and maps its claims to a principal.
func (o *OIDC) Authenticate(token string) (*Principal, error) {
	tok, err := jwt.Parse([]byte(token),
		jwt.WithKeySet(o.keys, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(true),
		jwt.WithIssuer(o.cfg.Issuer),
		jwt.WithAudience(o.cfg.Audience),
		jwt.WithAcceptableSkew(o.cfg.Skew),
	)
	if err != nil {
		return nil, err
	}
	claims, err := allClaims(tok)
	if err != nil {
		return nil, err
	}
	if o.cfg.RequireEmailVerified {
		switch v := claims["email_verified"].(type) {
		case bool:
			if !v {
				return nil, errors.New("email not verified")
			}
		case string: // some providers send "true"
			if v != "true" {
				return nil, errors.New("email not verified")
			}
		default:
			return nil, errors.New("token has no email_verified claim")
		}
	}
	if len(o.cfg.HostedDomains) > 0 {
		hd, _ := claims["hd"].(string)
		if !slices.ContainsFunc(o.cfg.HostedDomains, func(d string) bool { return strings.EqualFold(d, hd) }) {
			return nil, fmt.Errorf("hosted domain %q not allowed", hd)
		}
	}
	name, _ := lookup(claims, o.cfg.UserClaim).(string)
	if name == "" {
		return nil, fmt.Errorf("token has no %q claim", o.cfg.UserClaim)
	}
	p := &Principal{Name: name, Method: MethodJWT, Roles: []string{}}
	if o.cfg.RolesClaim != "" {
		switch v := lookup(claims, o.cfg.RolesClaim).(type) {
		case string:
			p.Roles = strings.Fields(v) // e.g. a space-separated "scope"
		case []any:
			for _, r := range v {
				if s, ok := r.(string); ok {
					p.Roles = append(p.Roles, s)
				}
			}
		}
	}
	return p, nil
}

// allClaims returns the token's claims as a JSON-shaped map.
func allClaims(tok jwt.Token) (map[string]any, error) {
	b, err := json.Marshal(tok)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

// lookup follows a dotted path (realm_access.roles) through nested objects.
// A claim whose own name contains dots is matched first.
func lookup(m map[string]any, path string) any {
	if v, ok := m[path]; ok {
		return v
	}
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[part]
	}
	return cur
}
