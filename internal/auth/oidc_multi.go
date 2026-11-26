package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MultiOIDC routes bearer JWTs to one of several configured OIDC providers
// based on the token's unverified "iss" claim, then delegates full
// cryptographic verification to that single provider.
type MultiOIDC struct {
	providers map[string]*OIDC
}

var _ TokenAuthenticator = (*MultiOIDC)(nil)

// NewMultiOIDC initializes one OIDC authenticator per config. It rejects an
// empty list, missing issuers, or duplicate issuers.
func NewMultiOIDC(ctx context.Context, cfgs []OIDCConfig) (*MultiOIDC, error) {
	if len(cfgs) == 0 {
		return nil, errors.New("oidc: at least one provider is required")
	}
	seen := make(map[string]bool, len(cfgs))
	for _, cfg := range cfgs {
		if cfg.Issuer == "" {
			return nil, errors.New("oidc: issuer is required")
		}
		if seen[cfg.Issuer] {
			return nil, fmt.Errorf("oidc: duplicate issuer %q", cfg.Issuer)
		}
		seen[cfg.Issuer] = true
	}
	providers := make(map[string]*OIDC, len(cfgs))
	for _, cfg := range cfgs {
		o, err := NewOIDC(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("oidc provider %q: %w", cfg.Issuer, err)
		}
		providers[cfg.Issuer] = o
	}
	return &MultiOIDC{providers: providers}, nil
}

// Authenticate extracts the unverified "iss" claim strictly to select the
// matching registered provider, then delegates full verification to it.
func (m *MultiOIDC) Authenticate(token string) (*Principal, error) {
	iss, err := unverifiedIssuer(token)
	if err != nil {
		return nil, err
	}
	o, ok := m.providers[iss]
	if !ok {
		return nil, fmt.Errorf("oidc: unknown issuer %q", iss)
	}
	return o.Authenticate(token)
}

// unverifiedIssuer decodes only the payload segment of a compact JWT to read
// its "iss" claim for provider routing. The returned issuer is untrusted until
// the selected provider verifies the token's signature and claims.
func unverifiedIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("oidc: malformed jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("oidc: malformed jwt payload: %w", err)
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("oidc: malformed jwt payload: %w", err)
	}
	if claims.Issuer == "" {
		return "", errors.New("oidc: token missing iss claim")
	}
	return claims.Issuer, nil
}
