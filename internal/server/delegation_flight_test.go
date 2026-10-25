//go:build duckdb_arrow

package server

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/config"
)

func TestDelegationFlight(t *testing.T) {
	addr, _ := startFlight(t)
	key, hash, _ := auth.NewAPIKey()
	lastServer.SetAuth(auth.New(&config.Users{APIKeys: []config.APIKey{{Name: "portal", KeyHash: hash, Roles: []string{"admin"}, Delegation: true}},
		Identities: []config.Identity{{Match: "portal:user:42", Roles: []string{"analyst"}}}}, 0))
	cl := flightClient(t, addr)
	run := func(ctx context.Context, sql string) ([][]string, error) {
		info, err := cl.Execute(ctx, sql)
		rows, _, err := fetch(ctx, cl, info, err)
		return rows, err
	}
	bearer := metadata.Pairs("authorization", "Bearer "+key)
	ctx := metadata.NewOutgoingContext(context.Background(), bearer)
	if _, err := run(ctx, "SELECT * FROM orders"); err == nil {
		t.Fatal("a delegating key needs an identity")
	}
	as := metadata.Join(bearer, metadata.Pairs(strings.ToLower(executionContextHeader), contextHeader(map[string]any{"subject": "portal:user:42"})))
	ctx = metadata.NewOutgoingContext(context.Background(), as)
	if rows, err := run(ctx, "SELECT id FROM orders"); err != nil || len(rows) == 0 {
		t.Fatalf("delegated flight query: %v %v", rows, err)
	}
	if _, err := run(ctx, "SELECT * FROM salaries"); err == nil {
		t.Fatal("must not inherit the key's roles over Flight")
	}
}
