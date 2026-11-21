package db

import (
	"errors"
	"testing"
	"time"
)

func TestAPITokenLifecycle(t *testing.T) {
	d := usersTestDB(t)
	defer func() { _, _ = d.Exec(`DELETE FROM api_tokens`) }()
	u, _ := d.CreateUser("claude", "", "", "h", RoleOperator, false, nil)
	exp := time.Now().Add(24 * time.Hour)
	tok, err := d.CreateAPIToken(u.ID, "scan monitor", "atk_abcd1234", []byte("hashbytes"), RoleOperator, exp, &u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Username != "claude" || !tok.Active(time.Now()) || tok.RoleCap != RoleOperator {
		t.Fatalf("unexpected token: %+v", tok)
	}
	if _, err := d.CreateAPIToken(u.ID, "x", "atk_other000", []byte("h"), RoleAdmin, exp, nil); !errors.Is(err, ErrTokenRole) {
		t.Fatalf("admin must never be a token role, got %v", err)
	}
	if _, err := d.CreateAPIToken(u.ID, "dup", "atk_abcd1234", []byte("h"), RoleViewer, exp, nil); err == nil {
		t.Fatal("prefixes are unique")
	}
	got, err := d.GetAPITokenByPrefix("atk_abcd1234")
	if err != nil || string(got.Hash) != "hashbytes" {
		t.Fatalf("lookup by prefix: %v %v", got, err)
	}
	if err := d.TouchAPIToken(tok.ID); err != nil {
		t.Fatal(err)
	}
	if g, _ := d.GetAPIToken(tok.ID); g.LastUsedAt == nil {
		t.Fatal("touch must stamp last_used_at")
	}
	rev, err := d.RevokeAPIToken(tok.ID)
	if err != nil || rev.RevokedAt == nil || rev.Active(time.Now()) {
		t.Fatalf("revoke: %v %v", rev, err)
	}
	if _, err := d.RevokeAPIToken(99999); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("revoking a missing token: %v", err)
	}
	expired, _ := d.CreateAPIToken(u.ID, "old", "atk_expired00", []byte("h"), RoleViewer, time.Now().Add(-time.Hour), nil)
	if expired.Active(time.Now()) {
		t.Fatal("an expired token is not active")
	}
	all, _ := d.ListAPITokens(0)
	mine, _ := d.ListAPITokens(u.ID)
	if len(all) != 2 || len(mine) != 2 {
		t.Fatalf("listing wrong: %d %d", len(all), len(mine))
	}
	// Deleting the user removes the tokens.
	_, _ = d.Exec(`DELETE FROM users WHERE id=$1`, u.ID)
	if rest, _ := d.ListAPITokens(0); len(rest) != 0 {
		t.Fatalf("tokens must go with the user, %d left", len(rest))
	}
}
