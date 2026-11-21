package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// mkToken has the admin create a token for the named user and returns it with its id.
func (r *authTestRig) mkToken(admin, user, roleCap string) (string, int64) {
	r.t.Helper()
	code, body := r.do("POST", "/api/api-tokens", admin, map[string]any{
		"user_id": r.userID(user), "name": "test token", "role_cap": roleCap,
	})
	r.expect(201, code, body, "")
	tok, _ := body["token"].(string)
	info, _ := body["info"].(map[string]any)
	id, _ := info["id"].(float64)
	if !strings.HasPrefix(tok, apiTokenPrefix) || len(tok) != apiTokenLen {
		r.t.Fatalf("token has the wrong shape: %q", tok)
	}
	return tok, int64(id)
}

func TestAPITokenActsAsUserCappedAtRole(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	rig.mkUser(admin, "claude", "operator", "claude-account-pass-1")
	tok, _ := rig.mkToken(admin, "claude", "operator")

	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/tasks", 200}, {"POST", "/api/tasks", 200}, {"GET", "/api/traffic", 200},
		{"PUT", "/api/settings", 403}, {"GET", "/api/users", 403}, {"GET", "/api/api-tokens", 403},
		{"POST", "/api/api-tokens", 403}, {"GET", "/api/security-log", 403},
	} {
		if code, body := rig.do(c.method, c.path, tok, map[string]any{}); code != c.want {
			t.Errorf("%s %s with an operator token = %d, want %d (%v)", c.method, c.path, code, c.want, body)
		}
	}
	res := rig.req("GET", "/api/auth/session", map[string]string{"Authorization": "Bearer " + tok}, "", nil)
	if res.body["role"] != "operator" || res.body["username"] != "claude" {
		t.Fatalf("session via token wrong: %v", res.body)
	}
	// A token cannot change a password.
	code, body := rig.do("POST", "/api/auth/change-password", tok, map[string]any{"old_password": "claude-account-pass-1", "new_password": "a-brand-new-pass-123"})
	rig.expect(403, code, body, errForbidden)

	// The cap lowers an admin's token: an admin-owned operator token cannot administer.
	adminTok, _ := rig.mkToken(admin, legacyAdminUsername, "operator")
	if code, _ := rig.do("PUT", "/api/settings", adminTok, map[string]any{}); code != 403 {
		t.Errorf("an admin's operator-capped token must not reach admin routes, got %d", code)
	}
	if code, _ := rig.do("GET", "/api/users", adminTok, nil); code != 403 {
		t.Errorf("tokens never manage users, got %d", code)
	}
	// A viewer cap lowers an operator further.
	viewTok, _ := rig.mkToken(admin, "claude", "viewer")
	if code, _ := rig.do("POST", "/api/tasks", viewTok, map[string]any{}); code != 403 {
		t.Errorf("viewer-capped token must not write, got %d", code)
	}
}

func TestAPITokenCreationRules(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	rig.mkUser(admin, "claude", "operator", "claude-account-pass-1")
	uid := rig.userID("claude")
	for _, c := range []struct {
		body map[string]any
		want int
	}{
		{map[string]any{"user_id": uid, "name": "x", "role_cap": "admin"}, 400},
		{map[string]any{"user_id": uid, "name": "", "role_cap": "operator"}, 400},
		{map[string]any{"user_id": uid, "name": "x", "expires_in_days": 366}, 400},
		{map[string]any{"user_id": 999999, "name": "x"}, 404},
	} {
		if code, body := rig.do("POST", "/api/api-tokens", admin, c.body); code != c.want {
			t.Errorf("create %v = %d, want %d (%v)", c.body, code, c.want, body)
		}
	}
	// Defaults: operator cap, 90 days.
	code, body := rig.do("POST", "/api/api-tokens", admin, map[string]any{"user_id": uid, "name": "defaults"})
	rig.expect(201, code, body, "")
	info, _ := body["info"].(map[string]any)
	if info["role_cap"] != "operator" {
		t.Fatalf("default cap should be operator: %v", info)
	}
	exp, _ := time.Parse(time.RFC3339, fmt.Sprint(info["expires_at"]))
	if d := time.Until(exp); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("default expiry should be about 90 days, got %v", d)
	}
	// The listing never exposes the hash or the token.
	code, body = rig.do("GET", "/api/api-tokens", admin, nil)
	rig.expect(200, code, body, "")
	if s := fmt.Sprint(body); strings.Contains(s, "atk_") && strings.Contains(s, "token_hash") {
		t.Fatalf("listing leaks token material: %v", body)
	}
	// A disabled account cannot be given a token.
	dis := true
	if _, err := rig.s.m.pg.UpdateUserAccess(uid, nil, &dis); err != nil {
		t.Fatal(err)
	}
	code, body = rig.do("POST", "/api/api-tokens", admin, map[string]any{"user_id": uid, "name": "x"})
	rig.expect(409, code, body, "")
}

func TestAPITokenRevocationExpiryAndUserChangesApplyAtOnce(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	rig.mkUser(admin, "claude", "operator", "claude-account-pass-1")
	uid := rig.userID("claude")

	// Revocation.
	tok, id := rig.mkToken(admin, "claude", "operator")
	if code, _ := rig.do("GET", "/api/tasks", tok, nil); code != 200 {
		t.Fatalf("token should work, got %d", code)
	}
	if code, _ := rig.do("DELETE", fmt.Sprintf("/api/api-tokens/%d", id), admin, nil); code != 200 {
		t.Fatalf("revoke failed: %d", code)
	}
	if code, _ := rig.do("GET", "/api/tasks", tok, nil); code != 401 {
		t.Fatalf("a revoked token must stop at once, got %d", code)
	}
	if code, _ := rig.do("DELETE", "/api/api-tokens/999999", admin, nil); code != 404 {
		t.Fatalf("revoking a missing token should be 404, got %d", code)
	}

	// Expiry.
	full, prefix, hash, err := generateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.s.m.pg.CreateAPIToken(uid, "old", prefix, hash, db.RoleOperator, time.Now().Add(-time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	if code, _ := rig.do("GET", "/api/tasks", full, nil); code != 401 {
		t.Fatalf("an expired token must be refused, got %d", code)
	}

	// Demotion lowers the effective role at once, disabling kills the token.
	tok2, _ := rig.mkToken(admin, "claude", "operator")
	viewer := db.RoleViewer
	if code, body := rig.do("PATCH", fmt.Sprintf("/api/users/%d", uid), admin, map[string]any{"role": viewer}); code != 200 {
		t.Fatalf("demote: %d %v", code, body)
	}
	if code, _ := rig.do("POST", "/api/tasks", tok2, map[string]any{}); code != 403 {
		t.Fatalf("a demoted user's token must lose write access, got %d", code)
	}
	if code, _ := rig.do("PATCH", fmt.Sprintf("/api/users/%d", uid), admin, map[string]any{"disabled": true}); code != 200 {
		t.Fatalf("disable failed: %d", code)
	}
	if code, _ := rig.do("GET", "/api/tasks", tok2, nil); code != 401 {
		t.Fatalf("a disabled user's token must stop, got %d", code)
	}
}

func TestAPITokenAcceptedOnlyInAuthorizationHeader(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	rig.mkUser(admin, "claude", "operator", "claude-account-pass-1")
	tok, _ := rig.mkToken(admin, "claude", "operator")
	res := rig.req("GET", "/api/tasks", nil, tok, nil) // as the session cookie
	if res.code != 401 {
		t.Fatalf("a token in a cookie must be refused, got %d", res.code)
	}
	// Right prefix, wrong secret.
	forged := tok[:apiTokenPrefixLen] + strings.Repeat("x", apiTokenLen-apiTokenPrefixLen)
	if code, _ := rig.do("GET", "/api/tasks", forged, nil); code != 401 {
		t.Fatalf("a forged token must be refused, got %d", code)
	}
	// Repeated bad tokens from one client are throttled.
	var last int
	for i := 0; i < authFreeFailures+3; i++ {
		last, _ = rig.do("GET", "/api/tasks", forged, nil)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("brute-forcing tokens must be throttled, last status %d", last)
	}
}

func TestAPITokenUseIsLoggedAndStamped(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	rig.mkUser(admin, "claude", "operator", "claude-account-pass-1")
	tok, id := rig.mkToken(admin, "claude", "operator")
	rig.do("POST", "/api/tasks", tok, map[string]any{})

	deadline := time.Now().Add(3 * time.Second)
	for {
		t2, err := rig.s.m.pg.GetAPIToken(id)
		if err == nil && t2.LastUsedAt != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("last_used_at was never stamped")
		}
		time.Sleep(50 * time.Millisecond)
	}
	rig.do("DELETE", fmt.Sprintf("/api/api-tokens/%d", id), admin, nil)
	code, body := rig.do("GET", "/api/security-log?limit=200", admin, nil)
	rig.expect(200, code, body, "")
	text := fmt.Sprint(body)
	for _, want := range []string{"token_create", "token_revoke", "via token " + tok[:apiTokenPrefixLen]} {
		if !strings.Contains(text, want) {
			t.Errorf("security log missing %q", want)
		}
	}
	if strings.Contains(text, tok) {
		t.Fatal("the full token must never be written to the log")
	}
}
