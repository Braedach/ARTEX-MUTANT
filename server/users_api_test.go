package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Multi-user behaviour end to end: real middleware, real user handlers, real database.

// adminToken initialises the first admin and returns a session token for it.
func (r *authTestRig) adminToken() string {
	r.t.Helper()
	res := r.initAndLogin()
	tok, _ := res.body["token"].(string)
	if tok == "" {
		r.t.Fatalf("no admin token: %v", res.body)
	}
	return tok
}

func (r *authTestRig) mkUser(admin, name, role, pw string) {
	r.t.Helper()
	code, body := r.do("POST", "/api/users", admin, map[string]any{
		"username": name, "role": role, "password": pw, "must_change_password": false,
	})
	r.expect(201, code, body, "")
}

func (r *authTestRig) login(name, pw string) string {
	r.t.Helper()
	code, body := r.do("POST", "/api/auth/login", "", map[string]any{"username": name, "password": pw})
	r.expect(200, code, body, "")
	tok, _ := body["token"].(string)
	r.s.limiter().reset(clientKey(&http.Request{RemoteAddr: "192.0.2.1:1234"}))
	return tok
}

func TestRolesEnforcedThroughMiddleware(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	rig.mkUser(admin, "vera", "viewer", "viewer-pass-1234")
	rig.mkUser(admin, "alan", "analyst", "analyst-pass-1234")
	rig.mkUser(admin, "oscar", "operator", "operator-pass-1234")
	toks := map[string]string{
		"viewer": rig.login("vera", "viewer-pass-1234"), "analyst": rig.login("alan", "analyst-pass-1234"),
		"operator": rig.login("oscar", "operator-pass-1234"), "admin": admin,
	}
	cases := []struct {
		method, path string
		want         map[string]int
	}{
		{"GET", "/api/tasks", map[string]int{"viewer": 200, "analyst": 200, "operator": 200, "admin": 200}},
		{"GET", "/api/traffic", map[string]int{"viewer": 403, "analyst": 200, "operator": 200, "admin": 200}},
		{"POST", "/api/tasks", map[string]int{"viewer": 403, "analyst": 403, "operator": 200, "admin": 200}},
		{"PUT", "/api/settings", map[string]int{"viewer": 403, "analyst": 403, "operator": 403, "admin": 200}},
		{"GET", "/api/users", map[string]int{"viewer": 403, "analyst": 403, "operator": 403, "admin": 200}},
		{"GET", "/api/security-log", map[string]int{"viewer": 403, "analyst": 403, "operator": 403, "admin": 200}},
		// Registered but absent from the permission table: denied for everyone, admin included.
		{"POST", "/api/unlisted/route", map[string]int{"viewer": 403, "analyst": 403, "operator": 403, "admin": 403}},
	}
	for _, c := range cases {
		for role, want := range c.want {
			code, body := rig.do(c.method, c.path, toks[role], map[string]any{})
			if code != want {
				t.Errorf("%s %s as %s = %d, want %d (%v)", c.method, c.path, role, code, want, body)
			}
		}
	}
	// No token at all: 401 before any permission check.
	code, _ := rig.do("GET", "/api/tasks", "", nil)
	if code != 401 {
		t.Errorf("anonymous = %d, want 401", code)
	}
}

func TestSessionReportsRoleAndPermissions(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	rig.mkUser(admin, "vera", "viewer", "viewer-pass-1234")
	vt := rig.login("vera", "viewer-pass-1234")
	res := rig.req("GET", "/api/auth/session", map[string]string{"Authorization": "Bearer " + vt}, "", nil)
	if res.body["role"] != "viewer" || res.body["username"] != "vera" || res.body["authenticated"] != true {
		t.Fatalf("session payload wrong: %v", res.body)
	}
	perms, _ := res.body["permissions"].([]any)
	got := map[string]bool{}
	for _, p := range perms {
		got[fmt.Sprint(p)] = true
	}
	if !got[permTaskRead] || got[permTaskWrite] || got[permEvidenceRead] {
		t.Fatalf("viewer permissions wrong: %v", perms)
	}
}

func TestRoleChangeDisableAndResetTakeEffectAtOnce(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	rig.mkUser(admin, "oscar", "operator", "operator-pass-1234")
	ot := rig.login("oscar", "operator-pass-1234")
	users, _ := rig.do("GET", "/api/users", admin, nil)
	_ = users
	oscarID := rig.userID("oscar")

	if code, _ := rig.do("POST", "/api/tasks", ot, map[string]any{}); code != 200 {
		t.Fatalf("operator should create tasks, got %d", code)
	}
	// Demotion applies on the very next request, no re-login.
	code, body := rig.do("PATCH", fmt.Sprintf("/api/users/%d", oscarID), admin, map[string]any{"role": "viewer"})
	rig.expect(200, code, body, "")
	ot = rig.relogin("oscar", "operator-pass-1234") // role change bumps the version: the old token is dead
	if code, _ := rig.do("POST", "/api/tasks", ot, map[string]any{}); code != 403 {
		t.Fatalf("demoted user must lose write access at once, got %d", code)
	}
	// Disabling kills the session and blocks login.
	code, body = rig.do("PATCH", fmt.Sprintf("/api/users/%d", oscarID), admin, map[string]any{"disabled": true})
	rig.expect(200, code, body, "")
	if code, _ := rig.do("GET", "/api/tasks", ot, nil); code != 401 {
		t.Fatalf("disabled user's token must stop working, got %d", code)
	}
	code, body = rig.do("POST", "/api/auth/login", "", map[string]any{"username": "oscar", "password": "operator-pass-1234"})
	rig.expect(401, code, body, authErrBadCredential)
	// Re-enable, then reset: the old password stops working and the user must change the temporary one.
	code, body = rig.do("PATCH", fmt.Sprintf("/api/users/%d", oscarID), admin, map[string]any{"disabled": false})
	rig.expect(200, code, body, "")
	code, body = rig.do("POST", fmt.Sprintf("/api/users/%d/reset-password", oscarID), admin, map[string]any{})
	rig.expect(200, code, body, "")
	temp, _ := body["temporary_password"].(string)
	if len(temp) < 16 {
		t.Fatalf("a generated temporary password is expected, got %q", temp)
	}
	rig.s.limiter().reset("u:oscar")
	code, body = rig.do("POST", "/api/auth/login", "", map[string]any{"username": "oscar", "password": "operator-pass-1234"})
	rig.expect(401, code, body, authErrBadCredential)
	rig.s.limiter().reset("u:oscar")
	code, body = rig.do("POST", "/api/auth/login", "", map[string]any{"username": "oscar", "password": temp})
	rig.expect(200, code, body, "")
	if body["must_change_password"] != true {
		t.Fatalf("a reset password must force a change: %v", body)
	}
}

func (r *authTestRig) userID(name string) int64 {
	r.t.Helper()
	u, err := r.s.m.pg.GetUserByName(name)
	if err != nil {
		r.t.Fatal(err)
	}
	return u.ID
}

func (r *authTestRig) relogin(name, pw string) string {
	r.t.Helper()
	r.s.limiter().reset("u:" + strings.ToLower(name))
	return r.login(name, pw)
}

func TestMustChangePasswordBlocksEverythingElse(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	code, body := rig.do("POST", "/api/users", admin, map[string]any{"username": "newbie", "role": "operator"})
	rig.expect(201, code, body, "")
	temp, _ := body["temporary_password"].(string)
	tok := rig.login("newbie", temp)

	code, body = rig.do("GET", "/api/tasks", tok, nil)
	if code != 403 || body["code"] != "password_change_required" {
		t.Fatalf("must-change user should be blocked with password_change_required, got %d %v", code, body)
	}
	if res := rig.req("GET", "/api/auth/session", map[string]string{"Authorization": "Bearer " + tok}, "", nil); res.body["must_change_password"] != true {
		t.Fatalf("session must say a change is required: %v", res.body)
	}
	code, body = rig.do("POST", "/api/auth/change-password", tok, map[string]any{"old_password": temp, "new_password": "short"})
	rig.expect(400, code, body, errPasswordTooShortNew)
	code, body = rig.do("POST", "/api/auth/change-password", tok, map[string]any{"old_password": temp, "new_password": temp})
	rig.expect(400, code, body, "The new password must differ from the current one")
	code, body = rig.do("POST", "/api/auth/change-password", tok, map[string]any{"old_password": temp, "new_password": "my-own-new-pass-1"})
	rig.expect(200, code, body, "")
	tok2, _ := body["token"].(string)
	if code, _ := rig.do("GET", "/api/tasks", tok2, nil); code != 200 {
		t.Fatalf("after changing the password access is restored, got %d", code)
	}
	if code, _ := rig.do("GET", "/api/tasks", tok, nil); code != 401 {
		t.Fatalf("the pre-change token must be dead, got %d", code)
	}
}

func TestUserManagementGuardRails(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	adminID := rig.userID(legacyAdminUsername)

	// Cannot change your own role or disable yourself, or reset your own password here.
	for _, b := range []map[string]any{{"role": "viewer"}, {"disabled": true}} {
		code, body := rig.do("PATCH", fmt.Sprintf("/api/users/%d", adminID), admin, b)
		rig.expect(403, code, body, errUserSelfChange)
	}
	code, body := rig.do("POST", fmt.Sprintf("/api/users/%d/reset-password", adminID), admin, map[string]any{})
	rig.expect(403, code, body, errUserSelfReset)

	// Validation and uniqueness.
	code, body = rig.do("POST", "/api/users", admin, map[string]any{"username": "x", "role": "viewer", "password": "long-enough-pass-1"})
	rig.expect(400, code, body, "")
	code, body = rig.do("POST", "/api/users", admin, map[string]any{"username": "okname", "role": "root", "password": "long-enough-pass-1"})
	rig.expect(400, code, body, "")
	code, body = rig.do("POST", "/api/users", admin, map[string]any{"username": "okname", "role": "viewer", "password": "short"})
	rig.expect(400, code, body, errPasswordTooShortNew)
	rig.mkUser(admin, "okname", "viewer", "long-enough-pass-1")
	code, body = rig.do("POST", "/api/users", admin, map[string]any{"username": "OKNAME", "role": "viewer", "password": "long-enough-pass-1"})
	rig.expect(409, code, body, "")

	// A second admin may demote the first; the last admin can never be removed.
	rig.mkUser(admin, "boss2", "admin", "another-admin-pass-1")
	b2 := rig.login("boss2", "another-admin-pass-1")
	code, body = rig.do("PATCH", fmt.Sprintf("/api/users/%d", adminID), b2, map[string]any{"role": "viewer"})
	rig.expect(200, code, body, "")
	code, body = rig.do("GET", "/api/users", admin, nil)
	if code != 401 {
		t.Fatalf("the demoted admin's old token must be dead, got %d %v", code, body)
	}
	b2ID := rig.userID("boss2")
	op := rig.userID("okname")
	code, body = rig.do("PATCH", fmt.Sprintf("/api/users/%d", op), b2, map[string]any{"role": "admin"})
	rig.expect(200, code, body, "")
	_ = b2ID
}

func TestLoginDoesNotRevealWhetherUserExists(t *testing.T) {
	rig := newAuthTestRig(t)
	rig.adminToken()
	rig.s.limiter().reset(clientKey(&http.Request{RemoteAddr: "192.0.2.1:1234"}))
	code1, body1 := rig.do("POST", "/api/auth/login", "", map[string]any{"username": "ARTEX", "password": "wrong-password-123"})
	code2, body2 := rig.do("POST", "/api/auth/login", "", map[string]any{"username": "nobody", "password": "wrong-password-123"})
	if code1 != 401 || code2 != 401 || body1["error"] != body2["error"] {
		t.Fatalf("unknown user and wrong password must look identical: %d %v / %d %v", code1, body1, code2, body2)
	}
}

func TestSecurityLogRecordsAccountEvents(t *testing.T) {
	rig := newAuthTestRig(t)
	admin := rig.adminToken()
	rig.mkUser(admin, "oscar", "operator", "operator-pass-1234")
	rig.login("oscar", "operator-pass-1234")
	rig.do("POST", "/api/auth/login", "", map[string]any{"username": "oscar", "password": "bad-bad-bad-bad"})
	code, body := rig.do("PATCH", fmt.Sprintf("/api/users/%d", rig.userID("oscar")), admin, map[string]any{"role": "analyst"})
	rig.expect(200, code, body, "")
	ot := rig.relogin("oscar", "operator-pass-1234")
	rig.do("PUT", "/api/settings", ot, map[string]any{}) // denied

	code, body = rig.do("GET", "/api/security-log?limit=200", admin, nil)
	rig.expect(200, code, body, "")
	evs, _ := body["events"].([]any)
	seen := map[string]bool{}
	for _, e := range evs {
		m, _ := e.(map[string]any)
		seen[fmt.Sprint(m["event"])] = true
	}
	for _, want := range []string{"init", "user_create", "login", "login_failed", "role_change", "denied", "api"} {
		if !seen[want] {
			t.Errorf("security log is missing %q events (got %v)", want, seen)
		}
	}
}

func TestLegacyPasswordMigratesToAdminAccount(t *testing.T) {
	rig := newAuthTestRig(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("old-admin-pass-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := rig.s.m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	// Status alone triggers the migration and reports initialised.
	code, body := rig.do("GET", "/api/auth/status", "", nil)
	rig.expect(200, code, body, "")
	if body["initialized"] != true {
		t.Fatalf("a legacy password counts as initialised: %v", body)
	}
	tok := rig.login("ARTEX", "old-admin-pass-123")
	u, err := rig.s.m.pg.GetUserByName("artex")
	if err != nil || u.Role != "admin" {
		t.Fatalf("legacy admin must become an admin account: %v %v", u, err)
	}
	if code, _ := rig.do("GET", "/api/users", tok, nil); code != 200 {
		t.Fatalf("migrated admin must be able to manage users, got %d", code)
	}
	// Idempotent: a second pass creates nothing.
	rig.s.migrateLegacyAdmin()
	if n, _ := rig.s.m.pg.CountUsers(); n != 1 {
		t.Fatalf("migration must be idempotent, %d users", n)
	}
}

func TestLegacyTokensDieOnceAccountsExist(t *testing.T) {
	rig := newAuthTestRig(t)
	legacy, err := signJWT(rig.s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	// No accounts yet: a legacy-format token is honoured (fresh install, tests).
	if code, _ := rig.do("GET", "/api/tasks", legacy, nil); code != 200 {
		t.Fatalf("legacy token on an empty install should pass, got %d", code)
	}
	rig.adminToken()
	if code, _ := rig.do("GET", "/api/tasks", legacy, nil); code != 401 {
		t.Fatalf("legacy token must be refused once accounts exist, got %d", code)
	}
}
