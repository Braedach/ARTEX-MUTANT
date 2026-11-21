package db

import (
	"errors"
	"testing"
	"time"
)

// usersTestDB opens the shared test database with the users tables empty.
func usersTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`UPDATE tasks SET created_by=NULL`)
		_, _ = d.Exec(`DELETE FROM security_log`)
		_, _ = d.Exec(`DELETE FROM users`)
		d.Close()
	})
	_, _ = d.Exec(`UPDATE tasks SET created_by=NULL`)
	_, _ = d.Exec(`DELETE FROM users`)
	return d
}

func TestUserCreateLookupAndUniqueness(t *testing.T) {
	d := usersTestDB(t)
	u, err := d.CreateUser("Alice", "Alice A", "a@example.test", "hash", RoleOperator, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != RoleOperator || !u.MustChangePW || u.TokenVersion != 1 {
		t.Fatalf("unexpected row: %+v", u)
	}
	if _, err := d.CreateUser("alice", "", "", "h", RoleViewer, false, nil); !errors.Is(err, ErrUserExists) {
		t.Fatalf("usernames are case-insensitive unique, got %v", err)
	}
	got, err := d.GetUserByName("ALICE")
	if err != nil || got.ID != u.ID {
		t.Fatalf("case-insensitive lookup failed: %v %v", got, err)
	}
	for _, bad := range []string{"", "ab", "has space", "-lead", "x/y", "waytoolongusername_waytoolongusername"} {
		if _, err := d.CreateUser(bad, "", "", "h", RoleViewer, false, nil); !errors.Is(err, ErrInvalidUsername) {
			t.Fatalf("username %q should be rejected, got %v", bad, err)
		}
	}
	if _, err := d.CreateUser("bob12", "", "", "h", "root", false, nil); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("bad role must be rejected, got %v", err)
	}
	if _, err := d.GetUserByID(999999); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}
}

func TestCreateFirstAdminOnlyOnce(t *testing.T) {
	d := usersTestDB(t)
	if _, err := d.CreateFirstAdmin("ARTEX", "h1", false); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateFirstAdmin("other", "h2", false); !errors.Is(err, ErrUsersExist) {
		t.Fatalf("second first-admin must fail, got %v", err)
	}
	if n, _ := d.CountUsers(); n != 1 {
		t.Fatalf("want 1 user, got %d", n)
	}
}

func TestLastAdminCannotBeRemoved(t *testing.T) {
	d := usersTestDB(t)
	a1, _ := d.CreateUser("admin1", "", "", "h", RoleAdmin, false, nil)
	op, _ := d.CreateUser("oper1", "", "", "h", RoleOperator, false, nil)
	dis, role := true, RoleViewer
	if _, err := d.UpdateUserAccess(a1.ID, nil, &dis); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disabling the last admin must fail, got %v", err)
	}
	if _, err := d.UpdateUserAccess(a1.ID, &role, nil); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demoting the last admin must fail, got %v", err)
	}
	// A second admin makes the first removable.
	adm := RoleAdmin
	if _, err := d.UpdateUserAccess(op.ID, &adm, nil); err != nil {
		t.Fatal(err)
	}
	u, err := d.UpdateUserAccess(a1.ID, &role, nil)
	if err != nil || u.Role != RoleViewer {
		t.Fatalf("demote with another admin present: %v %v", u, err)
	}
	if u.TokenVersion != 2 {
		t.Fatalf("a role change must bump token_version, got %d", u.TokenVersion)
	}
	// ...and now the remaining admin is protected.
	if _, err := d.UpdateUserAccess(op.ID, nil, &dis); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("remaining admin protected, got %v", err)
	}
}

func TestPasswordResetBumpsVersionAndClearsLock(t *testing.T) {
	d := usersTestDB(t)
	u, _ := d.CreateUser("carol", "", "", "old", RoleViewer, false, nil)
	for i := 0; i < LoginMaxFailures-1; i++ {
		if locked, err := d.RecordLoginFailure(u.ID); err != nil || locked {
			t.Fatalf("failure %d: locked=%v err=%v", i+1, locked, err)
		}
	}
	locked, err := d.RecordLoginFailure(u.ID)
	if err != nil || !locked {
		t.Fatalf("the %dth failure must lock: locked=%v err=%v", LoginMaxFailures, locked, err)
	}
	cur, _ := d.GetUserByID(u.ID)
	if !cur.Locked(time.Now()) {
		t.Fatal("account should be locked")
	}
	nu, err := d.SetUserPassword(u.ID, "new", true)
	if err != nil {
		t.Fatal(err)
	}
	if nu.PasswordHash != "new" || !nu.MustChangePW || nu.TokenVersion != u.TokenVersion+1 || nu.Locked(time.Now()) {
		t.Fatalf("reset must set hash, force change, bump version and unlock: %+v", nu)
	}
	if err := d.RecordLoginSuccess(u.ID); err != nil {
		t.Fatal(err)
	}
	cur, _ = d.GetUserByID(u.ID)
	if cur.LastLoginAt == nil || cur.FailedLogins != 0 {
		t.Fatalf("login success must stamp and clear: %+v", cur)
	}
}

func TestSecurityLogRoundTrip(t *testing.T) {
	d := usersTestDB(t)
	u, _ := d.CreateUser("dave12", "", "", "h", RoleOperator, false, nil)
	_ = d.InsertSecurityEvent(u.ID, "dave12", RoleOperator, "login", "ok", "10.0.0.1")
	_ = d.InsertSecurityEvent(0, "ghost", "", "login_failed", "unknown user", "10.0.0.2")
	all, err := d.ListSecurityEvents(10, 0, "")
	if err != nil || len(all) != 2 || all[0].Event != "login_failed" || all[0].UserID != nil {
		t.Fatalf("newest-first listing wrong: %+v %v", all, err)
	}
	only, _ := d.ListSecurityEvents(10, 0, "login")
	if len(only) != 1 || only[0].UserID == nil {
		t.Fatalf("event filter wrong: %+v", only)
	}
}
