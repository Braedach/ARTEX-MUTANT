package db

import (
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Multi-user accounts (docs/multiuser-design.md). Passwords are bcrypt hashes
// produced by the caller; nothing here ever sees a plaintext password.

// Roles, lowest to highest privilege. The permission sets live in the server package.
const (
	RoleViewer   = "viewer"
	RoleAnalyst  = "analyst"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// ValidRole reports whether r is one of the four roles.
func ValidRole(r string) bool {
	switch r {
	case RoleViewer, RoleAnalyst, RoleOperator, RoleAdmin:
		return true
	}
	return false
}

var (
	ErrUserExists      = errors.New("username already exists")
	ErrUserNotFound    = errors.New("user not found")
	ErrLastAdmin       = errors.New("cannot remove the last enabled admin")
	ErrInvalidUsername = errors.New("username must be 3-32 characters: letters, digits, '.', '_' or '-'")
	ErrInvalidRole     = errors.New("invalid role")
	ErrUsersExist      = errors.New("users already exist")
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$`)

// ValidUsername reports whether name is an acceptable username.
func ValidUsername(name string) bool { return usernameRE.MatchString(name) }

// Failed-login lockout policy.
const (
	LoginMaxFailures = 10
	LoginLockFor     = 15 * time.Minute
)

// adminGuardLock serialises changes that could leave the system without an
// enabled admin (pg_advisory_xact_lock key, arbitrary constant).
const adminGuardLock = 7240001

// User is one account row. PasswordHash is never serialised.
type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"display_name"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	Role         string     `json:"role"`
	Disabled     bool       `json:"disabled"`
	MustChangePW bool       `json:"must_change_password"`
	TokenVersion int        `json:"-"`
	FailedLogins int        `json:"-"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedBy    *int64     `json:"created_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Locked reports whether the account is inside a failed-login lockout at now.
func (u *User) Locked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

const userCols = `id, username, display_name, email, password_hash, role, disabled, must_change_pw,
 token_version, failed_logins, locked_until, last_login_at, created_by, created_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanUser(sc rowScanner) (*User, error) {
	var u User
	var lockedUntil, lastLogin sql.NullTime
	var createdBy sql.NullInt64
	if err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.PasswordHash, &u.Role, &u.Disabled,
		&u.MustChangePW, &u.TokenVersion, &u.FailedLogins, &lockedUntil, &lastLogin, &createdBy, &u.CreatedAt); err != nil {
		return nil, err
	}
	if lockedUntil.Valid {
		t := lockedUntil.Time
		u.LockedUntil = &t
	}
	if lastLogin.Valid {
		t := lastLogin.Time
		u.LastLoginAt = &t
	}
	if createdBy.Valid {
		v := createdBy.Int64
		u.CreatedBy = &v
	}
	return &u, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CountUsers returns the number of accounts (enabled or not).
func (d *DB) CountUsers() (int, error) {
	var n int
	err := d.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// GetUserByID returns the account, or ErrUserNotFound.
func (d *DB) GetUserByID(id int64) (*User, error) {
	u, err := scanUser(d.QueryRow(`SELECT `+userCols+` FROM users WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return u, err
}

// GetUserByName looks a user up case-insensitively, or returns ErrUserNotFound.
func (d *DB) GetUserByName(name string) (*User, error) {
	u, err := scanUser(d.QueryRow(`SELECT `+userCols+` FROM users WHERE lower(username)=lower($1)`, strings.TrimSpace(name)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return u, err
}

// ListUsers returns every account ordered by id.
func (d *DB) ListUsers() ([]*User, error) {
	rows, err := d.Query(`SELECT ` + userCols + ` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CreateUser inserts an account and returns it. The caller validates the password.
func (d *DB) CreateUser(username, displayName, email, passwordHash, role string, mustChange bool, createdBy *int64) (*User, error) {
	if !ValidUsername(username) {
		return nil, ErrInvalidUsername
	}
	if !ValidRole(role) {
		return nil, ErrInvalidRole
	}
	var by any
	if createdBy != nil {
		by = *createdBy
	}
	u, err := scanUser(d.QueryRow(`
INSERT INTO users(username, display_name, email, password_hash, role, must_change_pw, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+userCols,
		username, displayName, email, passwordHash, role, mustChange, by))
	if isUniqueViolation(err) {
		return nil, ErrUserExists
	}
	return u, err
}

// CreateFirstAdmin inserts the first admin only when no account exists yet, in one
// statement so two concurrent first-run requests cannot both win. It returns
// ErrUsersExist when an account is already present.
func (d *DB) CreateFirstAdmin(username, passwordHash string, mustChange bool) (*User, error) {
	u, err := scanUser(d.QueryRow(`
INSERT INTO users(username, password_hash, role, must_change_pw)
SELECT $1,$2,'admin',$3 WHERE NOT EXISTS (SELECT 1 FROM users)
RETURNING `+userCols, username, passwordHash, mustChange))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUsersExist
	}
	return u, err
}

// withAdminGuard runs fn in a transaction holding the admin-guard lock.
func (d *DB) withAdminGuard(fn func(tx *sql.Tx) error) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, adminGuardLock); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// otherEnabledAdmins counts enabled admins other than id.
func otherEnabledAdmins(tx *sql.Tx, id int64) (int, error) {
	var n int
	err := tx.QueryRow(`SELECT count(*) FROM users WHERE role='admin' AND NOT disabled AND id<>$1`, id).Scan(&n)
	return n, err
}

// UpdateUserAccess changes role and/or disabled state, refusing any change that
// would leave no enabled admin. nil leaves a field unchanged.
func (d *DB) UpdateUserAccess(id int64, role *string, disabled *bool) (*User, error) {
	if role != nil && !ValidRole(*role) {
		return nil, ErrInvalidRole
	}
	var out *User
	err := d.withAdminGuard(func(tx *sql.Tx) error {
		cur, err := scanUser(tx.QueryRow(`SELECT `+userCols+` FROM users WHERE id=$1 FOR UPDATE`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		if err != nil {
			return err
		}
		newRole, newDisabled := cur.Role, cur.Disabled
		if role != nil {
			newRole = *role
		}
		if disabled != nil {
			newDisabled = *disabled
		}
		wasEnabledAdmin := cur.Role == RoleAdmin && !cur.Disabled
		willBeEnabledAdmin := newRole == RoleAdmin && !newDisabled
		if wasEnabledAdmin && !willBeEnabledAdmin {
			n, err := otherEnabledAdmins(tx, id)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrLastAdmin
			}
		}
		// A disabled account's sessions must die at once: bump the token version too.
		bump := 0
		if newDisabled != cur.Disabled || newRole != cur.Role {
			bump = 1
		}
		out, err = scanUser(tx.QueryRow(`
UPDATE users SET role=$2, disabled=$3, token_version=token_version+$4 WHERE id=$1 RETURNING `+userCols,
			id, newRole, newDisabled, bump))
		return err
	})
	return out, err
}

// UpdateUserProfile changes the display name and email.
func (d *DB) UpdateUserProfile(id int64, displayName, email string) (*User, error) {
	u, err := scanUser(d.QueryRow(`UPDATE users SET display_name=$2, email=$3 WHERE id=$1 RETURNING `+userCols, id, displayName, email))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return u, err
}

// SetUserPassword stores a new bcrypt hash, ends every existing session of the
// user (token_version bump) and clears any lockout.
func (d *DB) SetUserPassword(id int64, passwordHash string, mustChange bool) (*User, error) {
	u, err := scanUser(d.QueryRow(`
UPDATE users SET password_hash=$2, must_change_pw=$3, token_version=token_version+1,
 failed_logins=0, locked_until=NULL WHERE id=$1 RETURNING `+userCols, id, passwordHash, mustChange))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return u, err
}

// RecordLoginSuccess stamps the last login and clears the failure counter.
func (d *DB) RecordLoginSuccess(id int64) error {
	_, err := d.Exec(`UPDATE users SET last_login_at=now(), failed_logins=0, locked_until=NULL WHERE id=$1`, id)
	return err
}

// RecordLoginFailure counts a failed login and starts a lockout once the limit is
// reached. It reports whether the account is now locked.
func (d *DB) RecordLoginFailure(id int64) (locked bool, err error) {
	err = d.QueryRow(`
UPDATE users SET
  failed_logins = CASE WHEN failed_logins+1 >= $2 THEN 0 ELSE failed_logins+1 END,
  locked_until  = CASE WHEN failed_logins+1 >= $2 THEN now() + make_interval(secs => $3) ELSE locked_until END
WHERE id=$1 RETURNING (locked_until IS NOT NULL AND locked_until > now())`,
		id, LoginMaxFailures, LoginLockFor.Seconds()).Scan(&locked)
	return locked, err
}

// SetTaskCreatedBy records which user created a task (best effort attribution).
func (d *DB) SetTaskCreatedBy(taskID, userID int64) error {
	_, err := d.Exec(`UPDATE tasks SET created_by=$2 WHERE id=$1`, taskID, userID)
	return err
}

// SecurityEvent is one security_log row.
type SecurityEvent struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	UserID   *int64    `json:"user_id,omitempty"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
	Event    string    `json:"event"`
	Detail   string    `json:"detail"`
	IP       string    `json:"ip"`
}

// InsertSecurityEvent appends one row. Callers treat failure as non-fatal.
func (d *DB) InsertSecurityEvent(userID int64, username, role, event, detail, ip string) error {
	var uid any
	if userID > 0 {
		uid = userID
	}
	_, err := d.Exec(`INSERT INTO security_log(user_id, username, role, event, detail, ip) VALUES ($1,$2,$3,$4,$5,$6)`,
		uid, username, role, event, detail, ip)
	return err
}

// ListSecurityEvents returns newest-first rows, optionally those older than beforeID.
func (d *DB) ListSecurityEvents(limit int, beforeID int64, event string) ([]SecurityEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.Query(`
SELECT id, ts, user_id, username, role, event, detail, ip FROM security_log
WHERE ($1::bigint = 0 OR id < $1) AND ($2 = '' OR event = $2)
ORDER BY id DESC LIMIT $3`, beforeID, event, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecurityEvent{}
	for rows.Next() {
		var e SecurityEvent
		var uid sql.NullInt64
		if err := rows.Scan(&e.ID, &e.TS, &uid, &e.Username, &e.Role, &e.Event, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		if uid.Valid {
			v := uid.Int64
			e.UserID = &v
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
