package db

import (
	"database/sql"
	"errors"
	"time"
)

// API tokens (docs/multiuser-design.md, phase 2). The caller generates the token and
// passes only its SHA-256; nothing here ever holds the token itself.

var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenRole     = errors.New("a token's role must be viewer, analyst or operator")
)

// ValidTokenRole reports whether r may be the role cap of a token. Admin is never allowed.
func ValidTokenRole(r string) bool {
	return r == RoleViewer || r == RoleAnalyst || r == RoleOperator
}

// APIToken is one token row. The hash is never serialised.
type APIToken struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	Username   string     `json:"username,omitempty"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Hash       []byte     `json:"-"`
	RoleCap    string     `json:"role_cap"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedBy  *int64     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Active reports whether the token can still authenticate at now.
func (t *APIToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && t.ExpiresAt.After(now)
}

const tokenCols = `t.id, t.user_id, COALESCE(u.username,''), t.name, t.prefix, t.token_hash, t.role_cap,
 t.expires_at, t.last_used_at, t.revoked_at, t.created_by, t.created_at`

func scanToken(sc rowScanner) (*APIToken, error) {
	var t APIToken
	var last, rev sql.NullTime
	var by sql.NullInt64
	if err := sc.Scan(&t.ID, &t.UserID, &t.Username, &t.Name, &t.Prefix, &t.Hash, &t.RoleCap,
		&t.ExpiresAt, &last, &rev, &by, &t.CreatedAt); err != nil {
		return nil, err
	}
	if last.Valid {
		v := last.Time
		t.LastUsedAt = &v
	}
	if rev.Valid {
		v := rev.Time
		t.RevokedAt = &v
	}
	if by.Valid {
		v := by.Int64
		t.CreatedBy = &v
	}
	return &t, nil
}

// CreateAPIToken stores a token for userID. prefix is the public lookup prefix and hash
// the SHA-256 of the full token.
func (d *DB) CreateAPIToken(userID int64, name, prefix string, hash []byte, roleCap string, expires time.Time, createdBy *int64) (*APIToken, error) {
	if !ValidTokenRole(roleCap) {
		return nil, ErrTokenRole
	}
	var by any
	if createdBy != nil {
		by = *createdBy
	}
	var id int64
	err := d.QueryRow(`
INSERT INTO api_tokens(user_id, name, prefix, token_hash, role_cap, expires_at, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`, userID, name, prefix, hash, roleCap, expires, by).Scan(&id)
	if err != nil {
		return nil, err
	}
	return d.GetAPIToken(id)
}

// GetAPIToken returns one token, or ErrTokenNotFound.
func (d *DB) GetAPIToken(id int64) (*APIToken, error) {
	t, err := scanToken(d.QueryRow(`SELECT `+tokenCols+` FROM api_tokens t LEFT JOIN users u ON u.id=t.user_id WHERE t.id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenNotFound
	}
	return t, err
}

// GetAPITokenByPrefix looks a token up by its public prefix, or returns ErrTokenNotFound.
func (d *DB) GetAPITokenByPrefix(prefix string) (*APIToken, error) {
	t, err := scanToken(d.QueryRow(`SELECT `+tokenCols+` FROM api_tokens t LEFT JOIN users u ON u.id=t.user_id WHERE t.prefix=$1`, prefix))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenNotFound
	}
	return t, err
}

// ListAPITokens returns tokens newest first; userID 0 lists every user's tokens.
func (d *DB) ListAPITokens(userID int64) ([]*APIToken, error) {
	rows, err := d.Query(`SELECT `+tokenCols+` FROM api_tokens t LEFT JOIN users u ON u.id=t.user_id
WHERE ($1::bigint = 0 OR t.user_id = $1) ORDER BY t.id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken marks a token revoked (idempotent) and returns it.
func (d *DB) RevokeAPIToken(id int64) (*APIToken, error) {
	res, err := d.Exec(`UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrTokenNotFound
	}
	return d.GetAPIToken(id)
}

// TouchAPIToken stamps last_used_at. Best effort.
func (d *DB) TouchAPIToken(id int64) error {
	_, err := d.Exec(`UPDATE api_tokens SET last_used_at = now() WHERE id=$1`, id)
	return err
}
