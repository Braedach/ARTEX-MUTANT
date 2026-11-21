package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// API token management (admin only; see rbac.go). A token acts as one user, capped at a
// role that is never admin, and is shown to the admin exactly once, at creation. Tokens
// cannot manage users or tokens themselves (enforced in requireAuth).

const (
	defaultTokenDays = 90
	maxTokenDays     = 365
)

// GET /api/api-tokens?user_id=
func (s *Server) listAPITokens(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	uid, _ := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
	ts, err := pg.ListAPITokens(uid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"tokens": ts})
}

// POST /api/api-tokens {user_id, name, role_cap, expires_in_days}
func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		UserID        int64  `json:"user_id"`
		Name          string `json:"name"`
		RoleCap       string `json:"role_cap"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 80 {
		writeErr(w, 400, "A token needs a name of up to 80 characters")
		return
	}
	if req.RoleCap == "" {
		req.RoleCap = db.RoleOperator
	}
	if !db.ValidTokenRole(req.RoleCap) {
		writeErr(w, 400, db.ErrTokenRole.Error())
		return
	}
	if req.ExpiresInDays == 0 {
		req.ExpiresInDays = defaultTokenDays
	}
	if req.ExpiresInDays < 1 || req.ExpiresInDays > maxTokenDays {
		writeErr(w, 400, "Expiry must be between 1 and 365 days")
		return
	}
	u, err := pg.GetUserByID(req.UserID)
	if err != nil {
		code, msg := userErrStatus(err)
		writeErr(w, code, msg)
		return
	}
	if u.Disabled {
		writeErr(w, 409, "The account is disabled")
		return
	}
	token, prefix, hash, err := generateAPIToken()
	if err != nil {
		writeErr(w, 500, authErrTokenGen)
		return
	}
	pr := principalFrom(r)
	var by *int64
	if pr != nil && pr.UserID > 0 {
		by = &pr.UserID
	}
	t, err := pg.CreateAPIToken(u.ID, req.Name, prefix, hash, req.RoleCap,
		time.Now().Add(time.Duration(req.ExpiresInDays)*24*time.Hour), by)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.securityEvent(pr, pr.Username, pr.Role, "token_create",
		"token "+t.Prefix+" ("+t.Name+") for "+u.Username+", cap "+t.RoleCap, clientKey(r))
	writeJSON(w, 201, map[string]any{"token": token, "info": t})
}

// DELETE /api/api-tokens/{id} — revokes the token; it stops working at once.
func (s *Server) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	t, err := pg.RevokeAPIToken(id)
	if errors.Is(err, db.ErrTokenNotFound) {
		writeErr(w, 404, err.Error())
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.dropToken(t.Prefix)
	pr := principalFrom(r)
	s.securityEvent(pr, pr.Username, pr.Role, "token_revoke", "token "+t.Prefix+" ("+t.Name+") of "+t.Username, clientKey(r))
	writeJSON(w, 200, map[string]any{"info": t})
}
