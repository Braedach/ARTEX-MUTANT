package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
)

// User management (admin only; see rbac.go). Passwords are shown to the admin at most
// once, when the server generated them.

const (
	errUserSelfChange = "You cannot change your own role or disable your own account; ask another admin"
	errUserSelfReset  = "Use change-password to change your own password"
)

func userErrStatus(err error) (int, string) {
	switch {
	case errors.Is(err, db.ErrUserExists):
		return 409, err.Error()
	case errors.Is(err, db.ErrUserNotFound):
		return 404, err.Error()
	case errors.Is(err, db.ErrLastAdmin):
		return 409, err.Error()
	case errors.Is(err, db.ErrInvalidUsername), errors.Is(err, db.ErrInvalidRole):
		return 400, err.Error()
	}
	return 500, err.Error()
}

// GET /api/users
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	us, err := pg.ListUsers()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"users": us, "roles": roleOrder})
}

// POST /api/users
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		Role         string `json:"role"`
		DisplayName  string `json:"display_name"`
		Email        string `json:"email"`
		MustChangePW *bool  `json:"must_change_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !validRole(req.Role) {
		writeErr(w, 400, db.ErrInvalidRole.Error())
		return
	}
	generated := false
	if req.Password == "" {
		pw, err := randomPassword()
		if err != nil {
			writeErr(w, 500, authErrPasswordHash)
			return
		}
		req.Password, generated = pw, true
	} else if msg := checkAccountPassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	must := true
	if req.MustChangePW != nil {
		must = *req.MustChangePW
	}
	if generated {
		must = true
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, authErrPasswordHash)
		return
	}
	pr := principalFrom(r)
	var by *int64
	if pr != nil && pr.UserID > 0 {
		by = &pr.UserID
	}
	u, err := pg.CreateUser(req.Username, strings.TrimSpace(req.DisplayName), strings.TrimSpace(req.Email), string(hash), req.Role, must, by)
	if err != nil {
		code, msg := userErrStatus(err)
		writeErr(w, code, msg)
		return
	}
	s.securityEvent(pr, pr.Username, pr.Role, "user_create", "created "+u.Username+" as "+u.Role, clientKey(r))
	out := map[string]any{"user": u}
	if generated {
		out["temporary_password"] = req.Password
	}
	writeJSON(w, 201, out)
}

// PATCH /api/users/{id}
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	var req struct {
		Role        *string `json:"role"`
		Disabled    *bool   `json:"disabled"`
		DisplayName *string `json:"display_name"`
		Email       *string `json:"email"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	pr := principalFrom(r)
	if (req.Role != nil || req.Disabled != nil) && pr != nil && pr.UserID == id {
		writeErr(w, 403, errUserSelfChange)
		return
	}
	cur, err := pg.GetUserByID(id)
	if err != nil {
		code, msg := userErrStatus(err)
		writeErr(w, code, msg)
		return
	}
	u := cur
	if req.Role != nil || req.Disabled != nil {
		if u, err = pg.UpdateUserAccess(id, req.Role, req.Disabled); err != nil {
			code, msg := userErrStatus(err)
			writeErr(w, code, msg)
			return
		}
		if req.Role != nil && *req.Role != cur.Role {
			s.securityEvent(pr, pr.Username, pr.Role, "role_change", u.Username+": "+cur.Role+" -> "+u.Role, clientKey(r))
		}
		if req.Disabled != nil && *req.Disabled != cur.Disabled {
			ev := "user_enable"
			if *req.Disabled {
				ev = "user_disable"
			}
			s.securityEvent(pr, pr.Username, pr.Role, ev, u.Username, clientKey(r))
		}
	}
	if req.DisplayName != nil || req.Email != nil {
		dn, em := u.DisplayName, u.Email
		if req.DisplayName != nil {
			dn = strings.TrimSpace(*req.DisplayName)
		}
		if req.Email != nil {
			em = strings.TrimSpace(*req.Email)
		}
		if u, err = pg.UpdateUserProfile(id, dn, em); err != nil {
			code, msg := userErrStatus(err)
			writeErr(w, code, msg)
			return
		}
	}
	s.dropUser(id)
	writeJSON(w, 200, map[string]any{"user": u})
}

// POST /api/users/{id}/reset-password — sets a temporary password the user must
// change at next login, and ends all of the user's sessions.
func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	pr := principalFrom(r)
	if pr != nil && pr.UserID == id {
		writeErr(w, 403, errUserSelfReset)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	_ = decode(r, &req) // an empty body means "generate one"
	pw, generated := req.Password, false
	if pw == "" {
		var err error
		if pw, err = randomPassword(); err != nil {
			writeErr(w, 500, authErrPasswordHash)
			return
		}
		generated = true
	} else if msg := checkAccountPassword(pw); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, authErrPasswordHash)
		return
	}
	u, err := pg.SetUserPassword(id, string(hash), true)
	if err != nil {
		code, msg := userErrStatus(err)
		writeErr(w, code, msg)
		return
	}
	s.dropUser(id)
	s.securityEvent(pr, pr.Username, pr.Role, "password_reset", "reset password of "+u.Username, clientKey(r))
	out := map[string]any{"user": u}
	if generated {
		out["temporary_password"] = pw
	}
	writeJSON(w, 200, out)
}

// GET /api/security-log?limit=&before=&event=
func (s *Server) listSecurityLog(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	ev, err := pg.ListSecurityEvents(limit, before, q.Get("event"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"events": ev})
}
