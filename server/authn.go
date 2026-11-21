package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Authentication with per-user accounts (docs/multiuser-design.md). A session token
// carries the user id and the user's token version; the server loads the user (cached
// for a few seconds) on every request, so disabling a user, changing a role or
// resetting a password takes effect at once instead of when the token expires.

const (
	// sessionIdleTTL is how long a token lives without activity; the cookie is reissued
	// while the user is active, up to sessionAbsoluteTTL after login.
	sessionIdleTTL     = 12 * time.Hour
	sessionAbsoluteTTL = 7 * 24 * time.Hour
	// sessionRefreshAfter is how old a token must be before the server reissues it.
	sessionRefreshAfter = 30 * time.Minute

	// legacyAdminUsername is the single username older versions logged in with. The
	// migrated admin keeps it so nobody is locked out by the upgrade.
	legacyAdminUsername = "ARTEX"
	// minAccountPasswordLen applies to passwords set through the multi-user paths.
	minAccountPasswordLen = 12

	adminUsernameEnv = "ARTEX_ADMIN_USERNAME"
)

const (
	errPasswordChangeRequired = "You must change your password before continuing"
	errForbidden              = "Your role does not allow this action"
	errPasswordTooShortNew    = "The password must be at least 12 characters"
	errAccountNeedsDB         = "User accounts need the database"
)

// Principal is the authenticated caller of a request.
type Principal struct {
	UserID       int64
	Username     string
	Role         string
	MustChangePW bool
	// Legacy marks a token signed by an older single-password build (no user id). It is
	// honoured only while no account exists (fresh install, tests); it acts as admin.
	Legacy bool
}

type principalCtxKey struct{}

// principalFrom returns the caller attached by requireAuth (nil on public routes).
func principalFrom(r *http.Request) *Principal {
	p, _ := r.Context().Value(principalCtxKey{}).(*Principal)
	return p
}

type sessionClaims struct {
	jwt.RegisteredClaims
	UID int64 `json:"uid,omitempty"`
	Ver int   `json:"ver,omitempty"`
	Abs int64 `json:"abs,omitempty"` // absolute expiry (unix seconds) the sliding refresh never exceeds
}

// signJWT issues a legacy-format token (no user id). Kept for DB-less operation and
// tests; it is accepted only while no account exists.
func signJWT(key []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "ARTEX",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(sessionIdleTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(key)
}

// signUserJWT issues a session token for u. abs is the absolute expiry (zero = now +
// sessionAbsoluteTTL).
func signUserJWT(key []byte, u *db.User, abs time.Time) (string, error) {
	now := time.Now()
	if abs.IsZero() {
		abs = now.Add(sessionAbsoluteTTL)
	}
	exp := now.Add(sessionIdleTTL)
	if exp.After(abs) {
		exp = abs
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprint(u.ID),
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		UID: u.ID,
		Ver: u.TokenVersion,
		Abs: abs.Unix(),
	}).SignedString(key)
}

func parseSession(tok string, key []byte) (*sessionClaims, error) {
	c := &sessionClaims{}
	t, err := jwt.ParseWithClaims(tok, c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !t.Valid {
		return nil, errors.New("invalid token")
	}
	return c, nil
}

// userCacheTTL bounds how long a loaded user is trusted before a re-read, so changes
// made outside this process (reset-password.sh) apply within seconds. A var so tests
// can shorten it.
var userCacheTTL = 3 * time.Second

// ---- user lookup cache -----------------------------------------------------

type cachedUser struct {
	u   *db.User
	exp time.Time
}

func (s *Server) loadUserCached(id int64) (*db.User, error) {
	s.userMu.Lock()
	if c, ok := s.userCache[id]; ok && time.Now().Before(c.exp) {
		s.userMu.Unlock()
		return c.u, nil
	}
	s.userMu.Unlock()
	u, err := s.m.pg.GetUserByID(id)
	if err != nil {
		return nil, err
	}
	s.userMu.Lock()
	if s.userCache == nil {
		s.userCache = map[int64]cachedUser{}
	}
	s.userCache[id] = cachedUser{u: u, exp: time.Now().Add(userCacheTTL)}
	s.userMu.Unlock()
	return u, nil
}

// dropUser forgets a cached user so the next request re-reads the row.
func (s *Server) dropUser(id int64) {
	s.userMu.Lock()
	delete(s.userCache, id)
	s.userMu.Unlock()
}

// hasAnyAccount reports whether an account (or a legacy password awaiting migration)
// exists. A read error is returned, never folded into "no".
func (s *Server) hasAnyAccount() (bool, error) {
	if s.m == nil || s.m.pg == nil {
		return false, nil
	}
	n, err := s.m.pg.CountUsers()
	if err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}
	h, _, err := s.m.pg.GetSetting(authPassKey)
	if err != nil {
		return false, err
	}
	return h != "", nil
}

// migrateLegacyAdmin turns the single legacy admin password into the first admin
// account (username ARTEX). It is a no-op once any account exists and is safe to
// call concurrently. The legacy settings row is left in place for rollback.
func (s *Server) migrateLegacyAdmin() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	n, err := s.m.pg.CountUsers()
	if err != nil || n > 0 {
		return
	}
	h, _, err := s.m.pg.GetSetting(authPassKey)
	if err != nil || h == "" {
		return
	}
	if _, err := s.m.pg.CreateFirstAdmin(legacyAdminUsername, h, false); err == nil {
		log.Printf("[auth] migrated the single admin password to account %q (role admin); everyone logs in once again", legacyAdminUsername)
		s.securityEvent(nil, legacyAdminUsername, db.RoleAdmin, "migrate", "legacy password became the first admin", "")
	}
}

// authFailure says why authenticate refused a request.
type authFailure int

const (
	authOK authFailure = iota
	authNoToken
	authBadToken
)

// authenticate resolves a session token to the calling principal.
func (s *Server) authenticate(tok string) (*Principal, *sessionClaims, authFailure) {
	if tok == "" {
		return nil, nil, authNoToken
	}
	claims, err := parseSession(tok, s.jwtKey)
	if err != nil {
		return nil, nil, authBadToken
	}
	if claims.UID == 0 {
		// Legacy token: valid only while there are no accounts at all.
		if has, err := s.hasAnyAccount(); err != nil || has {
			return nil, nil, authBadToken
		}
		return &Principal{Username: legacyAdminUsername, Role: db.RoleAdmin, Legacy: true}, claims, authOK
	}
	if s.m == nil || s.m.pg == nil {
		return nil, nil, authBadToken
	}
	u, err := s.loadUserCached(claims.UID)
	if err != nil || u.Disabled || u.Locked(time.Now()) || u.TokenVersion != claims.Ver {
		return nil, nil, authBadToken
	}
	return &Principal{UserID: u.ID, Username: u.Username, Role: u.Role, MustChangePW: u.MustChangePW}, claims, authOK
}

// ---- middleware ------------------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// requireAuth authenticates the request, enforces the route's permission (default
// deny) and attaches the principal. lookup returns the registered pattern that will
// serve the request. /api/auth/* and /api/health authenticate themselves.
func (s *Server) requireAuth(h http.Handler, lookup func(*http.Request) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		pr, claims, fail := s.authenticate(tok)
		switch fail {
		case authNoToken:
			writeErr(w, 401, authErrUnauthorized)
			return
		case authBadToken:
			writeErr(w, 401, authErrTokenInvalid)
			return
		}
		if pr.MustChangePW {
			writeJSON(w, 403, map[string]any{"error": errPasswordChangeRequired, "code": "password_change_required"})
			return
		}
		if pattern := lookup(r); pattern != "" {
			perm, known := routePermission(pattern)
			if !known {
				log.Printf("[rbac] route %q has no permission entry; denied", pattern)
				writeErr(w, 403, errForbidden)
				return
			}
			if perm != permPublic && !roleHas(pr.Role, perm) {
				s.securityEvent(pr, pr.Username, pr.Role, "denied", r.Method+" "+r.URL.Path+" needs "+perm, clientKey(r))
				writeErr(w, 403, errForbidden)
				return
			}
		}
		s.maybeRefreshCookie(w, r, pr, claims, tok)
		r = r.WithContext(context.WithValue(r.Context(), principalCtxKey{}, pr))
		if isMutatingMethod(r.Method) {
			rec := &statusRecorder{ResponseWriter: w}
			h.ServeHTTP(rec, r)
			s.securityEvent(pr, pr.Username, pr.Role, "api", fmt.Sprintf("%s %s -> %d", r.Method, r.URL.Path, rec.status), clientKey(r))
			return
		}
		h.ServeHTTP(w, r)
	})
}

// maybeRefreshCookie slides the idle expiry for browser sessions: once the cookie's
// token is older than sessionRefreshAfter it is reissued (never past its absolute
// expiry). Bearer clients are not refreshed.
func (s *Server) maybeRefreshCookie(w http.ResponseWriter, r *http.Request, pr *Principal, c *sessionClaims, tok string) {
	if pr.Legacy || c == nil || c.IssuedAt == nil || time.Since(c.IssuedAt.Time) < sessionRefreshAfter {
		return
	}
	if ck, err := r.Cookie(sessionCookieName); err != nil || ck.Value != tok {
		return
	}
	abs := time.Unix(c.Abs, 0)
	if c.Abs == 0 || time.Now().After(abs) {
		return
	}
	u, err := s.loadUserCached(pr.UserID)
	if err != nil {
		return
	}
	if nt, err := signUserJWT(s.jwtKey, u, abs); err == nil {
		setSessionCookie(w, r, nt)
	}
}

// securityEvent records an event in security_log. Failure never breaks the request.
func (s *Server) securityEvent(pr *Principal, username, role, event, detail, ip string) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	var uid int64
	if pr != nil {
		uid = pr.UserID
	}
	if err := s.m.pg.InsertSecurityEvent(uid, username, role, event, detail, ip); err != nil {
		log.Printf("[auth] security log write failed: %v", err)
	}
}

// ---- password helpers ------------------------------------------------------

// checkAccountPassword validates a password set through the multi-user paths.
func checkAccountPassword(pw string) string {
	switch {
	case pw == "":
		return authErrPasswordEmpty
	case utf8.RuneCountInString(pw) < minAccountPasswordLen:
		return errPasswordTooShortNew
	case len(pw) > maxPasswordBytes:
		return authErrPasswordTooLong
	}
	return ""
}

// randomPassword returns a 20-character random password (letters and digits).
func randomPassword() (string, error) {
	b := make([]byte, 20)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return "", err
		}
		b[i] = keyChars[n.Int64()]
	}
	return string(b), nil
}

// dummyHash is compared against when a username does not exist, so an unknown user
// costs the same as a wrong password.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("artex-dummy-password"), bcrypt.DefaultCost)

// ---- bootstrap -------------------------------------------------------------

// bootstrapAuth runs once at startup: it migrates a legacy single password into the
// first admin account and, when there are no accounts at all, either creates the
// first admin from ARTEX_ADMIN_PASSWORD (headless deployments) or issues the setup
// token that /api/auth/init requires.
func (s *Server) bootstrapAuth() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	has, err := s.hasAnyAccount()
	if err != nil {
		// Unknown whether accounts exist: neither create one from the env var nor issue
		// a setup token now. authStatus re-reads on every request.
		log.Printf(logT("[auth] 비밀번호 상태를 읽지 못해 첫 실행 초기화를 건너뜁니다: %v"), err)
		return
	}
	if has {
		s.migrateLegacyAdmin()
		return
	}
	if pw := os.Getenv(adminPasswordEnv); pw != "" {
		name := strings.TrimSpace(os.Getenv(adminUsernameEnv))
		if name == "" {
			name = legacyAdminUsername
		}
		switch {
		case !db.ValidUsername(name):
			log.Printf("[auth] %s is not a valid username; ignoring %s", adminUsernameEnv, adminPasswordEnv)
		case utf8.RuneCountInString(pw) < minPasswordLen:
			log.Printf(logT("[auth] %s 가 %d자 미만이라 무시합니다. 설정 토큰 방식으로 초기화하세요"), adminPasswordEnv, minPasswordLen)
		case len(pw) > maxPasswordBytes:
			log.Printf(logT("[auth] %s 가 %d바이트를 넘어 무시합니다. 설정 토큰 방식으로 초기화하세요"), adminPasswordEnv, maxPasswordBytes)
		default:
			h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
			if err != nil {
				log.Printf(logT("[auth] %s 해시 생성 실패: %v"), adminPasswordEnv, err)
				break
			}
			if _, err := s.m.pg.CreateFirstAdmin(name, string(h), false); err == nil {
				log.Printf("[auth] created the first admin account %q from %s", name, adminPasswordEnv)
				return
			} else if errors.Is(err, db.ErrUsersExist) {
				return // another instance won the race
			} else {
				log.Printf(logT("[auth] %s 저장 실패: %v"), adminPasswordEnv, err)
			}
		}
	}
	s.currentSetupToken()
}

// ---- handlers --------------------------------------------------------------

// GET /api/auth/status — whether the first admin exists. While it does not, the
// /setup screen must present the console setup token.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	// A read failure must be a 503, not initialized:false: the frontend sends the user
	// to /setup on false, and wrapping a database outage as 200 would push them toward
	// the first-run path.
	s.migrateLegacyAdmin()
	has, err := s.hasAnyAccount()
	if err != nil {
		writeErr(w, 503, authErrDataSourceUnavailable)
		return
	}
	if !has {
		s.currentSetupToken()
	}
	writeJSON(w, 200, map[string]any{"initialized": has, "setup_token_required": !has})
}

// POST /api/auth/init — creates the first admin account; rejected once any account
// exists. It is reachable without a session (nothing exists to log in with yet), so
// it is gated by the setup token printed on the server console.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := clientKey(r)
	if !s.limiter().allow(key) {
		writeErr(w, 429, authErrTooManyAttempts)
		return
	}
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		SetupToken string `json:"setup_token"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	// Serialise the check-then-create so two concurrent first-run requests cannot both
	// pass the "no account yet" check (CreateFirstAdmin is also atomic in SQL).
	s.initMu.Lock()
	defer s.initMu.Unlock()
	s.migrateLegacyAdmin()
	has, err := s.hasAnyAccount()
	if err != nil {
		writeErr(w, 503, authErrDataSourceUnavailable)
		return
	}
	if has {
		writeErr(w, 403, authErrPasswordAlreadySet)
		return
	}
	if !s.checkSetupToken(req.SetupToken) {
		s.limiter().fail(key)
		log.Printf(logT("[auth] 초기 설정 거부: 설정 토큰 불일치 (client=%s)"), clientLogID(r))
		writeErr(w, 403, authErrSetupTokenInvalid)
		return
	}
	name := strings.TrimSpace(req.Username)
	if name == "" {
		name = legacyAdminUsername
	}
	if !db.ValidUsername(name) {
		writeErr(w, 400, db.ErrInvalidUsername.Error())
		return
	}
	if req.Password == "" {
		writeErr(w, 400, authErrPasswordEmpty)
		return
	}
	if utf8.RuneCountInString(req.Password) < minPasswordLen {
		writeErr(w, 400, authErrPasswordTooShort)
		return
	}
	if len(req.Password) > maxPasswordBytes {
		writeErr(w, 400, authErrPasswordTooLong)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, authErrPasswordHash)
		return
	}
	u, err := pg.CreateFirstAdmin(name, string(hash), false)
	if errors.Is(err, db.ErrUsersExist) {
		writeErr(w, 403, authErrPasswordAlreadySet)
		return
	}
	if err != nil {
		writeErr(w, 500, trMsg(authErrSaveFailedPrefix)+err.Error())
		return
	}
	s.clearSetupToken()
	s.limiter().reset(key)
	tok, err := signUserJWT(s.jwtKey, u, time.Time{})
	if err != nil {
		writeErr(w, 500, authErrTokenGen)
		return
	}
	log.Printf(logT("[auth] 관리자 비밀번호를 초기화했습니다 (client=%s)"), clientLogID(r))
	s.securityEvent(nil, u.Username, u.Role, "init", "first admin created", key)
	setSessionCookie(w, r, tok)
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/login — validates username and password and issues a session token.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	ip := clientKey(r)
	userKey := "u:" + strings.ToLower(strings.TrimSpace(req.Username))
	if !s.limiter().allow(ip) || !s.limiter().allow(userKey) {
		writeErr(w, 429, authErrTooManyAttempts)
		return
	}
	s.migrateLegacyAdmin()
	has, err := s.hasAnyAccount()
	if err != nil {
		writeErr(w, 503, authErrDataSourceUnavailable)
		return
	}
	if !has {
		writeErr(w, 403, authErrPasswordNotInit)
		return
	}
	u, err := pg.GetUserByName(req.Username)
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		writeErr(w, 503, authErrDataSourceUnavailable)
		return
	}
	// Always run one bcrypt comparison so an unknown user costs the same as a wrong
	// password (no username oracle, no timing shortcut).
	hash := dummyHash
	if u != nil {
		hash = []byte(u.PasswordHash)
	}
	pwErr := bcrypt.CompareHashAndPassword(hash, []byte(req.Password))
	if u == nil || pwErr != nil || u.Disabled || u.Locked(time.Now()) {
		s.limiter().fail(ip)
		s.limiter().fail(userKey)
		detail := "bad credentials"
		if u != nil {
			switch {
			case u.Disabled:
				detail = "account disabled"
			case u.Locked(time.Now()):
				detail = "account locked"
			case pwErr != nil:
				if locked, err := pg.RecordLoginFailure(u.ID); err == nil && locked {
					detail = "bad credentials; account now locked"
					s.dropUser(u.ID)
				}
			}
		}
		log.Printf(logT("[auth] 로그인 실패 (client=%s)"), clientLogID(r))
		name := strings.TrimSpace(req.Username)
		if len(name) > 64 {
			name = name[:64]
		}
		s.securityEvent(nil, name, "", "login_failed", detail, ip)
		writeErr(w, 401, authErrBadCredential)
		return
	}
	s.limiter().reset(ip)
	s.limiter().reset(userKey)
	_ = pg.RecordLoginSuccess(u.ID)
	s.dropUser(u.ID)
	tok, err := signUserJWT(s.jwtKey, u, time.Time{})
	if err != nil {
		writeErr(w, 500, authErrTokenGen)
		return
	}
	s.securityEvent(&Principal{UserID: u.ID}, u.Username, u.Role, "login", "ok", ip)
	setSessionCookie(w, r, tok)
	writeJSON(w, 200, map[string]any{"token": tok, "username": u.Username, "role": u.Role, "must_change_password": u.MustChangePW})
}

// POST /api/auth/change-password — changes the caller's own password. It needs a
// valid session (this route is exempt from requireAuth so a user who must change
// their password can reach it) and the current password. Every older session of the
// user ends (token version bump); the response carries a fresh token.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	pr, _, fail := s.authenticate(extractToken(r))
	if fail != authOK {
		writeErr(w, 401, authErrUnauthorized)
		return
	}
	if pr.Legacy {
		writeErr(w, 403, authErrPasswordNotInit)
		return
	}
	key := clientKey(r)
	if !s.limiter().allow(key) {
		writeErr(w, 429, authErrTooManyAttempts)
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, authErrNewPasswordEmpty)
		return
	}
	if msg := checkAccountPassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	u, err := pg.GetUserByID(pr.UserID)
	if err != nil {
		writeErr(w, 503, authErrDataSourceUnavailable)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.OldPassword)); err != nil {
		s.limiter().fail(key)
		log.Printf(logT("[auth] 비밀번호 변경 거부: 현재 비밀번호 불일치 (client=%s)"), clientLogID(r))
		writeErr(w, 401, authErrCurrentPasswordWrong)
		return
	}
	if req.NewPassword == req.OldPassword {
		writeErr(w, 400, "The new password must differ from the current one")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, authErrPasswordHash)
		return
	}
	nu, err := pg.SetUserPassword(u.ID, string(newHash), false)
	if err != nil {
		writeErr(w, 500, trMsg(authErrSaveFailedPrefix)+err.Error())
		return
	}
	s.dropUser(u.ID)
	s.limiter().reset(key)
	tok, err := signUserJWT(s.jwtKey, nu, time.Time{})
	if err != nil {
		writeErr(w, 500, authErrTokenGen)
		return
	}
	log.Printf(logT("[auth] 관리자 비밀번호를 변경했습니다. 기존 세션은 모두 무효화됩니다 (client=%s)"), clientLogID(r))
	s.securityEvent(pr, u.Username, u.Role, "password_change", "own password changed", key)
	setSessionCookie(w, r, tok)
	writeJSON(w, 200, map[string]any{"ok": true, "token": tok})
}

// GET /api/auth/session — tells the web UI who it is, since it cannot read the HttpOnly
// cookie. Always 200: "not signed in" is an ordinary answer.
func (s *Server) authSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	pr, _, fail := s.authenticate(extractToken(r))
	if fail != authOK {
		writeJSON(w, 200, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, 200, map[string]any{
		"authenticated":        true,
		"username":             pr.Username,
		"role":                 pr.Role,
		"permissions":          permissionsFor(pr.Role),
		"must_change_password": pr.MustChangePW,
	})
}
