package server

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// setupTokenEnv pins the first-run setup token to a known value (headless /
	// automated deployments). When unset a random token is generated at startup and
	// printed to the server console only.
	setupTokenEnv = "ARTEX_SETUP_TOKEN"
	// adminPasswordEnv initialises the admin password at startup without the /setup
	// screen (headless deployments). Ignored once a password is set.
	adminPasswordEnv = "ARTEX_ADMIN_PASSWORD"
	// minPasswordLen mirrors the /setup screen's client-side rule, enforced server side.
	minPasswordLen = 8
	// maxPasswordBytes is bcrypt's hard limit: GenerateFromPassword errors past 72
	// bytes, so reject it up front with a clear message instead of a 500.
	maxPasswordBytes = 72
	setupTokenLen    = 32
)

// 인증 엔드포인트가 HTTP 응답으로 돌려주는 사용자 노출 문구다. 한국어 UI 에서 로그인·
// 비밀번호 설정이 실패하면 이 문구가 그대로 토스트로 뜨므로 한국어로 둔다. 자격 증명
// 오류 문구는 로그인 화면(web messages auth.login.errorCredential)과 표기를 맞췄다.
// token 은 기술 용어라 원문 그대로 둔다(로그·주석은 BRIEF 방침상 최하위라 손대지 않음).
const (
	authErrUnauthorized         = "인증이 필요합니다"
	authErrTokenInvalid         = "token 이 유효하지 않거나 만료되었습니다"
	authErrPasswordAlreadySet   = "비밀번호가 이미 설정되어 있습니다"
	authErrPasswordEmpty        = "비밀번호를 입력해 주세요"
	authErrPasswordTooShort     = "비밀번호는 최소 8자 이상이어야 합니다"
	authErrPasswordTooLong      = "비밀번호는 72바이트를 넘을 수 없습니다"
	authErrNewPasswordEmpty     = "새 비밀번호를 입력해 주세요"
	authErrPasswordHash         = "비밀번호 암호화에 실패했습니다"
	authErrSaveFailedPrefix     = "저장에 실패했습니다: "
	authErrTokenGen             = "token 생성에 실패했습니다"
	authErrBadRequest           = "요청 형식이 올바르지 않습니다"
	authErrPasswordNotInit      = "비밀번호가 초기화되지 않았습니다. 먼저 비밀번호를 설정해 주세요"
	authErrCurrentPasswordWrong = "현재 비밀번호가 올바르지 않습니다"
	authErrBadCredential        = "사용자 이름 또는 비밀번호가 올바르지 않습니다"
	authErrSetupTokenInvalid    = "설정 토큰이 올바르지 않습니다. 서버 콘솔 로그의 [auth] 줄에 출력된 설정 토큰을 입력해 주세요"
	authErrTooManyAttempts      = "실패한 시도가 너무 많습니다. 잠시 후 다시 시도해 주세요"
	// 비밀번호 관련 읽기가 실패했을 때 돌려주는 공통 문구다. 이 핸들러들은 "읽지 못함"을
	// "설정되지 않음"으로 취급하면 안 된다: 그렇게 취급하면 데이터베이스 장애 중에 초기화
	// 입구가 열려, 인증되지 않은 요청이 이미 설정된 관리자 비밀번호를 덮어쓸 수 있다.
	authErrDataSourceUnavailable = "데이터 소스를 일시적으로 사용할 수 없습니다. 잠시 후 다시 시도해 주세요"
)

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf(logT("[auth] JWT 키를 %s 에서 %s 로 이전(탐색 가능한 워크스페이스 밖으로 이동)"), legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	key, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate jwt key: %w", err)
	}
	if err := os.WriteFile(path, []byte(key), 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf(logT("[auth] 새 JWT 키를 %s 에 기록"), path)
	return []byte(key), nil
}

// randomToken returns n characters drawn from keyChars with crypto/rand.
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	for i := range buf {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return "", err
		}
		buf[i] = keyChars[v.Int64()]
	}
	return string(buf), nil
}

// currentSetupToken returns the setup token that gates /api/auth/init while no
// password is set, generating (and printing to the console) one on first use.
// ARTEX_SETUP_TOKEN, when set, is used verbatim and never logged.
func (s *Server) currentSetupToken() string {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.setupToken != "" {
		return s.setupToken
	}
	if v := strings.TrimSpace(os.Getenv(setupTokenEnv)); v != "" {
		s.setupToken = v
		log.Printf(logT("[auth] 관리자 비밀번호가 아직 설정되지 않았습니다. 설정 토큰은 환경 변수 %s 값입니다(로그에 출력하지 않음)"), setupTokenEnv)
		return s.setupToken
	}
	tok, err := randomToken(setupTokenLen)
	if err != nil {
		log.Printf(logT("[auth] 설정 토큰 생성 실패: %v"), err)
		return ""
	}
	s.setupToken = tok
	log.Printf(logT("[auth] 관리자 비밀번호가 아직 설정되지 않았습니다. 설정 토큰: %s"), tok)
	log.Print(logT("[auth] 첫 화면(/setup)의 \"설정 토큰\" 칸에 위 값을 입력하거나 POST /api/auth/init 본문의 setup_token 으로 보내십시오. 이 토큰은 네트워크로 전달되지 않으며 이 콘솔 로그에서만 확인할 수 있습니다"))
	return s.setupToken
}

// checkSetupToken compares the client-supplied token with the current one in
// constant time. An empty server-side token (generation failed) never matches.
func (s *Server) checkSetupToken(given string) bool {
	want := s.currentSetupToken()
	given = strings.TrimSpace(given)
	return want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(given)) == 1
}

func (s *Server) clearSetupToken() {
	s.authMu.Lock()
	s.setupToken = ""
	s.authMu.Unlock()
}

// limiter returns the per-client failed-attempt limiter shared by login and init.
func (s *Server) limiter() *authLimiter {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.loginLimiter == nil {
		s.loginLimiter = newAuthLimiter()
	}
	return s.loginLimiter
}

// authLimiter throttles repeated authentication failures per client address: the
// first few failures are free, after that each further failure doubles a cooldown
// during which the client gets 429. A success clears the client's record.
type authLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	clients map[string]*authAttempts
}

type authAttempts struct {
	fails int
	last  time.Time
	until time.Time
}

const (
	authFreeFailures    = 5
	authFailureWindow   = 10 * time.Minute
	authCooldownBase    = 30 * time.Second
	authCooldownMax     = 10 * time.Minute
	authLimiterMaxItems = 10000
)

func newAuthLimiter() *authLimiter {
	return &authLimiter{now: time.Now, clients: map[string]*authAttempts{}}
}

// allow reports whether the client may attempt authentication right now.
func (l *authLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.clients[key]
	if a == nil {
		return true
	}
	now := l.now()
	if now.Sub(a.last) > authFailureWindow {
		delete(l.clients, key)
		return true
	}
	return !now.Before(a.until)
}

// fail records a failed attempt and, past the free allowance, starts a cooldown.
func (l *authLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	a := l.clients[key]
	if a == nil || now.Sub(a.last) > authFailureWindow {
		if len(l.clients) >= authLimiterMaxItems {
			l.clients = map[string]*authAttempts{}
		}
		a = &authAttempts{}
		l.clients[key] = a
	}
	a.fails++
	a.last = now
	if extra := a.fails - authFreeFailures; extra >= 0 {
		cool := authCooldownBase << uint(extra)
		if cool > authCooldownMax || cool <= 0 {
			cool = authCooldownMax
		}
		a.until = now.Add(cool)
	}
}

func (l *authLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.clients, key)
	l.mu.Unlock()
}

// clientKey identifies the client for throttling and audit logs. The throttle key
// is the TCP peer only — X-Forwarded-For is client-controlled and would let an
// attacker dodge the limiter (or lock out others) by forging it. The forwarded
// value is still surfaced in the log line so an operator behind a reverse proxy
// can see the real origin.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func clientLogID(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		return r.RemoteAddr + " (X-Forwarded-For: " + xff + ")"
	}
	return r.RemoteAddr
}

// isLoopbackAddr reports whether a listen address only accepts local connections.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	if host == "" { // ":8787" / "0.0.0.0:8787" style — every interface
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// WarnIfExposed logs a warning when the admin password is still unset and the
// server accepts connections from other hosts: the setup token blocks a remote
// takeover, but the port should still not be reachable before setup is done.
func (s *Server) WarnIfExposed(addr string) {
	if s.m == nil || s.m.pg == nil || isLoopbackAddr(addr) {
		return
	}
	if has, err := s.hasAnyAccount(); err != nil || has {
		return
	}
	log.Printf(logT("[auth] 경고: 관리자 비밀번호가 아직 설정되지 않았는데 서버가 %q 에 바인딩되어 다른 호스트에서도 접속할 수 있습니다. 설정 토큰 없이는 초기화할 수 없지만, 초기 설정을 마칠 때까지 이 포트를 외부 네트워크에 노출하지 마십시오(기본값 127.0.0.1:8787)"), addr)
}

// extractToken reads the JWT from the Authorization: Bearer header (API clients) or
// the HttpOnly session cookie (the web UI). A token in the URL is NOT accepted: it
// would leak through access logs, proxies and the Referer header, and the cookie is
// sent automatically on same-origin EventSource streams, so the UI does not need it.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}
