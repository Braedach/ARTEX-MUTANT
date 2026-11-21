package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Session-cookie behaviour against a real database: the token is delivered as an
// HttpOnly, SameSite=Strict cookie, JavaScript never needs it, a URL token is not
// accepted, logout works from the server, and cross-origin writes are refused.

type sessionResp struct {
	code   int
	body   map[string]any
	cookie *http.Cookie
	header http.Header
}

func (r *authTestRig) req(method, path string, headers map[string]string, cookie string, body map[string]any) sessionResp {
	r.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	res := sessionResp{code: rec.Code, body: out, header: rec.Header()}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			res.cookie = c
		}
	}
	return res
}

// initAndLogin sets the admin password and returns a logged-in login response.
func (r *authTestRig) initAndLogin() sessionResp {
	r.t.Helper()
	r.s.bootstrapAuth()
	setup := r.s.currentSetupToken()
	res := r.req("POST", "/api/auth/init", nil, "", map[string]any{"password": "operator-pass-123", "setup_token": setup})
	if res.code != 200 {
		r.t.Fatalf("init failed: %d %v", res.code, res.body)
	}
	return r.req("POST", "/api/auth/login", nil, "", map[string]any{"username": "ARTEX", "password": "operator-pass-123"})
}

func TestSessionCookieAttributesOnLogin(t *testing.T) {
	rig := newAuthTestRig(t)
	res := rig.initAndLogin()
	if res.code != 200 {
		t.Fatalf("login: %d %v", res.code, res.body)
	}
	c := res.cookie
	if c == nil {
		t.Fatal("login did not set the session cookie")
	}
	if !c.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("SameSite = %v, want Strict", c.SameSite)
	}
	if c.Path != "/" {
		t.Fatalf("Path = %q", c.Path)
	}
	if want := int(sessionAbsoluteTTL / time.Second); c.MaxAge != want {
		t.Fatalf("MaxAge = %d, want %d", c.MaxAge, want)
	}
	if c.Secure {
		t.Fatal("Secure must not be set on a plain-HTTP request (the browser would drop the cookie)")
	}
	if tok, _ := res.body["token"].(string); tok == "" || tok != c.Value {
		t.Fatal("body token (for API clients) and cookie must carry the same JWT")
	}
}

func TestSessionCookieSecureBehindHTTPSProxy(t *testing.T) {
	rig := newAuthTestRig(t)
	rig.initAndLogin()
	for _, tc := range []struct {
		proto  string
		secure bool
	}{{"https", true}, {"HTTPS", true}, {"https, http", true}, {"http", false}, {"", false}} {
		h := map[string]string{}
		if tc.proto != "" {
			h["X-Forwarded-Proto"] = tc.proto
		}
		res := rig.req("POST", "/api/auth/login", h, "", map[string]any{"username": "ARTEX", "password": "operator-pass-123"})
		if res.cookie == nil || res.cookie.Secure != tc.secure {
			t.Fatalf("X-Forwarded-Proto %q: Secure = %v, want %v", tc.proto, res.cookie != nil && res.cookie.Secure, tc.secure)
		}
	}
}

func TestFailedLoginSetsNoCookie(t *testing.T) {
	rig := newAuthTestRig(t)
	rig.initAndLogin()
	res := rig.req("POST", "/api/auth/login", nil, "", map[string]any{"username": "ARTEX", "password": "wrong-password-xx"})
	if res.code != 401 || res.cookie != nil {
		t.Fatalf("code=%d cookie=%v", res.code, res.cookie)
	}
}

func TestCookieAuthenticatesAndQueryTokenDoesNot(t *testing.T) {
	rig := newAuthTestRig(t)
	login := rig.initAndLogin()
	tok := login.cookie.Value

	if res := rig.req("GET", "/api/ping", nil, tok, nil); res.code != 200 {
		t.Fatalf("cookie auth: %d", res.code)
	}
	if res := rig.req("GET", "/api/ping", map[string]string{"Authorization": "Bearer " + tok}, "", nil); res.code != 200 {
		t.Fatalf("bearer auth: %d", res.code)
	}
	if res := rig.req("GET", "/api/ping", nil, "", nil); res.code != 401 {
		t.Fatalf("no credentials: %d", res.code)
	}
	// The old EventSource convention must be dead, including on a stream request.
	res := rig.req("GET", "/api/ping?token="+tok, map[string]string{"Accept": "text/event-stream"}, "", nil)
	if res.code != 401 {
		t.Fatalf("URL token accepted: %d", res.code)
	}
	if res := rig.req("GET", "/api/ping", nil, tok+"x", nil); res.code != 401 {
		t.Fatalf("tampered cookie accepted: %d", res.code)
	}
}

func TestSessionEndpoint(t *testing.T) {
	rig := newAuthTestRig(t)
	login := rig.initAndLogin()

	res := rig.req("GET", "/api/auth/session", nil, "", nil)
	if res.code != 200 || res.body["authenticated"] != false {
		t.Fatalf("anonymous: %d %v", res.code, res.body)
	}
	res = rig.req("GET", "/api/auth/session", nil, "garbage", nil)
	if res.code != 200 || res.body["authenticated"] != false {
		t.Fatalf("bad cookie: %d %v", res.code, res.body)
	}
	res = rig.req("GET", "/api/auth/session", nil, login.cookie.Value, nil)
	if res.code != 200 || res.body["authenticated"] != true || res.body["username"] != "ARTEX" {
		t.Fatalf("valid cookie: %d %v", res.code, res.body)
	}
	if res.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", res.header.Get("Cache-Control"))
	}
	if _, leaked := res.body["token"]; leaked {
		t.Fatal("the session endpoint must not return the token")
	}
}

func TestLogoutClearsCookieWithoutASession(t *testing.T) {
	rig := newAuthTestRig(t)
	login := rig.initAndLogin()
	for _, cookie := range []string{login.cookie.Value, "", "expired-or-garbage"} {
		res := rig.req("POST", "/api/auth/logout", nil, cookie, nil)
		if res.code != 200 {
			t.Fatalf("logout with cookie %q: %d", cookie, res.code)
		}
		c := res.cookie
		if c == nil || c.MaxAge >= 0 || c.Value != "" {
			t.Fatalf("logout must expire the cookie: %+v", c)
		}
		if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
			t.Fatalf("the clearing cookie must match the original attributes or the browser keeps the old one: %+v", c)
		}
	}
}

func TestChangePasswordReissuesCookieAndRevokesOld(t *testing.T) {
	rig := newAuthTestRig(t)
	login := rig.initAndLogin()
	old := login.cookie.Value
	res := rig.req("POST", "/api/auth/change-password", nil, old, map[string]any{
		"old_password": "operator-pass-123", "new_password": "another-pass-456",
	})
	if res.code != 200 || res.cookie == nil || !res.cookie.HttpOnly {
		t.Fatalf("change-password: %d cookie=%v", res.code, res.cookie)
	}
	if res.cookie.Value == old {
		t.Fatal("a new token must be issued")
	}
	if r := rig.req("GET", "/api/ping", nil, res.cookie.Value, nil); r.code != 200 {
		t.Fatalf("new cookie rejected: %d", r.code)
	}
	if r := rig.req("GET", "/api/ping", nil, old, nil); r.code != 401 {
		t.Fatalf("old session survived a password change: %d", r.code)
	}
}

func TestCSRFGuardMatrix(t *testing.T) {
	t.Setenv(corsOriginsEnv, "http://dev.example:5173") // read once when the chain is built
	rig := newAuthTestRig(t)
	tok := rig.initAndLogin().cookie.Value

	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{"same-origin fetch", "POST", map[string]string{"Sec-Fetch-Site": "same-origin"}, 200},
		{"user typed URL", "POST", map[string]string{"Sec-Fetch-Site": "none"}, 200},
		{"cross-site", "POST", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"same-site sibling", "POST", map[string]string{"Sec-Fetch-Site": "same-site"}, 403},
		{"no fetch metadata, matching Origin", "POST", map[string]string{"Origin": "http://example.com"}, 200},
		{"no fetch metadata, other Origin", "POST", map[string]string{"Origin": "http://evil.example"}, 403},
		{"Origin null", "POST", map[string]string{"Origin": "null"}, 403},
		{"proxy-rewritten Host, forwarded host matches", "POST", map[string]string{"Origin": "https://ui.example", "X-Forwarded-Host": "ui.example"}, 200},
		{"non-browser client", "POST", nil, 200},
		{"cross-site GET is not guarded", "GET", map[string]string{"Sec-Fetch-Site": "cross-site"}, 200},
		{"cross-site DELETE", "DELETE", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"explicitly trusted CORS origin", "POST", map[string]string{"Origin": "http://dev.example:5173", "Sec-Fetch-Site": "same-site"}, 200},
	}
	for _, c := range cases {
		// httptest.NewRequest defaults Host to example.com.
		res := rig.req(c.method, "/api/ping", c.headers, tok, nil)
		if c.method == "DELETE" {
			// no DELETE route: a guarded request would 403 first, an allowed one reaches 405
			if (res.code == 403) != (c.want == 403) {
				t.Fatalf("%s: got %d", c.name, res.code)
			}
			continue
		}
		if res.code != c.want {
			t.Fatalf("%s: got %d, want %d", c.name, res.code, c.want)
		}
	}
}

func TestCSRFGuardExemptsBearerClients(t *testing.T) {
	rig := newAuthTestRig(t)
	tok := rig.initAndLogin().cookie.Value
	// A page on another site cannot set Authorization, so a bearer request is never a CSRF.
	res := rig.req("POST", "/api/ping", map[string]string{"Authorization": "Bearer " + tok, "Sec-Fetch-Site": "cross-site"}, "", nil)
	if res.code != 200 {
		t.Fatalf("bearer client blocked: %d", res.code)
	}
	// Without the cookie there is nothing to forge.
	res = rig.req("POST", "/api/auth/login", map[string]string{"Sec-Fetch-Site": "cross-site"}, "", map[string]any{"username": "ARTEX", "password": "wrong-password-xx"})
	if res.code == 403 {
		t.Fatal("the guard should not run when no session cookie is present")
	}
}

func TestCORSCredentialsOnlyForListedOrigins(t *testing.T) {
	t.Setenv(corsOriginsEnv, "http://dev.example:5173")
	rig := newAuthTestRig(t)
	res := rig.req("GET", "/api/auth/status", map[string]string{"Origin": "http://dev.example:5173"}, "", nil)
	if res.header.Get("Access-Control-Allow-Credentials") != "true" ||
		res.header.Get("Access-Control-Allow-Origin") != "http://dev.example:5173" {
		t.Fatalf("listed origin: %v", res.header)
	}
	res = rig.req("GET", "/api/auth/status", map[string]string{"Origin": "http://evil.example"}, "", nil)
	if res.header.Get("Access-Control-Allow-Origin") != "" || res.header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("unlisted origin got CORS headers: %v", res.header)
	}
	// "*" may allow reads, but must never grant credentials.
	t.Setenv(corsOriginsEnv, "*")
	rig = newAuthTestRig(t)
	res = rig.req("GET", "/api/auth/status", map[string]string{"Origin": "http://anything.example"}, "", nil)
	if res.header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("wildcard granted credentials: %v", res.header)
	}
}

func TestRequestIsHTTPS(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if requestIsHTTPS(r) {
		t.Fatal("plain request reported as HTTPS")
	}
	r.Header.Set("X-Forwarded-Proto", " https ,http")
	if !requestIsHTTPS(r) {
		t.Fatal("forwarded https not detected")
	}
}
