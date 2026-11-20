package server

import (
	"net/http"
	"net/url"
	"strings"
)

// Session cookie (ARTEX-MUTANT hardening). The admin JWT used to live in
// localStorage and in a cookie written by JavaScript, so any script running on the
// page (an XSS, a malicious dependency) could read it. It is now set by the server as
// HttpOnly, so page scripts never see it, SameSite=Strict, so a cross-site request
// does not carry it, and Secure whenever the request arrived over HTTPS (directly or
// through a reverse proxy that sets X-Forwarded-Proto).
//
// The JSON bodies of login, init and change-password still carry the token for API
// clients that send "Authorization: Bearer"; the web UI ignores it and stores nothing.
const sessionCookieName = "artex_token"

// requestIsHTTPS reports whether the client reached us over HTTPS, directly or via a
// reverse proxy. A client can forge X-Forwarded-Proto, but that only decides the
// Secure attribute of a cookie we send back to that same client.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if i := strings.IndexByte(proto, ','); i >= 0 {
		proto = proto[:i]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

func sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	}
}

// setSessionCookie issues the session cookie for a freshly signed token.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, sessionCookie(r, token, int(jwtTTL.Seconds())))
}

// clearSessionCookie expires the session cookie. Only the server can do this: the
// cookie is HttpOnly, so page scripts cannot delete it.
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, sessionCookie(r, "", -1))
}

// POST /api/auth/logout - expires the session cookie. It needs no valid session:
// logging out must always work, including with an already expired token. The JWT is
// stateless, so this ends the browser session but cannot revoke a token that was
// copied elsewhere; changing the password does that (the signing key is bound to it).
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w, r)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/auth/session - tells the web UI whether it holds a valid session, since
// it can no longer look at the token itself. Always 200: "not signed in" is an
// ordinary answer, not an error.
func (s *Server) authSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.verifyToken(extractToken(r)) {
		writeJSON(w, 200, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, 200, map[string]any{"authenticated": true, "username": "ARTEX"})
}

// csrfGuard refuses cross-origin state-changing requests that are authenticated only
// by the session cookie. SameSite=Strict already keeps the cookie off cross-site
// requests in current browsers; this is the second, server-side layer, and it covers
// sibling subdomains (same-site but not same-origin) and older browsers.
//
// Requests with an Authorization header are exempt (a cross-site page cannot set that
// header), as are clients that send no browser headers at all.
func csrfGuard(allowedOrigins map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := r.Cookie(sessionCookieName); err != nil {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOriginRequest(r, allowedOrigins) {
			writeErr(w, 403, "cross-origin request refused")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOriginRequest decides from the browser's own headers. Sec-Fetch-Site is sent by
// every current browser and cannot be set by page script; Origin is the fallback.
func sameOriginRequest(r *http.Request, allowed map[string]bool) bool {
	origin := r.Header.Get("Origin")
	if origin != "" && allowed[strings.ToLower(origin)] {
		return true // an origin the operator explicitly trusts (CORS allow-list)
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		return sfs == "same-origin" || sfs == "none"
	}
	if origin == "" {
		return true // not a browser request
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		return strings.EqualFold(u.Host, strings.TrimSpace(strings.Split(fh, ",")[0]))
	}
	return false
}
