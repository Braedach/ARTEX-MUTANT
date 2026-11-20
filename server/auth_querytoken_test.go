package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A token in the URL is never accepted, not even on an event stream: the web UI's
// EventSource sends the HttpOnly session cookie by itself.
func TestExtractTokenIgnoresQueryString(t *testing.T) {
	for _, tc := range []struct{ method, target, accept string }{
		{"GET", "/api/tasks?token=abc", ""},
		{"GET", "/api/logs/stream?token=abc", "text/event-stream"},
		{"POST", "/api/tasks?token=abc", "text/event-stream"},
	} {
		r := httptest.NewRequest(tc.method, tc.target, nil)
		if tc.accept != "" {
			r.Header.Set("Accept", tc.accept)
		}
		if got := extractToken(r); got != "" {
			t.Fatalf("%s %s: query token accepted: %q", tc.method, tc.target, got)
		}
	}
}

func TestExtractTokenSources(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/x", nil)
	r.Header.Set("Authorization", "Bearer from-header")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "from-cookie"})
	if got := extractToken(r); got != "from-header" {
		t.Fatalf("header should win: %q", got)
	}
	r = httptest.NewRequest("GET", "/api/x", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "from-cookie"})
	if got := extractToken(r); got != "from-cookie" {
		t.Fatalf("cookie not read: %q", got)
	}
	r = httptest.NewRequest("GET", "/api/x", nil)
	r.Header.Set("Authorization", "Basic abc")
	if got := extractToken(r); got != "" {
		t.Fatalf("non-bearer scheme accepted: %q", got)
	}
}

func TestSelfUpdateDisabledEnv(t *testing.T) {
	t.Setenv("ARTEX_DISABLE_SELFUPDATE", "1")
	if !selfUpdateDisabled() {
		t.Fatal("expected disabled")
	}
	t.Setenv("ARTEX_DISABLE_SELFUPDATE", "")
	if selfUpdateDisabled() {
		t.Fatal("expected enabled")
	}
}
