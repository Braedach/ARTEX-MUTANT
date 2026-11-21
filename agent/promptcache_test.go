package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// body builds an Anthropic Messages request body with n alternating messages.
func cacheTestBody(t *testing.T, msgs []map[string]any, withSystemMarker bool) []byte {
	t.Helper()
	sys := map[string]any{"type": "text", "text": "SYSTEM PROMPT"}
	if withSystemMarker {
		sys["cache_control"] = map[string]any{"type": "ephemeral"}
	}
	b, err := json.Marshal(map[string]any{
		"model":    "m",
		"system":   []any{sys},
		"tools":    []any{map[string]any{"name": "t", "description": "d", "input_schema": map[string]any{"type": "object"}}},
		"messages": msgs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func userText(s string) map[string]any {
	return map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": s}}}
}
func asstToolUse() map[string]any {
	return map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "x", "name": "t", "input": map[string]any{}}}}
}
func userToolResult() map[string]any {
	return map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "x", "content": []any{map[string]any{"type": "text", "text": "out"}}}}}
}

func lastBlock(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var d struct {
		Messages []struct {
			Content []map[string]any `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatal(err)
	}
	m := d.Messages[len(d.Messages)-1].Content
	return m[len(m)-1]
}

func TestHistoryMarkerAddedToLastToolResult(t *testing.T) {
	in := cacheTestBody(t, []map[string]any{userText("go"), asstToolUse(), userToolResult()}, true)
	out, ok := addHistoryCacheMarker(in)
	if !ok {
		t.Fatal("expected a marker on a multi-turn request")
	}
	if cc, _ := lastBlock(t, out)["cache_control"].(map[string]any); cc["type"] != "ephemeral" {
		t.Fatalf("last block has no ephemeral marker: %v", lastBlock(t, out))
	}
	// Exactly two breakpoints now: the SDK's system one plus ours.
	if n := bytes.Count(out, []byte(`"cache_control"`)); n != 2 {
		t.Fatalf("want 2 breakpoints, got %d", n)
	}
	// Idempotent: a second pass changes nothing.
	if _, again := addHistoryCacheMarker(out); again {
		t.Fatal("second pass must be a no-op")
	}
}

func TestHistoryMarkerSkipsOneShotAndAssistantTail(t *testing.T) {
	one := cacheTestBody(t, []map[string]any{userText("summarise this")}, true)
	if _, ok := addHistoryCacheMarker(one); ok {
		t.Fatal("a one-shot request is never re-read; no marker")
	}
	asst := cacheTestBody(t, []map[string]any{userText("a"), asstToolUse(), userToolResult(), asstToolUse()}, true)
	if _, ok := addHistoryCacheMarker(asst); ok {
		t.Fatal("a prefill (assistant last) must not be marked")
	}
}

func TestHistoryMarkerStringContentAndThinking(t *testing.T) {
	msgs := []map[string]any{userText("a"), asstToolUse(), {"role": "user", "content": "plain string"}}
	out, ok := addHistoryCacheMarker(cacheTestBody(t, msgs, false))
	if !ok {
		t.Fatal("string content should be promoted to a text block and marked")
	}
	if b := lastBlock(t, out); b["type"] != "text" || b["text"] != "plain string" || b["cache_control"] == nil {
		t.Fatalf("bad promoted block: %v", b)
	}
	think := []map[string]any{userText("a"), asstToolUse(), {"role": "user", "content": []any{map[string]any{"type": "thinking", "thinking": "x"}}}}
	if _, ok := addHistoryCacheMarker(cacheTestBody(t, think, false)); ok {
		t.Fatal("thinking blocks cannot carry cache_control")
	}
}

func TestHistoryMarkerNeverExceedsFourBreakpoints(t *testing.T) {
	// Four markers already present (even in odd places): add nothing.
	body := []byte(`{"messages":[{"role":"user","content":"a"},{"role":"assistant","content":"b"},{"role":"user","content":"c"}],` +
		`"x":[{"cache_control":1},{"cache_control":1},{"cache_control":1},{"cache_control":1}]}`)
	if _, ok := addHistoryCacheMarker(body); ok {
		t.Fatal("must respect Anthropic's 4-breakpoint limit")
	}
}

func TestHistoryMarkerLeavesGarbageAlone(t *testing.T) {
	for _, in := range []string{``, `not json`, `{}`, `{"messages":"x"}`, `{"messages":[]}`} {
		if out, ok := addHistoryCacheMarker([]byte(in)); ok || string(out) != in {
			t.Fatalf("input %q must pass through untouched", in)
		}
	}
}

func TestStripRemovesEveryMarker(t *testing.T) {
	in := cacheTestBody(t, []map[string]any{userText("go"), asstToolUse(), userToolResult()}, true)
	marked, _ := addHistoryCacheMarker(in)
	// Put one inside the nested tool_result content too.
	marked = bytes.Replace(marked, []byte(`"text":"out"`), []byte(`"text":"out","cache_control":{"type":"ephemeral"}`), 1)
	out, ok := stripCacheMarkers(marked)
	if !ok || bytes.Contains(out, []byte("cache_control")) {
		t.Fatalf("markers remain: %s", out)
	}
	var d map[string]any
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("stripped body is not valid JSON: %v", err)
	}
	if _, ok := stripCacheMarkers(out); ok {
		t.Fatal("nothing left to strip")
	}
}

// ---- transport behaviour -------------------------------------------------

func anthropicReq(t *testing.T, url string, body []byte) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, url+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPrepareMarkersOnOffAndOtherFormats(t *testing.T) {
	defer SetPromptCache(true)
	body := cacheTestBody(t, []map[string]any{userText("a"), asstToolUse(), userToolResult()}, true)

	SetPromptCache(true)
	r, marked := prepareCacheMarkers(anthropicReq(t, "http://h", body))
	if !marked {
		t.Fatal("caching on: request should carry markers")
	}
	got, _ := io.ReadAll(r.Body)
	if n := bytes.Count(got, []byte(`"cache_control"`)); n != 2 {
		t.Fatalf("want system+history markers, got %d", n)
	}
	if int(r.ContentLength) != len(got) {
		t.Fatal("ContentLength must match the rewritten body")
	}

	SetPromptCache(false)
	r, marked = prepareCacheMarkers(anthropicReq(t, "http://h", body))
	got, _ = io.ReadAll(r.Body)
	if marked || bytes.Contains(got, []byte("cache_control")) {
		t.Fatalf("caching off: every marker (including the SDK's) must go: %s", got)
	}

	// Anything that is not an Anthropic Messages call is left strictly alone.
	SetPromptCache(true)
	oa, _ := http.NewRequest(http.MethodPost, "http://h/v1/chat/completions", bytes.NewReader(body))
	if r2, m := prepareCacheMarkers(oa); r2 != oa || m {
		t.Fatal("OpenAI-format request must not be rewritten")
	}
}

func TestEnvSwitchWinsOverSetting(t *testing.T) {
	t.Setenv("ARTEX_PROMPT_CACHE", "off")
	defer func() { t.Setenv("ARTEX_PROMPT_CACHE", ""); SetPromptCache(true) }()
	SetPromptCache(true)
	if PromptCacheEnabled() {
		t.Fatal("ARTEX_PROMPT_CACHE=off must not be overridable from the UI setting")
	}
}

func TestTransportRetriesOnceWithoutMarkersWhenRejected(t *testing.T) {
	defer SetPromptCache(true)
	SetPromptCache(true)
	var calls int32
	var lastBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		b, _ := io.ReadAll(r.Body)
		lastBody.Store(string(b))
		if bytes.Contains(b, []byte("cache_control")) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":{"message":"messages.2.content.0: cache_control: Extra inputs are not permitted"}}`))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	cacheRejectedHosts.Delete(srv.URL[len("http://"):]) // hygiene
	cacheRejectedHosts.Delete(srv.URL)

	cl, err := quotaAwareHTTPClient("", "")
	if err != nil {
		t.Fatal(err)
	}
	body := cacheTestBody(t, []map[string]any{userText("a"), asstToolUse(), userToolResult()}, true)
	resp, err := cl.Do(anthropicReq(t, srv.URL, body))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "ok") {
		t.Fatalf("want the retried 200, got %d %s", resp.StatusCode, b)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("want exactly 2 upstream calls (rejected + retry), got %d", n)
	}
	if strings.Contains(lastBody.Load().(string), "cache_control") {
		t.Fatal("the retry must carry no markers")
	}

	// The host is remembered: the next request goes out clean in ONE call.
	atomic.StoreInt32(&calls, 0)
	resp, err = cl.Do(anthropicReq(t, srv.URL, body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("after learning, want 1 clean call; got status %d, %d calls", resp.StatusCode, atomic.LoadInt32(&calls))
	}
	cacheRejectedHosts.Delete(srv.URL)
}

func TestTransportDoesNotRetryUnrelated400(t *testing.T) {
	defer SetPromptCache(true)
	SetPromptCache(true)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"message":"max_tokens too large"}}`))
	}))
	defer srv.Close()
	cl, _ := quotaAwareHTTPClient("", "")
	body := cacheTestBody(t, []map[string]any{userText("a"), asstToolUse(), userToolResult()}, true)
	resp, err := cl.Do(anthropicReq(t, srv.URL, body))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 400 || !strings.Contains(string(b), "max_tokens") {
		t.Fatalf("an unrelated 400 must be passed through intact, got %d %s", resp.StatusCode, b)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("an unrelated 400 must not be retried, got %d calls", atomic.LoadInt32(&calls))
	}
	if _, learned := cacheRejectedHosts.Load(srv.URL); learned {
		t.Fatal("must not blame caching for an unrelated error")
	}
}
