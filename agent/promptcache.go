package agent

// Prompt caching.
//
// Every agent turn re-sends the same large prefix: the tool definitions and the
// system prompt (8k to 40k tokens here), and then the whole conversation so far.
// Without caching a provider bills all of it at the full input rate on every
// call, which is what made a two-task, three-minute run cost about a million input
// tokens. This file is the model-neutral half of the fix; the system-prompt half
// is `deferredSystem` (always sets the cache boundary).
//
// How each wire format is covered:
//
//   - Anthropic Messages: caching is explicit. The SDK already puts a cache
//     breakpoint on the system prompt when a boundary is set, and a breakpoint on
//     the system block covers the tools before it. This file adds a second,
//     moving breakpoint on the last block of the conversation, so each turn reads
//     the previous turn's prefix from the cache instead of paying for it again.
//   - OpenAI Chat Completions / Responses and the many OpenAI-compatible gateways
//     (DeepSeek, Gemini's OpenAI endpoint, vLLM, ...): caching is automatic and
//     keyed on an identical prefix, so the only requirement is that the prefix is
//     byte-stable between calls (see TestToolOrderIsStable). The SDK already reads
//     the cached-token counts back from these responses.
//
// An endpoint that speaks the Anthropic wire format but rejects `cache_control`
// (some gateways) must not break: the transport retries the request once without
// any cache markers and remembers that host, so the cost of being wrong is one
// extra round trip, once.

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// promptCacheOff is the master switch. Caching is ON by default; ARTEX_PROMPT_CACHE=off
// (or the "Prompt caching" setting) turns it off, in which case the SDK's own system
// marker is stripped too so a gateway that dislikes the field never sees it.
var promptCacheOff atomic.Bool

func init() {
	if isFalsy(os.Getenv("ARTEX_PROMPT_CACHE")) {
		promptCacheOff.Store(true)
	}
}

// SetPromptCache switches prompt caching on or off at runtime. The environment
// variable ARTEX_PROMPT_CACHE=off always wins: a deployment that disabled caching
// there cannot be re-enabled from the UI by accident.
func SetPromptCache(on bool) {
	if isFalsy(os.Getenv("ARTEX_PROMPT_CACHE")) {
		on = false
	}
	promptCacheOff.Store(!on)
}

// PromptCacheEnabled reports whether prompt caching is currently on.
func PromptCacheEnabled() bool { return !promptCacheOff.Load() }

// cacheRejectedHosts remembers endpoints that refused cache markers, so we only pay
// the retry once per host per process.
var cacheRejectedHosts sync.Map // "scheme://host" -> struct{}

// minTurnsForHistoryMarker is how many messages a request needs before the moving
// breakpoint is worth placing. A one-shot call (one user message: a compaction
// summary, a title, a connection test) is never re-read, so writing a cache entry
// for it would only cost the write premium.
const minTurnsForHistoryMarker = 3

// maxCacheBreakpoints is Anthropic's hard limit per request.
const maxCacheBreakpoints = 4

var ephemeralMarker = json.RawMessage(`{"type":"ephemeral"}`)

// isAnthropicMessages reports whether r is a request to an Anthropic-format
// Messages endpoint (the only wire format that needs explicit cache markers).
func isAnthropicMessages(r *http.Request) bool {
	return r != nil && r.Method == http.MethodPost && r.URL != nil &&
		strings.HasSuffix(r.URL.Path, "/v1/messages")
}

func hostKey(r *http.Request) string { return r.URL.Scheme + "://" + r.URL.Host }

// addHistoryCacheMarker puts an ephemeral cache breakpoint on the last content
// block of the last message, which must be a user turn (tool results are user
// turns). It returns the new body and true when it changed anything. It never
// touches a body it cannot parse, never exceeds Anthropic's four breakpoints, and
// leaves one-shot requests alone.
func addHistoryCacheMarker(body []byte) ([]byte, bool) {
	if bytes.Count(body, []byte(`"cache_control"`)) >= maxCacheBreakpoints {
		return body, false
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return body, false
	}
	var msgs []json.RawMessage
	if json.Unmarshal(top["messages"], &msgs) != nil || len(msgs) < minTurnsForHistoryMarker {
		return body, false
	}
	var last map[string]json.RawMessage
	if json.Unmarshal(msgs[len(msgs)-1], &last) != nil {
		return body, false
	}
	var role string
	if json.Unmarshal(last["role"], &role) != nil || role != "user" {
		return body, false
	}

	content := bytes.TrimSpace(last["content"])
	var blocks []map[string]json.RawMessage
	switch {
	case len(content) > 0 && content[0] == '"':
		// A bare string content: promote it to a single text block so it can carry the marker.
		var text string
		if json.Unmarshal(content, &text) != nil {
			return body, false
		}
		t, _ := json.Marshal(text)
		blocks = []map[string]json.RawMessage{{"type": json.RawMessage(`"text"`), "text": t}}
	case len(content) > 0 && content[0] == '[':
		if json.Unmarshal(content, &blocks) != nil || len(blocks) == 0 {
			return body, false
		}
	default:
		return body, false
	}

	tail := blocks[len(blocks)-1]
	var typ string
	_ = json.Unmarshal(tail["type"], &typ)
	if typ == "thinking" || typ == "redacted_thinking" {
		return body, false // these block types cannot carry cache_control
	}
	if _, has := tail["cache_control"]; has {
		return body, false
	}
	tail["cache_control"] = ephemeralMarker

	nb, err := json.Marshal(blocks)
	if err != nil {
		return body, false
	}
	last["content"] = nb
	nl, err := json.Marshal(last)
	if err != nil {
		return body, false
	}
	msgs[len(msgs)-1] = nl
	nm, err := json.Marshal(msgs)
	if err != nil {
		return body, false
	}
	top["messages"] = nm
	out, err := json.Marshal(top)
	if err != nil {
		return body, false
	}
	return out, true
}

// stripCacheMarkers removes every cache_control field from the system blocks, the
// tool definitions and the message content blocks (including blocks nested in
// tool results). It returns the new body and whether anything was removed.
func stripCacheMarkers(body []byte) ([]byte, bool) {
	if !bytes.Contains(body, []byte(`"cache_control"`)) {
		return body, false
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return body, false
	}
	changed := false
	for _, key := range []string{"system", "tools", "messages"} {
		raw, ok := top[key]
		if !ok {
			continue
		}
		if nr, c := stripBlockList(raw, key == "messages"); c {
			top[key] = nr
			changed = true
		}
	}
	if !changed {
		return body, false
	}
	out, err := json.Marshal(top)
	if err != nil {
		return body, false
	}
	return out, true
}

// stripBlockList strips cache_control from a JSON array of objects. When
// descend is set it also walks each object's "content" (messages and tool
// results nest content blocks).
func stripBlockList(raw json.RawMessage, descend bool) (json.RawMessage, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return raw, false
	}
	var items []map[string]json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return raw, false
	}
	changed := false
	for _, it := range items {
		if _, ok := it["cache_control"]; ok {
			delete(it, "cache_control")
			changed = true
		}
		if descend {
			if c, ok := it["content"]; ok {
				if nc, cc := stripBlockList(c, true); cc {
					it["content"] = nc
					changed = true
				}
			}
		}
	}
	if !changed {
		return raw, false
	}
	out, err := json.Marshal(items)
	if err != nil {
		return raw, false
	}
	return out, true
}

// mentionsCacheControl reports whether an error body complains about the cache
// marker, which is the signal that a gateway does not support it.
func mentionsCacheControl(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "cache_control") || strings.Contains(s, "cache control") ||
		strings.Contains(s, "cachecontrol")
}

// withBody returns a shallow copy of r carrying body, with the length and the
// replay hook (GetBody) kept consistent. The original request is left untouched,
// as http.RoundTripper requires.
func withBody(r *http.Request, body []byte) *http.Request {
	c := r.Clone(r.Context())
	c.Body = io.NopCloser(bytes.NewReader(body))
	c.ContentLength = int64(len(body))
	c.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	return c
}

// prepareCacheMarkers rewrites an Anthropic Messages request according to the
// caching policy. It returns the request to send and whether markers are present
// on it (which decides whether a rejection should trigger the fallback retry).
func prepareCacheMarkers(r *http.Request) (*http.Request, bool) {
	if !isAnthropicMessages(r) || r.GetBody == nil {
		return r, false
	}
	rc, err := r.GetBody()
	if err != nil {
		return r, false
	}
	body, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return r, false
	}
	if !PromptCacheEnabled() {
		if nb, ok := stripCacheMarkers(body); ok {
			return withBody(r, nb), false
		}
		return r, false
	}
	if _, rejected := cacheRejectedHosts.Load(hostKey(r)); rejected {
		if nb, ok := stripCacheMarkers(body); ok {
			return withBody(r, nb), false
		}
		return r, false
	}
	if nb, ok := addHistoryCacheMarker(body); ok {
		return withBody(r, nb), true
	}
	return r, bytes.Contains(body, []byte(`"cache_control"`))
}

// retryWithoutCache is called when a request that carried cache markers came back
// 400/422. If the error is about the markers it remembers the host and returns a
// copy of the request with every marker removed; otherwise it returns nil and the
// original response stands.
func retryWithoutCache(r *http.Request, resp *http.Response) (*http.Request, []byte) {
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnprocessableEntity {
		return nil, nil
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(b))
		return nil, b
	}
	if !mentionsCacheControl(b) || r.GetBody == nil {
		resp.Body = io.NopCloser(bytes.NewReader(b))
		return nil, b
	}
	rc, err := r.GetBody()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(b))
		return nil, b
	}
	body, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(b))
		return nil, b
	}
	nb, changed := stripCacheMarkers(body)
	if !changed {
		resp.Body = io.NopCloser(bytes.NewReader(b))
		return nil, b
	}
	if _, loaded := cacheRejectedHosts.LoadOrStore(hostKey(r), struct{}{}); !loaded {
		log.Printf("[llm] %s rejected prompt-cache markers; retrying without them and not sending them to this host again", hostKey(r))
	}
	return withBody(r, nb), b
}

// PromptCacheEnvOff reports whether ARTEX_PROMPT_CACHE forces caching off.
func PromptCacheEnvOff() bool { return isFalsy(os.Getenv("ARTEX_PROMPT_CACHE")) }
