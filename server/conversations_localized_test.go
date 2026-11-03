package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"
)

// This is a regression guard keeping conversations.go's conversation (chat)
// API error responses in English. Unlike most of the server package's
// *_localized_test.go files (which pin Korean via the shared
// assertKoreanError helper), this file's own source was translated to
// English - see conversations.go's own comment on why only this file, not
// yet the rest of the package. assertEnglishError below is this file's own,
// separate check: no CJK Han ideograph and no Hangul syllable at all.

// assertEnglishError fails when msg is empty or contains any CJK Han
// ideograph or Hangul syllable (either would mean a translation reverted).
func assertEnglishError(t *testing.T, label, msg string) {
	t.Helper()
	if msg == "" {
		t.Fatalf("%s: empty message", label)
	}
	for _, r := range msg {
		if unicode.Is(unicode.Han, r) {
			t.Fatalf("%s: still has a CJK Han ideograph: %q", label, msg)
		}
		if unicode.Is(unicode.Hangul, r) {
			t.Fatalf("%s: still has a Hangul syllable: %q", label, msg)
		}
	}
}

// TestConversationErrorConstantsLocalized asserts all 12 response constants are in English.
// The handlers go through s.pg(w) (DB) first, so they can't run to completion on this DB-less
// host - this asserts the constants themselves instead (same precedent as auth.go). A format
// string with %d is filled with its real argument before checking the final text.
func TestConversationErrorConstantsLocalized(t *testing.T) {
	cases := []struct {
		name string
		msg  string
	}{
		{"request_too_large", convErrRequestTooLarge},
		{"agent_key_empty", convErrAgentKeyEmpty},
		{"agent_key_too_long", fmt.Sprintf(convErrAgentKeyTooLong, maxConversationAgentKeyRunes)},
		{"agent_not_found", convErrAgentNotFound},
		{"llm_profile", convErrLLMProfile},
		{"title_too_long", fmt.Sprintf(convErrTitleTooLong, maxConversationTitleRunes)},
		{"title_or_pinned", convErrTitleOrPinned},
		{"title_empty", convErrTitleEmpty},
		{"bad_conv_id", convErrBadConvID},
		{"ids_count", fmt.Sprintf(convErrIDsCount, maxConversationDeleteBatch)},
		{"message_empty", convErrMessageEmpty},
		{"busy", convErrBusy},
	}
	for _, c := range cases {
		assertEnglishError(t, c.name, c.msg)
	}
}

// TestDecodeConversationRequestTooLargeLocalized checks the oversized-request-body path all the
// way through the actual HTTP response body. decodeConversationRequest is a package function that
// doesn't go through Server(DB), so it can run without a DB, confirming the constant actually
// reaches the response (oversized body -> 413 + English text).
func TestDecodeConversationRequestTooLargeLocalized(t *testing.T) {
	// A valid JSON body that exceeds the 64KB limit. MaxBytesReader reports the overrun mid-read.
	body := `{"title":"` + strings.Repeat("a", maxConversationRequestBytes+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/conversations", strings.NewReader(body))
	rec := httptest.NewRecorder()
	var dst struct {
		Title string `json:"title"`
	}
	if decodeConversationRequest(rec, req, &dst) {
		t.Fatal("body exceeded the limit, but decodeConversationRequest returned true")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response JSON: %v (body=%q)", err, rec.Body.String())
	}
	if resp.Error != convErrRequestTooLarge {
		t.Fatalf("response error = %q, want %q", resp.Error, convErrRequestTooLarge)
	}
	assertEnglishError(t, "decode.too_large.response", resp.Error)
}

// TestConversationDefaultTitlesLocalized asserts the two default-conversation-title constants
// (F8) are in English and distinct from each other. convDefaultTitle is both the creation default
// and the sentinel for the auto-title branch, so reverting it would show the wrong language in the
// conversation list and the delete dialog.
func TestConversationDefaultTitlesLocalized(t *testing.T) {
	assertEnglishError(t, "default_title", convDefaultTitle)
	assertEnglishError(t, "attachment_title", convAttachmentTitle)
	if convDefaultTitle == convAttachmentTitle {
		t.Fatal("the default title and the attachment default title must not be equal")
	}
}

// TestIsDefaultConversationTitle pins the auto-title branch's own logic: the creation default
// (convDefaultTitle) and an empty title are both auto-title candidates, a user-given title is not.
// The creation default and the sentinel share one constant, so the two can't drift apart and break
// the auto-title branch.
func TestIsDefaultConversationTitle(t *testing.T) {
	if !isDefaultConversationTitle("") {
		t.Fatal("an empty title should be an auto-title candidate")
	}
	if !isDefaultConversationTitle(convDefaultTitle) {
		t.Fatalf("the creation default %q should be an auto-title candidate", convDefaultTitle)
	}
	if isDefaultConversationTitle("A title the user wrote") {
		t.Fatal("a user-given title should not be an auto-title candidate")
	}
}

// TestConversationRetestReasonsLocalized asserts the three retest-outcome constants (F9) are in
// English. These values are stored in the finding_retests.error column and surfaced as the retest
// panel's item.error, so reverting them would show the wrong language there.
func TestConversationRetestReasonsLocalized(t *testing.T) {
	assertEnglishError(t, "retest_failed_to_start", convRetestFailedToStart)
	assertEnglishError(t, "retest_status_read_failed", convRetestStatusReadFailed)
	assertEnglishError(t, "retest_stopped_or_closed", convRetestStoppedOrClosed)
}

// TestTranscriptErrorSummaryLocalized pins the activity-transcript error wrapper (F9). The chat-turn
// call (no label) and the task main-agent call ("Main agent") both render as the same
// "(...error: ...)" shape, the inner err text is preserved verbatim, and the wrapper has no
// leftover CJK Han or full-width punctuation.
func TestTranscriptErrorSummaryLocalized(t *testing.T) {
	cases := []struct {
		name  string
		label string
		errm  string
		want  string
	}{
		{"chat_turn", "", "connection reset", "(error: connection reset)"},
		{"main_agent", "Main agent", "connection reset", "(Main agent error: connection reset)"},
	}
	for _, c := range cases {
		got := transcriptErrorSummary(c.label, c.errm)
		if got != c.want {
			t.Fatalf("%s: transcriptErrorSummary = %q, want %q", c.name, got, c.want)
		}
		if !strings.Contains(got, c.errm) {
			t.Fatalf("%s: the original err text was not preserved: %q", c.name, got)
		}
		// Full-width brackets/colon must have been replaced with ASCII (F1/fluent-english policy).
		if strings.ContainsAny(got, "（）：") {
			t.Fatalf("%s: a full-width punctuation mark is still present: %q", c.name, got)
		}
		wrapper := strings.ReplaceAll(got, c.errm, "")
		assertEnglishError(t, c.name+".wrapper", wrapper)
	}
}
