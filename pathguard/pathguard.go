// Package pathguard blocks the agent's file tools from reaching the platform's own
// control-plane secrets (ARTEX-MUTANT hardening).
//
// Why it exists: the agent legitimately has shell and file access as the server's
// own UID, and it reads hostile content all day, so a prompt-injected agent is the
// expected threat. The JWT signing key and the MITM CA private key sit on the same
// filesystem; reading the first forges an admin session, reading the second lets an
// attacker impersonate any TLS site the recording proxy handles. The LLM judge's
// own prompt says reading a key is not by itself a reason to block, and intercept
// rules live in the database, so neither is a boundary for this.
//
// This guard is deliberately NOT stored in the database or settings: a settings
// write must not be able to switch it off. It resolves symlinks (a link planted in
// the workspace pointing at the key is caught) and resolves relative paths against
// the task's working directory.
//
// Scope: path-carrying file tools only (Read, Write, Edit, MultiEdit, LS, Glob,
// Grep). A Bash command string cannot be judged reliably here and stays with the
// intercept rules and the judge. Design informed by the equivalent package in
// wufufu770/reArtex; implemented fresh here (see MAINTAINING.md).
package pathguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// pathParams names the parameter that carries a path for each built-in file tool
// (from norma's tool schemas).
var pathParams = map[string][]string{
	"Read":      {"file_path"},
	"Write":     {"file_path"},
	"Edit":      {"file_path"},
	"MultiEdit": {"file_path"},
	"LS":        {"path"},
	"Glob":      {"path"},
	"Grep":      {"path"},
}

// procSecrets are the /proc/<pid>/ entries that expose a process's environment,
// command line or memory.
var procSecrets = map[string]bool{"environ": true, "cmdline": true, "mem": true, "maps": true, "mounts": true}

var (
	mu    sync.RWMutex
	roots []string // absolute and symlink-resolved forms of every protected path
)

// Protect registers paths (files or directories) the file tools may never reach.
// Both the lexical and the symlink-resolved form are stored, so the guard holds
// whichever spelling the tool call uses. Safe to call more than once.
func Protect(paths ...string) {
	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		roots = appendUnique(roots, abs)
		if real, err := resolveExisting(abs); err == nil {
			roots = appendUnique(roots, real)
		}
	}
}

// Reset clears the registry (tests).
func Reset() {
	mu.Lock()
	roots = nil
	mu.Unlock()
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// Check reports whether a tool call may proceed; nil means allow. workingDir is the
// task's working directory, used to resolve relative paths ("" falls back to the
// process directory).
func Check(toolName string, input []byte, workingDir string) error {
	params, ok := pathParams[toolName]
	if !ok {
		return nil
	}
	var in map[string]any
	if json.Unmarshal(input, &in) != nil {
		return nil // the tool reports a malformed call itself
	}
	for _, key := range params {
		raw, _ := in[key].(string)
		if raw == "" {
			continue // the tool defaults to the working directory
		}
		resolved, err := resolveFrom(raw, workingDir)
		if err != nil {
			return fmt.Errorf("%s %s=%q: cannot resolve the real path", toolName, key, raw)
		}
		if why := denyReason(toolName, resolved); why != "" {
			return fmt.Errorf("%s %s=%q: %s", toolName, key, raw, why)
		}
	}
	return nil
}

func denyReason(toolName, real string) string {
	mu.RLock()
	defer mu.RUnlock()
	for _, root := range roots {
		if real == root || strings.HasPrefix(real, root+string(os.PathSeparator)) {
			return "the target is a platform credential or control-plane file"
		}
		// A recursive content search over a directory that contains a secret would
		// read it too. Listing (LS/Glob) only reveals names, so it stays allowed.
		if toolName == "Grep" && strings.HasPrefix(root, real+string(os.PathSeparator)) {
			return "the search would read a platform credential under this directory"
		}
	}
	if isProcSecret(real) {
		return "the target is a process environment or memory entry"
	}
	if real == "/run/secrets" || strings.HasPrefix(real, "/run/secrets/") {
		return "the target is a container secret"
	}
	return ""
}

// isProcSecret matches /proc/<pid|self|thread-self>/{environ,cmdline,mem,maps,mounts}
// and the same entries under /proc/<pid>/task/<tid>/.
func isProcSecret(real string) bool {
	if !strings.HasPrefix(real, "/proc/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(real, "/proc/"), "/")
	if len(parts) >= 2 && procSecrets[parts[1]] {
		return true
	}
	return len(parts) >= 4 && parts[1] == "task" && procSecrets[parts[3]]
}

// resolveFrom makes p absolute against workingDir and resolves symlinks.
func resolveFrom(p, workingDir string) (string, error) {
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	if !filepath.IsAbs(p) && workingDir != "" {
		p = filepath.Join(workingDir, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return resolveExisting(abs)
}

// resolveExisting returns the real path of p; for a path that does not exist yet
// (a new file being written) it resolves the deepest existing ancestor and appends
// the remainder, so a symlinked parent directory is still followed.
func resolveExisting(p string) (string, error) {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r, nil
	}
	dir, tail := p, ""
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return p, nil
		}
		base := filepath.Base(dir)
		if tail == "" {
			tail = base
		} else {
			tail = filepath.Join(base, tail)
		}
		dir = parent
		if r, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(r, tail), nil
		}
	}
}
