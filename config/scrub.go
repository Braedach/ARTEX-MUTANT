package config

import "os"

// SecretEnvVars lists the environment variables ARTEX reads exactly once, at
// startup, to bootstrap a secret into memory (a DB connection, an LLM API key,
// the admin password, the setup token). None of them is read again afterwards
// — see each call site's own comment for where it's consumed. Left set, an
// agent-driven Bash tool call running as the same UID as the server process
// can read them straight back out of /proc/<pid>/environ (confirmed: Go's
// os.Unsetenv updates the real process environment block, not just an
// in-process cache, so this closes that path rather than only hiding the
// value from Go's own os.Getenv).
var SecretEnvVars = []string{
	"ARTEX_PG_DSN",
	"ANTHROPIC_API_KEY",
	"OPENAI_API_KEY",
	"ARTEX_ADMIN_PASSWORD",
	"ARTEX_SETUP_TOKEN",
}

// ScrubSecretEnv unsets SecretEnvVars. Call it once, as early as possible
// after every one-shot consumer above has run (today: after server.New
// returns in cmd/artex/main.go — NewManager has resolved the DSN, and New
// itself has run agent.FromEnv and bootstrapAuth by the time it returns).
// Safe to call more than once; unsetting an already-unset var is a no-op.
func ScrubSecretEnv() {
	for _, k := range SecretEnvVars {
		_ = os.Unsetenv(k)
	}
}
