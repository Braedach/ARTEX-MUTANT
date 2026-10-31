package config

import (
	"os"
	"testing"
)

func TestScrubSecretEnv(t *testing.T) {
	for _, k := range SecretEnvVars {
		t.Setenv(k, "secret-value")
	}
	ScrubSecretEnv()
	for _, k := range SecretEnvVars {
		if v := os.Getenv(k); v != "" {
			t.Fatalf("%s still set after ScrubSecretEnv: %q", k, v)
		}
	}
}

func TestScrubSecretEnvIdempotent(t *testing.T) {
	ScrubSecretEnv()
	ScrubSecretEnv() // must not panic or error on an already-clean environment
}
