package logging

import (
	"log/slog"
	"testing"
)

func TestRedactMasksSensitiveKeys(t *testing.T) {
	for _, key := range []string{"password", "secret", "token", "totp", "body", "key", "db_key", "authorization", "cookie"} {
		got := Redact(nil, slog.String(key, "super-secret-value"))
		if got.Value.String() != "[redacted]" {
			t.Errorf("key %q: got %q, want [redacted]", key, got.Value.String())
		}
	}
}

func TestRedactKeepsOrdinaryKeys(t *testing.T) {
	got := Redact(nil, slog.String("client", "Acme Co"))
	if got.Value.String() != "Acme Co" {
		t.Errorf("got %q, want unchanged", got.Value.String())
	}
}
