package config

import (
	"encoding/base64"
	"log/slog"
	"testing"
	"time"
)

func validKey() string {
	k := make([]byte, DBKeyLen)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(k)
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("CCLIENTS_DB_KEY", validKey())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.DBKey) != DBKeyLen {
		t.Fatalf("key length = %d, want %d", len(cfg.DBKey), DBKeyLen)
	}
	if cfg.BaseURL != "http://localhost:8080" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.SessionTTL != 720*time.Hour {
		t.Errorf("SessionTTL = %v", cfg.SessionTTL)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v", cfg.LogLevel)
	}
	if cfg.TrustProxy || cfg.Disable2FA {
		t.Errorf("bool defaults wrong: trustProxy=%v disable2FA=%v", cfg.TrustProxy, cfg.Disable2FA)
	}
}

func TestLoadAcceptsUnpaddedKey(t *testing.T) {
	raw := make([]byte, DBKeyLen)
	for i := range raw {
		raw[i] = byte(i)
	}
	t.Setenv("CCLIENTS_DB_KEY", base64.RawStdEncoding.EncodeToString(raw))
	if _, err := Load(); err != nil {
		t.Fatalf("Load unpadded: %v", err)
	}
}

func TestLoadRejectsBadKey(t *testing.T) {
	cases := map[string]string{
		"missing":   "",
		"not b64":   "not-valid-base64!!",
		"too long":  base64.StdEncoding.EncodeToString(make([]byte, 33)),
		"too short": base64.StdEncoding.EncodeToString(make([]byte, 16)),
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("CCLIENTS_DB_KEY", val)
			if _, err := Load(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	t.Setenv("CCLIENTS_DB_KEY", validKey())
	t.Setenv("CCLIENTS_SESSION_TTL", "not-a-duration")
	if _, err := Load(); err == nil {
		t.Fatal("expected session TTL error")
	}
	t.Setenv("CCLIENTS_SESSION_TTL", "")
	t.Setenv("CCLIENTS_TRUST_PROXY", "maybe")
	if _, err := Load(); err == nil {
		t.Fatal("expected trust proxy error")
	}
	t.Setenv("CCLIENTS_TRUST_PROXY", "")
	t.Setenv("CCLIENTS_LOG_LEVEL", "verbose")
	if _, err := Load(); err == nil {
		t.Fatal("expected log level error")
	}
}
