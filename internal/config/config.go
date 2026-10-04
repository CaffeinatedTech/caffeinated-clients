// Package config loads and validates all runtime configuration from the
// environment. There is no config file; every value comes from a CCLIENTS_*
// environment variable (see README.md).
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DBKeyLen is the required decoded length of CCLIENTS_DB_KEY, in bytes.
const DBKeyLen = 32

// Config is the fully-validated runtime configuration.
type Config struct {
	BaseURL       string
	DBPath        string
	DBKey         []byte
	ListenAddr    string
	SessionTTL    time.Duration
	TrustProxy    bool
	LogLevel      slog.Level
	BootstrapUser string
	BootstrapPass string
	Disable2FA    bool
	Argon2Memory  uint32
	Argon2Time    uint32
	Argon2Threads uint8

	// WebAuthn/passkey relying-party identity, derived from BaseURL. RPID is
	// the host without a port; RPOrigins is the single fully-qualified origin
	// (scheme://host) a ceremony must come from. Passkeys require HTTPS (or
	// http://localhost) and a real host, never a bare IP, per the WebAuthn spec.
	RPID          string
	RPOrigins     []string
	RPDisplayName string
}

// Load reads the environment and returns a validated Config. It fails closed:
// a missing or malformed CCLIENTS_DB_KEY is always an error.
func Load() (*Config, error) {
	c := &Config{
		BaseURL:       getenv("CCLIENTS_BASE_URL", "http://localhost:8080"),
		ListenAddr:    getenv("CCLIENTS_LISTEN_ADDR", ":8080"),
		BootstrapUser: os.Getenv("CCLIENTS_BOOTSTRAP_USERNAME"),
		BootstrapPass: os.Getenv("CCLIENTS_BOOTSTRAP_PASSWORD"),
	}

	dataDir := getenv("CCLIENTS_DATA_DIR", "./data")
	c.DBPath = getenv("CCLIENTS_DB_PATH", filepath.Join(dataDir, "clients.db"))

	key, err := decodeKey(os.Getenv("CCLIENTS_DB_KEY"))
	if err != nil {
		return nil, err
	}
	c.DBKey = key

	if err := c.DeriveWebAuthn(); err != nil {
		return nil, err
	}

	if c.SessionTTL, err = parseDuration("CCLIENTS_SESSION_TTL", "720h"); err != nil {
		return nil, err
	}
	if c.TrustProxy, err = parseBool("CCLIENTS_TRUST_PROXY", false); err != nil {
		return nil, err
	}
	if c.Disable2FA, err = parseBool("CCLIENTS_DISABLE_2FA", false); err != nil {
		return nil, err
	}
	if c.LogLevel, err = parseLevel(getenv("CCLIENTS_LOG_LEVEL", "info")); err != nil {
		return nil, err
	}
	if c.Argon2Memory, err = parseUint32("CCLIENTS_ARGON2_MEMORY", 64*1024); err != nil {
		return nil, err
	}
	if c.Argon2Time, err = parseUint32("CCLIENTS_ARGON2_TIME", 3); err != nil {
		return nil, err
	}
	threads, err := parseUint32("CCLIENTS_ARGON2_THREADS", 4)
	if err != nil {
		return nil, err
	}
	if threads == 0 || threads > 255 {
		return nil, fmt.Errorf("CCLIENTS_ARGON2_THREADS must be between 1 and 255, got %d", threads)
	}
	c.Argon2Threads = uint8(threads)
	return c, nil
}

// DeriveWebAuthn sets the relying-party identity for passkeys from BaseURL.
// RPID is the host (no port); RPOrigins is the single origin (scheme://host).
// A path on BaseURL is ignored: WebAuthn origins never carry one.
func (c *Config) DeriveWebAuthn() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("CCLIENTS_BASE_URL is not a valid URL: %q", c.BaseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("CCLIENTS_BASE_URL must be http or https, got %q", c.BaseURL)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("CCLIENTS_BASE_URL must include a host, got %q", c.BaseURL)
	}
	c.RPID = u.Hostname()
	c.RPOrigins = []string{u.Scheme + "://" + u.Host}
	c.RPDisplayName = getenv("CCLIENTS_RP_DISPLAY_NAME", "caffeinated-clients")
	return nil
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func decodeKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("CCLIENTS_DB_KEY is required (base64-encoded 32 bytes); generate one with: head -c 32 /dev/urandom | base64")
	}
	// Accept padded or unpadded standard base64.
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil {
		return nil, errors.New("CCLIENTS_DB_KEY is not valid base64")
	}
	if len(key) != DBKeyLen {
		return nil, fmt.Errorf("CCLIENTS_DB_KEY must decode to %d bytes, got %d", DBKeyLen, len(key))
	}
	return key, nil
}

func parseDuration(key, def string) (time.Duration, error) {
	raw := getenv(key, def)
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid duration: %q", key, raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %q", key, raw)
	}
	return d, nil
}

func parseUint32(key string, def uint32) (uint32, error) {
	raw := getenv(key, strconv.FormatUint(uint64(def), 10))
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s is not a non-negative integer: %q", key, raw)
	}
	if n == 0 {
		return 0, fmt.Errorf("%s must be positive, got %q", key, raw)
	}
	return uint32(n), nil
}

func parseBool(key string, def bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean, got %q", key, raw)
	}
	return b, nil
}

func parseLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(raw) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("CCLIENTS_LOG_LEVEL must be one of debug|info|warn|error, got %q", raw)
	}
}
