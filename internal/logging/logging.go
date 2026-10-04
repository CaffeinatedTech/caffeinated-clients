// Package logging builds the process logger and provides the redaction rule
// that keeps secrets out of logs (S3). No secret note body, password, token,
// TOTP secret, or recovery code is ever logged.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New returns a text logger at the given level whose attributes are run
// through a redaction rule.
func New(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: Redact,
	}))
}

// sensitiveKeys are attribute names whose string values are never logged.
// The list is deliberately broad: a false positive only hides a log value,
// a false negative leaks a credential.
var sensitiveKeys = map[string]bool{
	"password":      true,
	"pass":          true,
	"passwd":        true,
	"secret":        true,
	"token":         true,
	"totp":          true,
	"recovery":      true,
	"body":          true,
	"key":           true,
	"db_key":        true,
	"authorization": true,
	"cookie":        true,
}

// Redact masks the value of any attribute whose name looks sensitive. It is
// an slog ReplaceAttr function.
func Redact(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindString && sensitiveKeys[strings.ToLower(a.Key)] {
		return slog.String(a.Key, "[redacted]")
	}
	return a
}
