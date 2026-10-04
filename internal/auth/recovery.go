package auth

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// RecoveryCodeCount is the number of single-use recovery codes generated at
// TOTP enrollment (F1.5).
const RecoveryCodeCount = 10

// NewRecoveryCodes returns RecoveryCodeCount fresh codes in display form
// (e.g. "ABCD-EFGH-IJKL-MNOP"). They are high-entropy (10 random bytes each),
// shown once, and only ever stored as hashes.
func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
		codes[i] = groupCode(raw)
	}
	return codes, nil
}

// NormalizeRecoveryCode uppercases a code and strips separators so entry and
// storage agree.
func NormalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
}

// HashRecoveryCode returns an Argon2id PHC string for the normalized code.
func HashRecoveryCode(p Params, code string) (string, error) {
	return HashPassword(p, NormalizeRecoveryCode(code))
}

// VerifyRecoveryCode reports whether code matches the encoded hash.
func VerifyRecoveryCode(encoded, code string) bool {
	normalized := NormalizeRecoveryCode(code)
	if normalized == "" {
		return false
	}
	return VerifyPassword(encoded, normalized)
}

func groupCode(raw string) string {
	var b strings.Builder
	for i, r := range raw {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}
