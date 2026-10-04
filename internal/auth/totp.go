package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// totpPeriod and totpDigits are fixed by S4 (RFC 6238, SHA-1, 6 digits, 30 s).
const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // accept the previous and next step
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh 160-bit secret encoded as unpadded base32.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: read totp secret: %w", err)
	}
	return b32.EncodeToString(b), nil
}

// TOTPCode returns the code for secret at time t. It is exported for tests.
func TOTPCode(secret string, t time.Time) (string, error) {
	return hotp(secret, uint64(t.Unix()/totpPeriod))
}

// ValidateTOTP reports whether code is valid for secret at time t, allowing one
// step of drift in either direction.
func ValidateTOTP(secret, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	var ok bool
	for _, step := range []int64{-totpSkew, 0, totpSkew} {
		counter := uint64(int64(t.Unix()/totpPeriod) + step)
		want, err := hotp(secret, counter)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			ok = true
		}
	}
	return ok
}

// OTPAuthURL builds the otpauth:// URI an authenticator app can scan or key in
// by hand. The issuer and account are escaped; the secret is base32.
func OTPAuthURL(issuer, account, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func hotp(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("auth: decode totp secret: %w", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	value %= 1_000_000
	return fmt.Sprintf("%0*d", totpDigits, value), nil
}
