package auth

import (
	"testing"
	"time"
)

func testParams() Params {
	return Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword(testParams(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("correct password did not verify")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Fatal("wrong password verified")
	}
	if VerifyPassword("not-a-phc-string", "correct horse battery staple") {
		t.Fatal("malformed hash verified")
	}
}

// RFC 6238 test vectors (SHA-1, truncated to 6 digits).
func TestTOTPWindowsAndVectors(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // ASCII "12345678901234567890"

	cases := map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1234567890: "005924",
	}
	for unix, want := range cases {
		at := time.Unix(unix, 0)
		got, err := TOTPCode(secret, at)
		if err != nil {
			t.Fatalf("TOTPCode(%d): %v", unix, err)
		}
		if got != want {
			t.Errorf("TOTPCode(%d) = %s, want %s", unix, got, want)
		}
		if !ValidateTOTP(secret, got, at) {
			t.Errorf("ValidateTOTP(%d) rejected its own code", unix)
		}
	}

	at := time.Unix(1111111109, 0)
	code, _ := TOTPCode(secret, at)
	if !ValidateTOTP(secret, code, at.Add(30*time.Second)) {
		t.Error("code rejected one step in the future")
	}
	if !ValidateTOTP(secret, code, at.Add(-30*time.Second)) {
		t.Error("code rejected one step in the past")
	}
	if ValidateTOTP(secret, code, at.Add(90*time.Second)) {
		t.Error("code accepted three steps in the future")
	}
	if ValidateTOTP(secret, "000000", at) && code != "000000" {
		t.Error("arbitrary code accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatalf("NewRecoveryCodes: %v", err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), RecoveryCodeCount)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate recovery code %q", c)
		}
		seen[c] = true
		hash, err := HashRecoveryCode(testParams(), c)
		if err != nil {
			t.Fatalf("HashRecoveryCode: %v", err)
		}
		if !VerifyRecoveryCode(hash, c) {
			t.Fatalf("code %q did not verify", c)
		}
		// Separators and case must not matter.
		lower := " " + c + " "
		if !VerifyRecoveryCode(hash, lower) {
			t.Fatalf("code %q did not verify with separators", c)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Unix(1_000_000, 0)
	for i := 0; i < rateMaxFailure; i++ {
		if ok, _ := l.Allow("ip:1.2.3.4", now); !ok {
			t.Fatalf("attempt %d unexpectedly denied", i+1)
		}
		l.Fail("ip:1.2.3.4", now)
	}
	ok, retry := l.Allow("ip:1.2.3.4", now)
	if ok {
		t.Fatal("expected key to be locked after threshold")
	}
	if retry <= 0 {
		t.Fatalf("retry = %v, want positive", retry)
	}
	if ok, _ := l.Allow("ip:9.9.9.9", now); !ok {
		t.Fatal("unrelated key should not be locked")
	}
	l.Reset("ip:1.2.3.4")
	if ok, _ := l.Allow("ip:1.2.3.4", now); !ok {
		t.Fatal("reset key still locked")
	}
	// The window rolls over.
	for i := 0; i < rateMaxFailure; i++ {
		l.Fail("user:acme", now)
	}
	later := now.Add(rateWindow + time.Second)
	if ok, _ := l.Allow("user:acme", later); !ok {
		t.Fatal("key should be allowed after the window")
	}
}
