package web

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"
)

func TestQRPNGDataURI(t *testing.T) {
	const payload = "otpauth://totp/Acme:admin?secret=JBSWY3DPEHPK3PXP&issuer=Acme"
	uri := qrPNG(payload)

	const prefix = "data:image/png;base64,"
	s := string(uri)
	if !strings.HasPrefix(s, prefix) {
		t.Fatalf("qrPNG = %q, want a PNG data URI", s)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("png decode: %v", err)
	}
	if b := img.Bounds(); b.Dx() != b.Dy() || b.Dx() < 100 {
		t.Fatalf("qr image = %dx%d, want square and at least 100px", b.Dx(), b.Dy())
	}

	if uri == qrPNG("otpauth://totp/Other:bob?secret=KRSXG5CTMVRXEZLU") {
		t.Fatal("different payloads produced the same QR image")
	}
}
