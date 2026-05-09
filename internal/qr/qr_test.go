package qr

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	out, err := Render("https://auth.example.com/consent/openid/device-authorization?user_code=ABCDEFGH")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out == "" {
		t.Fatal("expected non-empty QR output")
	}

	if !strings.ContainsAny(out, "\u2580\u2584\u2588 ") {
		t.Errorf("expected output to contain block glyphs or spaces; got %q", out[:min(40, len(out))])
	}

	if !strings.Contains(out, "\n") {
		t.Error("expected multi-line output")
	}
}

func TestRenderEmpty(t *testing.T) {
	// Empty payload is not a useful QR, but it should not panic — the underlying
	// library may or may not return an error. We only assert no panic.
	_, _ = Render("")
}

func min(a, b int) int {
	if a < b {
		return a
	}

	return b
}
