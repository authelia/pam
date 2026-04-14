package main

import (
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()

	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}

	return u
}

func TestValidateVerificationURL(t *testing.T) {
	authelia := mustURL(t, "https://auth.example.com")

	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{
			name: "matching host",
			raw:  "https://auth.example.com/consent/openid/device-authorization?user_code=ABCD1234",
		},
		{
			name: "matching host, case-insensitive",
			raw:  "https://AUTH.example.com/consent",
		},
		{
			name:    "empty",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "http scheme",
			raw:     "http://auth.example.com/consent",
			wantErr: true,
		},
		{
			name:    "different host",
			raw:     "https://evil.example.com/consent",
			wantErr: true,
		},
		{
			name:    "subdomain spoof",
			raw:     "https://auth.example.com.evil.io/consent",
			wantErr: true,
		},
		{
			name:    "javascript scheme",
			raw:     "javascript:alert(1)",
			wantErr: true,
		},
		{
			name:    "huge url",
			raw:     "https://auth.example.com/" + strings.Repeat("a", maxVerificationURLLength),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVerificationURL(tt.raw, authelia)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateVerificationURL(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
		})
	}
}
