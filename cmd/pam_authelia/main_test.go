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
			name: "MatchingHost",
			raw:  "https://auth.example.com/consent/openid/device-authorization?user_code=ABCD1234",
		},
		{
			name: "MatchingHostCaseInsensitive",
			raw:  "https://AUTH.example.com/consent",
		},
		{
			name:    "Empty",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "HTTPScheme",
			raw:     "http://auth.example.com/consent",
			wantErr: true,
		},
		{
			name:    "DifferentHost",
			raw:     "https://evil.example.com/consent",
			wantErr: true,
		},
		{
			name:    "SubdomainSpoof",
			raw:     "https://auth.example.com.evil.io/consent",
			wantErr: true,
		},
		{
			name:    "JavaScriptScheme",
			raw:     "javascript:alert(1)",
			wantErr: true,
		},
		{
			name:    "HugeURL",
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
