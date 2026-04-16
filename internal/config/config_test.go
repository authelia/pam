package config

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		wantLevel AuthLevel
		wantURL   string
	}{
		{
			name:      "valid full config",
			args:      []string{"--url", "https://auth.example.com", "--auth-level", "1FA+2FA", "--cookie-name", "my_session", "--timeout", "60"},
			wantErr:   false,
			wantLevel: AuthLevel1FA2FA,
			wantURL:   "https://auth.example.com",
		},
		{
			name:      "valid 1fa only",
			args:      []string{"--url", "https://auth.example.com", "--auth-level", "1FA"},
			wantErr:   false,
			wantLevel: AuthLevel1FA,
		},
		{
			name:      "valid 2fa only",
			args:      []string{"--url", "https://auth.example.com", "--auth-level", "2FA"},
			wantErr:   false,
			wantLevel: AuthLevel2FA,
		},
		{
			name:      "defaults",
			args:      []string{"--url", "https://auth.example.com"},
			wantErr:   false,
			wantLevel: AuthLevel1FA2FA,
		},
		{
			name:    "missing url",
			args:    []string{"--auth-level", "1FA"},
			wantErr: true,
		},
		{
			name:    "http not allowed",
			args:    []string{"--url", "http://auth.example.com"},
			wantErr: true,
		},
		{
			name:    "invalid auth level",
			args:    []string{"--url", "https://auth.example.com", "--auth-level", "3FA"},
			wantErr: true,
		},
		{
			name:    "invalid timeout",
			args:    []string{"--url", "https://auth.example.com", "--timeout", "0"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if cfg.AuthLevel != tt.wantLevel {
				t.Errorf("AuthLevel = %v, want %v", cfg.AuthLevel, tt.wantLevel)
			}

			if tt.wantURL != "" && cfg.URL.String() != tt.wantURL {
				t.Errorf("URL = %v, want %v", cfg.URL.String(), tt.wantURL)
			}
		})
	}
}

func TestParseOAuth2Scope(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"default", "openid,authelia.pam", "openid authelia.pam", false},
		{"with profile", "openid,profile,authelia.pam", "openid profile authelia.pam", false},
		{"many", "openid,profile,email,groups,authelia.pam", "openid profile email groups authelia.pam", false},
		{"trimmed whitespace", " openid , authelia.pam ", "openid authelia.pam", false},
		{"repeated commas", "openid,,,authelia.pam", "openid authelia.pam", false},
		{"missing openid", "profile,authelia.pam", "", true},
		{"missing pam scope", "openid", "", true},
		{"missing pam scope with profile", "openid,profile", "", true},
		{"missing both", "profile,email", "", true},
		{"empty", "", "", true},
		{"only commas", ",,,", "", true},
		{"only whitespace", "   ", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOAuth2Scope(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseOAuth2Scope(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}

			if !tt.wantErr && got != tt.want {
				t.Errorf("parseOAuth2Scope(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseMethodPriority(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"single totp", "totp", []string{"totp"}, false},
		{"multi", "device_authorization,user", []string{"device_authorization", "user"}, false},
		{"trimmed", " totp , user ", []string{"totp", "user"}, false},
		{"invalid method", "totp,bogus", nil, true},
		{"unknown only", "nope", nil, true},
		{"all valid", "totp,mobile_push,device_authorization,user", []string{"totp", "mobile_push", "device_authorization", "user"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMethodPriority(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseMethodPriority(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if len(got) != len(tt.want) {
				t.Fatalf("parseMethodPriority(%q) len = %d, want %d (%v vs %v)", tt.in, len(got), len(tt.want), got, tt.want)
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseAuthLevel(t *testing.T) {
	tests := []struct {
		in      string
		want    AuthLevel
		wantErr bool
	}{
		{"1FA", AuthLevel1FA, false},
		{"2FA", AuthLevel2FA, false},
		{"1FA+2FA", AuthLevel1FA2FA, false},
		{"1fa", 0, true},
		{"", 0, true},
		{"3FA", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseAuthLevel(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAuthLevel(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}

			if !tt.wantErr && got != tt.want {
				t.Errorf("parseAuthLevel(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]string{"--url", "https://auth.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.CookieName != "authelia_session" {
		t.Errorf("CookieName = %q, want %q", cfg.CookieName, "authelia_session")
	}

	if cfg.Timeout.Seconds() != 30 {
		t.Errorf("Timeout = %v, want 30s", cfg.Timeout)
	}

	if cfg.CACert != "" {
		t.Errorf("CACert = %q, want empty", cfg.CACert)
	}

	if cfg.OAuth2Scope != "openid authelia.pam" {
		t.Errorf("OAuth2Scope = %q, want %q", cfg.OAuth2Scope, "openid authelia.pam")
	}
}
