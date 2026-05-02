package config

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/authelia/pam/internal/authelia"
)

// AuthLevel represents the authentication level required.
type AuthLevel int

const (
	// AuthLevel1FA requires only first-factor authentication.
	AuthLevel1FA AuthLevel = iota

	// AuthLevel2FA requires second-factor only; 1FA is performed silently via the PAM stack password.
	AuthLevel2FA

	// AuthLevel1FA2FA requires both first-factor and second-factor authentication.
	AuthLevel1FA2FA
)

// Config holds the configuration for the pam_authelia binary.
type Config struct {
	URL                *url.URL
	AuthLevel          AuthLevel
	CookieName         string
	CACert             string
	Timeout            time.Duration
	Debug              bool
	MethodPriority     []string
	OAuth2ClientID     string
	OAuth2ClientSecret string
	OAuth2Scope        string
}

// Parse parses CLI flags into a Config.
func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("pam_authelia", flag.ContinueOnError)

	var (
		rawURL             string
		authLevel          string
		cookieName         string
		caCert             string
		timeout            int
		debug              bool
		methodPriority     string
		oauth2ClientID     string
		oauth2ClientSecret string
		oauth2Scope        string
	)

	fs.StringVar(&rawURL, "url", "", "Authelia server URL (required)")
	fs.StringVar(&authLevel, "auth-level", "1FA+2FA", "Authentication level: 1FA, 2FA, or 1FA+2FA")
	fs.StringVar(&cookieName, "cookie-name", "authelia_session", "Session cookie name")
	fs.StringVar(&caCert, "ca-cert", "", "Path to custom CA certificate for TLS verification")
	fs.IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")
	fs.BoolVar(&debug, "debug", false, "Enable debug logging to stderr")
	fs.StringVar(&methodPriority, "method-priority", "", "Comma-separated 2FA methods to try in order (overrides user preference): totp,mobile_push,device_authorization,user")
	fs.StringVar(&oauth2ClientID, "oauth2-client-id", "", "OAuth2 client ID for Device Authorization grant fallback")
	fs.StringVar(&oauth2ClientSecret, "oauth2-client-secret", "", "OAuth2 client secret for confidential clients")
	fs.StringVar(&oauth2Scope, "oauth2-scope", "openid,authelia.pam", "Comma-separated OAuth2 scopes to request for Device Authorization")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if rawURL == "" {
		return nil, errors.New("--url is required")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("URL scheme must be https, got %q", parsed.Scheme)
	}

	level, err := parseAuthLevel(authLevel)
	if err != nil {
		return nil, err
	}

	if timeout <= 0 {
		return nil, errors.New("--timeout must be positive")
	}

	priority, err := parseMethodPriority(methodPriority)
	if err != nil {
		return nil, err
	}

	for _, m := range priority {
		if m == authelia.MethodDeviceAuth && oauth2ClientID == "" {
			return nil, errors.New("--method-priority includes device_authorization but --oauth2-client-id is not set")
		}
	}

	scope, err := parseOAuth2Scope(oauth2Scope)
	if err != nil {
		return nil, err
	}

	return &Config{
		URL:                parsed,
		AuthLevel:          level,
		CookieName:         cookieName,
		CACert:             caCert,
		Timeout:            time.Duration(timeout) * time.Second,
		Debug:              debug,
		MethodPriority:     priority,
		OAuth2ClientID:     oauth2ClientID,
		OAuth2ClientSecret: oauth2ClientSecret,
		OAuth2Scope:        scope,
	}, nil
}

func parseOAuth2Scope(raw string) (string, error) {
	parts := strings.Split(raw, ",")
	scopes := make([]string, 0, len(parts))

	var hasOpenID, hasPAMScope bool

	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			scopes = append(scopes, p)

			switch p {
			case "openid":
				hasOpenID = true
			case authelia.PAMScope:
				hasPAMScope = true
			}
		}
	}

	if len(scopes) == 0 {
		return "", errors.New("--oauth2-scope must not be empty")
	}

	if !hasOpenID {
		return "", errors.New("--oauth2-scope must include openid (required to verify the device-flow identity)")
	}

	if !hasPAMScope {
		return "", fmt.Errorf("--oauth2-scope must include %s (grants the %s claim used to bind the device flow)", authelia.PAMScope, authelia.PAMUsernameClaim)
	}

	return strings.Join(scopes, " "), nil
}

func parseMethodPriority(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	priority := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		switch p {
		case authelia.MethodTOTP, authelia.MethodMobilePush, authelia.MethodDeviceAuth, authelia.MethodUser:
			priority = append(priority, p)
		default:
			return nil, fmt.Errorf("invalid method %q in --method-priority: must be %s, %s, %s, or %s", p, authelia.MethodTOTP, authelia.MethodMobilePush, authelia.MethodDeviceAuth, authelia.MethodUser)
		}
	}

	return priority, nil
}

func parseAuthLevel(s string) (AuthLevel, error) {
	switch s {
	case "1FA":
		return AuthLevel1FA, nil
	case "2FA":
		return AuthLevel2FA, nil
	case "1FA+2FA":
		return AuthLevel1FA2FA, nil
	default:
		return 0, fmt.Errorf("invalid auth level %q: must be 1FA, 2FA, or 1FA+2FA", s)
	}
}
