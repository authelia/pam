package main

import (
	"bufio"
	"fmt"
	"log"
	"log/syslog"
	"net/url"
	"os"
	"strings"

	"github.com/authelia/pam/internal/authelia"
	"github.com/authelia/pam/internal/config"
	"github.com/authelia/pam/internal/protocol"
	"github.com/authelia/pam/internal/qr"
)

// maxVerificationURLLength bounds the verification URL before QR rendering; sits
// below the 2953-byte byte-mode QR v40 limit.
const maxVerificationURLLength = 2048

// setupLogging routes the standard log package through syslog (LOG_AUTH), the
// canonical channel for PAM modules — sshd closes stderr after log_init so this
// is the only path that reliably reaches journald. Falls back to prefixed stderr.
func setupLogging() {
	log.SetFlags(0)

	if w, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "pam_authelia"); err == nil {
		log.SetOutput(w)

		return
	}

	log.SetPrefix("pam_authelia: ")
}

func main() {
	setupLogging()

	if err := run(); err != nil {
		log.Printf("%v", err)
		os.Exit(1)
	}
}

// genericAuthFailure is the user-visible message for all auth failures; detail
// stays in the debug log to avoid leaking server state to the SSH client.
const genericAuthFailure = "Authentication failed."

func run() error {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	client, err := authelia.NewClient(authelia.Options{
		URL:        cfg.URL,
		CookieName: cfg.CookieName,
		CACert:     cfg.CACert,
		Timeout:    cfg.Timeout,
		Debug:      cfg.Debug,
	})
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	client.Debugf("parsed config: url=%s auth-level=%d cookie-name=%s method-priority=%q oauth2-client-id=%q oauth2-scope=%q",
		cfg.URL, cfg.AuthLevel, cfg.CookieName,
		strings.Join(cfg.MethodPriority, ","),
		cfg.OAuth2ClientID,
		strings.ReplaceAll(cfg.OAuth2Scope, " ", ","))

	reader := bufio.NewReader(os.Stdin)
	writer := os.Stdout

	username, err := protocol.ReadLine(reader)
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	if username == "" {
		return writeFailure(client, writer, "empty username received from shim", genericAuthFailure)
	}

	password, err := protocol.ReadLine(reader)
	if err != nil {
		return writeFailure(client, writer, fmt.Sprintf("failed to read password from shim: %v", err), genericAuthFailure)
	}

	// Device flow is self-contained; when it's first in priority, skip 1FA + user info.
	if len(cfg.MethodPriority) > 0 && cfg.MethodPriority[0] == authelia.MethodDeviceAuth && cfg.OAuth2ClientID != "" {
		if err = performDeviceAuth(cfg, client, reader, writer); err != nil {
			return writeFailure(client, writer, err.Error(), genericAuthFailure)
		}

		return protocol.WriteSuccess(writer)
	}

	if err = client.FirstFactor(username, password); err != nil {
		return writeFailure(client, writer, fmt.Sprintf("first factor failed: %v", err), genericAuthFailure)
	}

	if cfg.AuthLevel == config.AuthLevel1FA {
		return protocol.WriteSuccess(writer)
	}

	userInfo, err := client.UserInfo()
	if err != nil {
		return writeFailure(client, writer, fmt.Sprintf("user info fetch failed: %v", err), genericAuthFailure)
	}

	if err = performSecondFactor(cfg, client, userInfo, reader, writer); err != nil {
		return writeFailure(client, writer, err.Error(), genericAuthFailure)
	}

	return protocol.WriteSuccess(writer)
}

// pickSecondFactorMethod returns the first usable method from cfg.MethodPriority,
// falling back to the user's Authelia preference when the priority list is empty.
func pickSecondFactorMethod(cfg *config.Config, client *authelia.Client, userInfo *authelia.UserInfoResponse) (string, error) {
	priority := cfg.MethodPriority
	if len(priority) == 0 {
		priority = []string{authelia.MethodUser}
	}

	for _, m := range priority {
		resolved := resolveMethod(m, cfg, userInfo)
		if resolved != "" && methodUsable(resolved, cfg, userInfo) {
			client.Debugf("selected %q (from priority entry %q)", resolved, m)

			return resolved, nil
		}

		client.Debugf("method %q not usable for user, trying next", m)
	}

	return "", fmt.Errorf("no usable 2FA method for this user")
}

// resolveMethod maps a priority entry to a concrete 2FA method. "user" resolves
// to the user's Authelia preference; webauthn falls back to TOTP/Duo/device flow
// since it cannot respond over SSH.
func resolveMethod(entry string, cfg *config.Config, userInfo *authelia.UserInfoResponse) string {
	if entry != authelia.MethodUser {
		return entry
	}

	pref := userInfo.Method
	if pref == authelia.MethodWebAuthn || pref == "" {
		switch {
		case userInfo.HasTOTP:
			return authelia.MethodTOTP
		case userInfo.HasDuo:
			return authelia.MethodMobilePush
		case cfg.OAuth2ClientID != "":
			return authelia.MethodDeviceAuth
		default:
			return ""
		}
	}

	return pref
}

// methodUsable reports whether the given method can be used for the current user.
func methodUsable(method string, cfg *config.Config, userInfo *authelia.UserInfoResponse) bool {
	switch method {
	case authelia.MethodTOTP:
		return userInfo.HasTOTP
	case authelia.MethodMobilePush:
		return userInfo.HasDuo
	case authelia.MethodDeviceAuth:
		return cfg.OAuth2ClientID != ""
	default:
		return false
	}
}

func performSecondFactor(cfg *config.Config, client *authelia.Client, userInfo *authelia.UserInfoResponse, reader *bufio.Reader, writer *os.File) error {
	method, err := pickSecondFactorMethod(cfg, client, userInfo)
	if err != nil {
		return err
	}

	switch method {
	case authelia.MethodTOTP:
		return performTOTP(client, reader, writer)
	case authelia.MethodMobilePush:
		return performDuoPush(client, writer)
	case authelia.MethodDeviceAuth:
		return performDeviceAuth(cfg, client, reader, writer)
	default:
		return fmt.Errorf("unsupported 2FA method: %s", method)
	}
}

func performTOTP(client *authelia.Client, reader *bufio.Reader, writer *os.File) error {
	if err := protocol.WritePromptVisible(writer, "TOTP Code: "); err != nil {
		return err
	}

	token, err := protocol.ReadLine(reader)
	if err != nil {
		return fmt.Errorf("failed to read TOTP code")
	}

	token = strings.TrimSpace(token)

	n := len(token)
	if n != 6 && n != 8 {
		return fmt.Errorf("TOTP code must be 6 or 8 digits")
	}

	return client.SecondFactorTOTP(token)
}

// performDeviceAuth runs the OAuth2 device-authorization flow. The QR is sent
// via PAM_PROMPT_ECHO_ON to bypass BSD vis(3) sanitisation of PAM_TEXT_INFO;
// the user must press Enter after approving before polling resumes.
func performDeviceAuth(cfg *config.Config, client *authelia.Client, reader *bufio.Reader, writer *os.File) error {
	if cfg.OAuth2ClientID == "" {
		return fmt.Errorf("device authorization requires --oauth2-client-id")
	}

	resp, err := client.DeviceAuthorize(cfg.OAuth2ClientID, cfg.OAuth2ClientSecret, cfg.OAuth2Scope)
	if err != nil {
		return fmt.Errorf("failed to initiate device authorization: %w", err)
	}

	verification := resp.VerificationURIComplete
	if verification == "" {
		verification = resp.VerificationURI
	}

	if err := validateVerificationURL(verification, cfg.URL); err != nil {
		client.Debugf("verification URL rejected: %v", err)

		return fmt.Errorf("device authorization returned an invalid verification URL")
	}

	var body strings.Builder

	body.WriteString("Scan the QR code below or visit the URL to approve.\n")
	body.WriteString(verification)
	body.WriteByte('\n')

	if qrCode, err := qr.Render(verification); err == nil {
		body.WriteByte('\n')
		body.WriteString(strings.TrimRight(qrCode, "\n"))
		body.WriteByte('\n')
	}

	body.WriteString("\nApprove on your device, then press Enter.")

	if err := protocol.WritePromptMultiVisible(writer, body.String()); err != nil {
		return err
	}

	if _, err := protocol.ReadLine(reader); err != nil {
		return fmt.Errorf("failed to read device-auth prompt response: %w", err)
	}

	return client.PollDeviceToken(cfg.OAuth2ClientID, cfg.OAuth2ClientSecret, resp.DeviceCode, resp.ExpiresIn, resp.Interval)
}

// validateVerificationURL requires the URL to be https, under the configured
// Authelia host, and within maxVerificationURLLength — preventing a tampered
// response from phishing the user via an attacker-controlled QR target.
func validateVerificationURL(raw string, expected *url.URL) error {
	if raw == "" {
		return fmt.Errorf("empty URL")
	}

	if len(raw) > maxVerificationURLLength {
		return fmt.Errorf("URL length %d exceeds max %d", len(raw), maxVerificationURLLength)
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf("scheme %q is not https", parsed.Scheme)
	}

	if !strings.EqualFold(parsed.Host, expected.Host) {
		return fmt.Errorf("host %q does not match configured %q", parsed.Host, expected.Host)
	}

	return nil
}

func performDuoPush(client *authelia.Client, writer *os.File) error {
	if err := protocol.WriteInfo(writer, "Duo Push sent, approve on your device."); err != nil {
		return err
	}

	return client.SecondFactorDuoPush()
}

// writeFailure logs the full internal message via syslog and sends only
// userFacing over the protocol pipe. Returned error carries the internal detail
// for propagation.
func writeFailure(client *authelia.Client, writer *os.File, internal, userFacing string) error {
	log.Printf("%s", internal)

	if client != nil {
		client.Debugf("failure: %s", internal)
	}

	_ = protocol.WriteFailure(writer, userFacing)

	return fmt.Errorf("%s", internal)
}
