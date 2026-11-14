package authelia

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// 2FA method identifiers accepted in --method-priority.
const (
	MethodTOTP       = "totp"
	MethodWebAuthn   = "webauthn"
	MethodMobilePush = "mobile_push"
	MethodDeviceAuth = "device_authorization"
	// MethodUser resolves at runtime to the user's Authelia preference.
	MethodUser = "user"
)

// Cookie name prefixes and suffixes used by Authelia 4.40+ for the portal API.
const (
	cookiePrefixHost     = "__Host-"
	cookiePrefixHostHTTP = "__Host-Http-"
	cookieSuffixCSRF     = "_csrf"

	// HeaderCSRFToken carries the CSRF token on state-changing requests.
	HeaderCSRFToken = "X-CSRF-Token"
)

// Client handles HTTP communication with the Authelia server.
type Client struct {
	client            *http.Client
	baseURL           string
	cookieName        string
	sessionCookieName string
	sessionCookie     string
	csrfToken         string
	debug             bool
}

// Options configures a Client.
type Options struct {
	URL        *url.URL
	CookieName string
	CACert     string
	Timeout    time.Duration
	Debug      bool
}

// UserInfoResponse represents the response from the user info endpoint.
type UserInfoResponse struct {
	DisplayName string `json:"display_name"`
	Method      string `json:"method"`
	HasTOTP     bool   `json:"has_totp"`
	HasWebAuthn bool   `json:"has_webauthn"`
	HasDuo      bool   `json:"has_duo"`
}

type apiResponse struct {
	Status string `json:"status"`
}

// NewClient creates a new client for the Authelia API.
func NewClient(opts Options) (*Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	if opts.CACert != "" {
		caCert, err := os.ReadFile(opts.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		pool := x509.NewCertPool()

		if !pool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}

		transport.TLSClientConfig.RootCAs = pool
	}

	return &Client{
		client: &http.Client{
			Timeout:   opts.Timeout,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL:    strings.TrimRight(opts.URL.String(), "/"),
		cookieName: opts.CookieName,
		debug:      opts.Debug,
	}, nil
}

// FirstFactor performs first-factor authentication and stores the session cookie
// and CSRF token.
func (c *Client) FirstFactor(username, password string) error {
	body := map[string]string{
		"username": username,
		"password": password,
	}

	resp, err := c.postJSON("/api/firstfactor", body)
	if err != nil {
		return fmt.Errorf("first factor request failed: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	c.extractCookies(resp)

	return c.checkResponse(resp, "first factor authentication failed")
}

// UserInfo retrieves the user's 2FA method information.
func (c *Client) UserInfo() (*UserInfoResponse, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/api/user/info", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("user info request failed: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request returned status %d", resp.StatusCode)
	}

	c.extractCookies(resp)

	var info UserInfoResponse

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %w", err)
	}

	var envelope struct {
		Status string           `json:"status"`
		Data   UserInfoResponse `json:"data"`
	}

	if err = json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}

	info = envelope.Data

	c.Debugf("user info method=%q has_totp=%v has_webauthn=%v has_duo=%v",
		info.Method, info.HasTOTP, info.HasWebAuthn, info.HasDuo)

	return &info, nil
}

// SecondFactorTOTP performs TOTP second-factor authentication.
func (c *Client) SecondFactorTOTP(token string) error {
	body := map[string]string{
		"token": token,
	}

	resp, err := c.postJSON("/api/secondfactor/totp", body)
	if err != nil {
		return fmt.Errorf("TOTP request failed: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	c.extractCookies(resp)

	return c.checkResponse(resp, "TOTP authentication failed")
}

// SecondFactorDuoPush performs Duo push 2FA; blocks until the user responds or
// the server-side request times out.
func (c *Client) SecondFactorDuoPush() error {
	body := map[string]string{}

	resp, err := c.postJSON("/api/secondfactor/duo", body)
	if err != nil {
		return fmt.Errorf("duo push request failed: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	c.extractCookies(resp)

	return c.checkResponse(resp, "duo push authentication failed")
}

func (c *Client) postJSON(path string, body any) (*http.Response, error) {
	c.Debugf("POST %s%s", c.baseURL, path)

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	if c.csrfToken != "" {
		req.Header.Set(HeaderCSRFToken, c.csrfToken)
	}

	return c.client.Do(req)
}

func (c *Client) setHeaders(req *http.Request) {
	if c.sessionCookie != "" && c.sessionCookieName != "" {
		req.AddCookie(&http.Cookie{
			Name:  c.sessionCookieName,
			Value: c.sessionCookie,
		})
	}
}

func (c *Client) sessionCookieNames() (prefixed, bare string) {
	return cookiePrefixHostHTTP + c.cookieName, c.cookieName
}

func (c *Client) csrfCookieName() string {
	return cookiePrefixHost + c.cookieName + cookieSuffixCSRF
}

func (c *Client) extractCookies(resp *http.Response) {
	prefixedName, bareName := c.sessionCookieNames()
	csrfName := c.csrfCookieName()

	var prefixed, bare, csrf *http.Cookie

	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case prefixedName:
			prefixed = cookie
		case bareName:
			bare = cookie
		case csrfName:
			csrf = cookie
		}
	}

	now := time.Now()

	for _, cookie := range []*http.Cookie{bare, prefixed} {
		if cookie != nil && isDeletionCookie(cookie, now) && c.sessionCookieName == cookie.Name {
			c.Debugf("session cookie %q deleted by server", cookie.Name)

			c.sessionCookie, c.sessionCookieName = "", ""
		}
	}

	switch {
	case prefixed != nil && !isDeletionCookie(prefixed, now):
		c.setSessionCookie(prefixed)
	case bare != nil && !isDeletionCookie(bare, now):
		c.setSessionCookie(bare)
	}

	if csrf != nil {
		if isDeletionCookie(csrf, now) {
			c.Debugf("csrf cookie %q deleted by server", csrf.Name)

			c.csrfToken = ""
		} else {
			c.Debugf("stored csrf token from cookie %q", csrf.Name)

			c.csrfToken = csrf.Value
		}
	}
}

func (c *Client) setSessionCookie(cookie *http.Cookie) {
	c.Debugf("stored session cookie %q", cookie.Name)

	c.sessionCookieName = cookie.Name
	c.sessionCookie = cookie.Value
}

func isDeletionCookie(cookie *http.Cookie, now time.Time) bool {
	return cookie.Value == "" || cookie.MaxAge < 0 ||
		(cookie.MaxAge == 0 && !cookie.Expires.IsZero() && cookie.Expires.Before(now))
}

// Debugf emits a debug message via the standard log package (routed to syslog
// at program start by setupLogging). Never write to stdout — it is the protocol
// channel to the C shim.
func (c *Client) Debugf(format string, args ...any) {
	if !c.debug {
		return
	}

	log.Printf(format, args...)
}

func (c *Client) checkResponse(resp *http.Response, failMsg string) error {
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var result apiResponse

	_ = json.Unmarshal(data, &result)

	c.Debugf("response status=%d status_field=%q", resp.StatusCode, result.Status)

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return errors.New("rate limited by Authelia server, try again later")
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return errors.New(failMsg)
	case resp.StatusCode >= http.StatusBadRequest:
		return fmt.Errorf("%s (status %d)", failMsg, resp.StatusCode)
	}

	if result.Status == "" {
		return fmt.Errorf("failed to parse response")
	}

	if result.Status != "OK" {
		return errors.New(failMsg)
	}

	return nil
}
