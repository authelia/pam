package authelia

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RFC 8628 token endpoint polling error codes.
const (
	deviceAuthorizationPending = "authorization_pending"
	deviceSlowDown             = "slow_down"
	deviceAccessDenied         = "access_denied"
	deviceExpiredToken         = "expired_token"
)

// RFC 8628 §3.5 polling backoff.
const (
	defaultPollInterval = 5 * time.Second
	slowDownIncrement   = 5 * time.Second
)

type pollOutcome int

const (
	pollPending pollOutcome = iota
	pollSlowDown
	pollTimeout
)

// DeviceAuthorizationResponse is the RFC 8628 Device Authorization endpoint response.
type DeviceAuthorizationResponse struct {
	DeviceCode              string    `json:"device_code"`
	UserCode                string    `json:"user_code"`
	VerificationURI         string    `json:"verification_uri"`
	VerificationURIComplete string    `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int       `json:"expires_in"`
	Interval                int       `json:"interval"`
	IssuedAt                time.Time `json:"-"`
}

// DeviceAuthorize initiates an OAuth2 Device Authorization Grant flow.
func (c *Client) DeviceAuthorize(clientID, clientSecret, scope string) (*DeviceAuthorizationResponse, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", scope)

	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	c.Debugf("POST %s/api/oidc/device-authorization", c.baseURL)

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/oidc/device-authorization", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create device authorization request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device authorization request failed: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	if err != nil {
		return nil, fmt.Errorf("failed to read device authorization response: %w", err)
	}

	c.Debugf("device authorization response status=%d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device authorization returned status %d", resp.StatusCode)
	}

	var result DeviceAuthorizationResponse
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode device authorization response: %w", err)
	}

	result.IssuedAt = c.now()

	return &result, nil
}

// DeviceTokenResponse is the token endpoint response for the device flow.
type DeviceTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
}

// PollDeviceToken polls the token endpoint until approved, denied, or expired, following the RFC 8628 §3.5 backoff.
// The first poll runs immediately since the user has usually approved before pressing Enter; every later poll waits
// the interval in force, which starts at the server's interval, grows by 5 seconds with each slow_down, and doubles
// with each connection timeout. Expiry is measured from when the device authorization response was received, and
// polling stops as soon as the next poll would fall after it.
func (c *Client) PollDeviceToken(clientID, clientSecret string, auth *DeviceAuthorizationResponse) (accessToken, idToken string, err error) {
	if auth == nil {
		return "", "", errors.New("missing device authorization response")
	}

	interval := time.Duration(auth.Interval) * time.Second
	if interval <= 0 {
		interval = defaultPollInterval
	}

	issuedAt := auth.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = c.now()
	}

	deadline := issuedAt.Add(time.Duration(auth.ExpiresIn) * time.Second)

	for first := true; ; first = false {
		if !first {
			if c.now().Add(interval).After(deadline) {
				return "", "", errors.New("device authorization expired before user approval")
			}

			c.sleep(interval)
		}

		result, outcome, err := c.pollDeviceTokenOnce(clientID, clientSecret, auth.DeviceCode)
		if err != nil {
			return "", "", err
		}

		if result != nil {
			return result.AccessToken, result.IDToken, nil
		}

		switch outcome {
		case pollSlowDown:
			interval += slowDownIncrement

			c.Debugf("device token poll told to slow down, polling interval is now %s", interval)
		case pollTimeout:
			interval *= 2

			c.Debugf("device token poll timed out, polling interval is now %s", interval)
		}
	}
}

func (c *Client) pollDeviceTokenOnce(clientID, clientSecret, deviceCode string) (result *DeviceTokenResponse, outcome pollOutcome, err error) {
	c.Debugf("POST %s/api/oidc/token", c.baseURL)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("client_id", clientID)
	form.Set("device_code", deviceCode)

	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, pollPending, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		// RFC 8628 §3.5: a connection timeout MUST reduce the polling frequency before retrying.
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			c.Debugf("device token request timed out: %v", err)

			return nil, pollTimeout, nil
		}

		return nil, pollPending, fmt.Errorf("token request failed: %w", err)
	}

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	_ = resp.Body.Close()

	var parsed DeviceTokenResponse

	_ = json.Unmarshal(data, &parsed)

	c.Debugf("device token response status=%d error=%q", resp.StatusCode, parsed.Error)

	if resp.StatusCode == http.StatusOK && parsed.AccessToken != "" {
		return &parsed, pollPending, nil
	}

	switch parsed.Error {
	case deviceAuthorizationPending:
		return nil, pollPending, nil
	case deviceSlowDown:
		return nil, pollSlowDown, nil
	case deviceAccessDenied:
		return nil, pollPending, errors.New("device authorization denied by user")
	case deviceExpiredToken:
		return nil, pollPending, errors.New("device authorization token expired")
	default:
		if parsed.Error != "" {
			return nil, pollPending, fmt.Errorf("device token error: %s", parsed.Error)
		}

		return nil, pollPending, fmt.Errorf("device token request returned status %d", resp.StatusCode)
	}
}
