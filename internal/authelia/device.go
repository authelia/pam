package authelia

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// DeviceAuthorizationResponse is the RFC 8628 Device Authorization endpoint response.
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
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

// maxPollInterval caps the slow_down backoff so a hostile or misbehaving server
// can't stall the auth flow indefinitely.
const maxPollInterval = 60

// PollDeviceToken polls the token endpoint until approved, denied, or expired.
// Honors the server's recommended interval (RFC 8628 §3.5); the first poll runs
// immediately since the user has usually approved before pressing Enter.
func (c *Client) PollDeviceToken(clientID, clientSecret, deviceCode string, expiresIn, interval int) (accessToken, idToken string, err error) {
	if interval <= 0 {
		interval = 5
	}

	if interval > maxPollInterval {
		interval = maxPollInterval
	}

	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)

	for first := true; ; first = false {
		if time.Now().After(deadline) {
			return "", "", errors.New("device authorization expired before user approval")
		}

		if !first {
			time.Sleep(time.Duration(interval) * time.Second)
		}

		result, slowDown, err := c.pollDeviceTokenOnce(clientID, clientSecret, deviceCode)
		if err != nil {
			return "", "", err
		}

		if result != nil {
			return result.AccessToken, result.IDToken, nil
		}

		if slowDown {
			interval += 5
			if interval > maxPollInterval {
				interval = maxPollInterval
			}
		}
	}
}

// pollDeviceTokenOnce makes a single device token request and classifies the
// response. A non-nil result means the grant succeeded; a nil result with no
// error means the caller should keep polling.
func (c *Client) pollDeviceTokenOnce(clientID, clientSecret, deviceCode string) (result *DeviceTokenResponse, slowDown bool, err error) {
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
		return nil, false, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("token request failed: %w", err)
	}

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	_ = resp.Body.Close()

	var parsed DeviceTokenResponse

	_ = json.Unmarshal(data, &parsed)

	c.Debugf("device token response status=%d error=%q", resp.StatusCode, parsed.Error)

	if resp.StatusCode == http.StatusOK && parsed.AccessToken != "" {
		return &parsed, false, nil
	}

	switch parsed.Error {
	case deviceAuthorizationPending:
		return nil, false, nil
	case deviceSlowDown:
		return nil, true, nil
	case deviceAccessDenied:
		return nil, false, errors.New("device authorization denied by user")
	case deviceExpiredToken:
		return nil, false, errors.New("device authorization token expired")
	default:
		if parsed.Error != "" {
			return nil, false, fmt.Errorf("device token error: %s", parsed.Error)
		}

		return nil, false, fmt.Errorf("device token request returned status %d", resp.StatusCode)
	}
}
