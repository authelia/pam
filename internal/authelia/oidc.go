package authelia

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// PAMUsernameClaim is the OIDC claim compared against the requesting Linux
// username. Operators expose it via Authelia claims_policies — see README
// "Device authorization identity binding".
const PAMUsernameClaim = "authelia.pam.username"

// PAMScope is the OAuth2 scope that must grant PAMUsernameClaim. Operators
// define it under Authelia identity_providers.oidc.scopes and bind it to the
// pam_authelia client.
const PAMScope = "authelia.pam"

// VerifyDeviceIdentity binds a device-flow token to a Linux username, failing
// closed at every step. It verifies the ID token against the issuer's JWKs,
// asserts userinfo.sub matches id_token.sub (token substitution defense), and
// compares the configured custom claim to the PAM username case-sensitively.
func (c *Client) VerifyDeviceIdentity(ctx context.Context, clientID, accessToken, idToken, expectedUsername string) error {
	if clientID == "" {
		return errors.New("missing oauth2 client id")
	}

	if accessToken == "" {
		return errors.New("token endpoint returned no access token")
	}

	if idToken == "" {
		return errors.New("token endpoint returned no id token (is the openid scope requested?)")
	}

	if expectedUsername == "" {
		return errors.New("missing pam username")
	}

	ctx = oidc.ClientContext(ctx, c.client)

	provider, err := oidc.NewProvider(ctx, c.baseURL)
	if err != nil {
		return fmt.Errorf("oidc discovery failed: %w", err)
	}

	verified, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, idToken)
	if err != nil {
		return fmt.Errorf("id token verification failed: %w", err)
	}

	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}))
	if err != nil {
		return fmt.Errorf("userinfo request failed: %w", err)
	}

	if userInfo.Subject != verified.Subject {
		return fmt.Errorf("userinfo subject %q does not match id token subject %q", userInfo.Subject, verified.Subject)
	}

	var claims map[string]any
	if err = userInfo.Claims(&claims); err != nil {
		return fmt.Errorf("failed to decode userinfo claims: %w", err)
	}

	raw, ok := claims[PAMUsernameClaim]
	if !ok {
		return fmt.Errorf("claim %q missing from userinfo response", PAMUsernameClaim)
	}

	username, ok := raw.(string)
	if !ok {
		return fmt.Errorf("claim %q is not a string", PAMUsernameClaim)
	}

	if username == "" {
		return fmt.Errorf("claim %q is empty", PAMUsernameClaim)
	}

	if username != expectedUsername {
		return fmt.Errorf("authelia identity %q does not match pam username %q", username, expectedUsername)
	}

	c.Debugf("device identity verified: claim %q == pam username %q (sub=%q)", PAMUsernameClaim, expectedUsername, verified.Subject)

	return nil
}
