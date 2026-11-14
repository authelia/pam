package authelia

// 2FA method identifiers accepted in --method-priority.
const (
	MethodTOTP       = "totp"
	MethodWebAuthn   = "webauthn"
	MethodMobilePush = "mobile_push"
	MethodDeviceAuth = "device_authorization"
	MethodUser       = "user"
)

// Cookie name prefixes and suffixes used by Authelia 4.40+ for the portal API.
const (
	cookiePrefixHost     = "__Host-"
	cookiePrefixHostHTTP = "__Host-Http-"
	cookieSuffixCSRF     = "_csrf"

	// HeaderCSRFToken carries the CSRF token on state-changing requests.
	HeaderCSRFToken = "X-CSRF-Token"
)

// OIDC identity binding.
const (
	// PAMUsernameClaim is the OIDC claim compared against the requesting Linux
	// username. Operators expose it via Authelia claims_policies — see README
	// "Device authorization identity binding".
	PAMUsernameClaim = "authelia.pam.username"

	// PAMScope is the OAuth2 scope that must grant PAMUsernameClaim. Operators
	// define it under Authelia identity_providers.oidc.scopes and bind it to the
	// pam_authelia client.
	PAMScope = "authelia.pam"
)

// RFC 8628 token endpoint polling error codes.
const (
	deviceAuthorizationPending = "authorization_pending"
	deviceSlowDown             = "slow_down"
	deviceAccessDenied         = "access_denied"
	deviceExpiredToken         = "expired_token"
)
