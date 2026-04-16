package authelia

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testClientID = "pam_authelia_test"
	testKID      = "test-key-1"
	testSubject  = "11111111-2222-3333-4444-555555555555"
	testUsername = "john"
)

// oidcTestServer is a minimal OIDC provider for verifier tests. It serves a
// discovery doc, JWKs document, and userinfo endpoint, with the userinfo
// response settable per-test.
type oidcTestServer struct {
	srv      *httptest.Server
	priv     *rsa.PrivateKey
	mu       sync.Mutex
	userInfo map[string]any
	bearer   string // expected access token; empty allows any
}

func newOIDCTestServer(t *testing.T) *oidcTestServer {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	o := &oidcTestServer{priv: priv}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"issuer":%q,
			"authorization_endpoint":%q,
			"token_endpoint":%q,
			"device_authorization_endpoint":%q,
			"jwks_uri":%q,
			"userinfo_endpoint":%q,
			"response_types_supported":["code"],
			"subject_types_supported":["public"],
			"id_token_signing_alg_values_supported":["RS256"]
		}`, o.srv.URL, o.srv.URL+"/auth", o.srv.URL+"/token", o.srv.URL+"/device", o.srv.URL+"/jwks", o.srv.URL+"/userinfo")
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`, testKID, n, e)
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		expectedBearer := o.bearer
		body := o.userInfo
		o.mu.Unlock()

		if expectedBearer != "" {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+expectedBearer {
				w.WriteHeader(http.StatusUnauthorized)

				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	o.srv = httptest.NewTLSServer(mux)

	t.Cleanup(o.srv.Close)

	return o
}

// signJWT produces a compact RS256 JWT signed by the test key. Claims is taken
// as a map so individual tests can tamper with iss/aud/sub/exp.
func (o *oidcTestServer) signJWT(t *testing.T, claims map[string]any) string {
	t.Helper()

	header := map[string]any{"alg": "RS256", "kid": testKID, "typ": "JWT"}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)

	sum := sha256.Sum256([]byte(signingInput))

	sig, err := rsa.SignPKCS1v15(rand.Reader, o.priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// validIDTokenClaims returns the baseline claim set tests start from.
func (o *oidcTestServer) validIDTokenClaims() map[string]any {
	now := time.Now().Unix()

	return map[string]any{
		"iss": o.srv.URL,
		"sub": testSubject,
		"aud": testClientID,
		"iat": now,
		"exp": now + 300,
	}
}

// setUserInfo configures the userinfo response for the next call.
func (o *oidcTestServer) setUserInfo(body map[string]any) {
	o.mu.Lock()
	o.userInfo = body
	o.mu.Unlock()
}

// setExpectedBearer pins which access token /userinfo will accept. Empty allows any.
func (o *oidcTestServer) setExpectedBearer(token string) {
	o.mu.Lock()
	o.bearer = token
	o.mu.Unlock()
}

func (o *oidcTestServer) newClient() *Client {
	return &Client{
		client:  o.srv.Client(),
		baseURL: o.srv.URL,
	}
}

func TestVerifyDeviceIdentitySuccess(t *testing.T) {
	o := newOIDCTestServer(t)
	o.setUserInfo(map[string]any{
		"sub":                   testSubject,
		"authelia.pam.username": testUsername,
	})
	o.setExpectedBearer("access-token-abc")

	idToken := o.signJWT(t, o.validIDTokenClaims())

	if err := o.newClient().VerifyDeviceIdentity(context.Background(), testClientID, "access-token-abc", idToken, testUsername); err != nil {
		t.Fatalf("VerifyDeviceIdentity() unexpected error: %v", err)
	}
}

func TestVerifyDeviceIdentityFailures(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(o *oidcTestServer, claims map[string]any) (idToken string, accessToken string, expectedUsername string)
		errSubstr string
	}{
		{
			name: "missing access token",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": testUsername})

				return o.signJWT(t, claims), "", testUsername
			},
			errSubstr: "no access token",
		},
		{
			name: "missing id token",
			mutate: func(o *oidcTestServer, _ map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": testUsername})

				return "", "tok", testUsername
			},
			errSubstr: "no id token",
		},
		{
			name: "missing pam username",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": testUsername})

				return o.signJWT(t, claims), "tok", ""
			},
			errSubstr: "missing pam username",
		},
		{
			name: "wrong audience",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": testUsername})
				claims["aud"] = "some-other-client"

				return o.signJWT(t, claims), "tok", testUsername
			},
			errSubstr: "id token verification failed",
		},
		{
			name: "expired id token",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": testUsername})
				claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()

				return o.signJWT(t, claims), "tok", testUsername
			},
			errSubstr: "id token verification failed",
		},
		{
			name: "wrong issuer",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": testUsername})
				claims["iss"] = "https://attacker.example.com"

				return o.signJWT(t, claims), "tok", testUsername
			},
			errSubstr: "id token verification failed",
		},
		{
			name: "tampered signature",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": testUsername})

				// Flip the first byte of the signature segment — high-order bits of a base64url
				// char carry meaning, unlike the last char of an unpadded encoding.
				signed := o.signJWT(t, claims)
				lastDot := strings.LastIndexByte(signed, '.')
				mutated := []byte(signed)

				if mutated[lastDot+1] == 'A' {
					mutated[lastDot+1] = 'B'
				} else {
					mutated[lastDot+1] = 'A'
				}

				return string(mutated), "tok", testUsername
			},
			errSubstr: "id token verification failed",
		},
		{
			name: "userinfo subject mismatch",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": "different-sub", "authelia.pam.username": testUsername})

				return o.signJWT(t, claims), "tok", testUsername
			},
			errSubstr: "does not match id token subject",
		},
		{
			name: "claim missing",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject})

				return o.signJWT(t, claims), "tok", testUsername
			},
			errSubstr: `claim "authelia.pam.username" missing`,
		},
		{
			name: "claim wrong type",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": 42})

				return o.signJWT(t, claims), "tok", testUsername
			},
			errSubstr: `not a string`,
		},
		{
			name: "claim empty",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": ""})

				return o.signJWT(t, claims), "tok", testUsername
			},
			errSubstr: "is empty",
		},
		{
			name: "username mismatch",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": "jane"})

				return o.signJWT(t, claims), "tok", testUsername
			},
			errSubstr: `"jane" does not match pam username "john"`,
		},
		{
			name: "case-sensitive mismatch",
			mutate: func(o *oidcTestServer, claims map[string]any) (string, string, string) {
				o.setUserInfo(map[string]any{"sub": testSubject, "authelia.pam.username": "John"})

				return o.signJWT(t, claims), "tok", testUsername
			},
			errSubstr: `"John" does not match pam username "john"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newOIDCTestServer(t)

			claims := o.validIDTokenClaims()
			idToken, accessToken, expectedUsername := tt.mutate(o, claims)

			err := o.newClient().VerifyDeviceIdentity(context.Background(), testClientID, accessToken, idToken, expectedUsername)
			if err == nil {
				t.Fatalf("VerifyDeviceIdentity() expected error containing %q, got nil", tt.errSubstr)
			}

			if !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("VerifyDeviceIdentity() error = %q, want substring %q", err.Error(), tt.errSubstr)
			}
		})
	}
}
