package authelia

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testSessionID  = "test-session-id"
	testCookieName = "authelia_session"
)

func TestFirstFactorSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/firstfactor", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if body["username"] != "testuser" || body["password"] != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"status":"KO"}`)

			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  testCookieName,
			Value: testSessionID,
		})

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"status":"OK"}`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := newTestClient(srv)

	if err := client.FirstFactor("testuser", "testpass"); err != nil {
		t.Fatalf("FirstFactor() unexpected error: %v", err)
	}

	if client.sessionCookie != testSessionID {
		t.Errorf("sessionCookie = %q, want %q", client.sessionCookie, testSessionID)
	}
}

func TestFirstFactorFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/firstfactor", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"status":"KO","message":"Authentication failed."}`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := newTestClient(srv)

	if err := client.FirstFactor("baduser", "badpass"); err == nil {
		t.Fatal("FirstFactor() expected error, got nil")
	}
}

func TestSecondFactorTOTPSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/secondfactor/totp", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(testCookieName)
		if err != nil || cookie.Value != testSessionID {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"status":"KO"}`)

			return
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if body["token"] != "123456" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"status":"KO"}`)

			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"status":"OK"}`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := newTestClient(srv)
	client.sessionCookieName = testCookieName
	client.sessionCookie = testSessionID

	if err := client.SecondFactorTOTP("123456"); err != nil {
		t.Fatalf("SecondFactorTOTP() unexpected error: %v", err)
	}
}

func TestSecondFactorTOTPInvalidToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/secondfactor/totp", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"status":"KO","message":"Authentication failed."}`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := newTestClient(srv)
	client.sessionCookieName = testCookieName
	client.sessionCookie = testSessionID

	if err := client.SecondFactorTOTP("000000"); err == nil {
		t.Fatal("SecondFactorTOTP() expected error, got nil")
	}
}

func TestUserInfo(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user/info", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(testCookieName)
		if err != nil || cookie.Value != testSessionID {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"status":"OK","data":{"display_name":"Test User","method":"totp","has_totp":true,"has_webauthn":false,"has_duo":false}}`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := newTestClient(srv)
	client.sessionCookieName = testCookieName
	client.sessionCookie = testSessionID

	info, err := client.UserInfo()
	if err != nil {
		t.Fatalf("UserInfo() unexpected error: %v", err)
	}

	if info.Method != "totp" {
		t.Errorf("Method = %q, want %q", info.Method, "totp")
	}

	if !info.HasTOTP {
		t.Error("HasTOTP = false, want true")
	}

	if info.HasWebAuthn {
		t.Error("HasWebAuthn = true, want false")
	}
}

func TestUserInfoNonOKExtractsCookies(t *testing.T) {
	tests := []struct {
		name        string
		headers     []string
		wantName    string
		wantSession string
		wantCSRF    string
	}{
		{
			name: "rotated",
			headers: []string{
				"__Host-Http-authelia_session=new-session; Path=/; Secure; HttpOnly",
				"__Host-authelia_session_csrf=new-csrf; Path=/; Secure",
			},
			wantName:    "__Host-Http-authelia_session",
			wantSession: "new-session",
			wantCSRF:    "new-csrf",
		},
		{
			name: "deleted",
			headers: []string{
				"__Host-Http-authelia_session=; Path=/; Max-Age=0; Secure; HttpOnly",
				"__Host-authelia_session_csrf=; Path=/; Max-Age=0; Secure",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/user/info", func(w http.ResponseWriter, _ *http.Request) {
				for _, h := range tc.headers {
					w.Header().Add("Set-Cookie", h)
				}

				w.WriteHeader(http.StatusForbidden)
				_, _ = fmt.Fprint(w, `{"status":"KO"}`)
			})

			srv := httptest.NewTLSServer(mux)
			defer srv.Close()

			client := newTestClient(srv)
			client.cookieName = testCookieName
			client.sessionCookieName = "__Host-Http-authelia_session"
			client.sessionCookie = "old-session"
			client.csrfToken = "old-csrf"

			if _, err := client.UserInfo(); err == nil {
				t.Fatal("UserInfo() expected error, got nil")
			}

			if client.sessionCookieName != tc.wantName || client.sessionCookie != tc.wantSession || client.csrfToken != tc.wantCSRF {
				t.Errorf("name=%q session=%q csrf=%q, want %q/%q/%q",
					client.sessionCookieName, client.sessionCookie, client.csrfToken,
					tc.wantName, tc.wantSession, tc.wantCSRF)
			}
		})
	}
}

func TestSecondFactorDuoPush(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/secondfactor/duo", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(testCookieName)
		if err != nil || cookie.Value != testSessionID {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"status":"OK"}`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := newTestClient(srv)
	client.sessionCookieName = testCookieName
	client.sessionCookie = testSessionID

	if err := client.SecondFactorDuoPush(); err != nil {
		t.Fatalf("SecondFactorDuoPush() unexpected error: %v", err)
	}
}

func TestRateLimiting(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/secondfactor/totp", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := newTestClient(srv)
	client.sessionCookieName = testCookieName
	client.sessionCookie = testSessionID

	err := client.SecondFactorTOTP("123456")
	if err == nil {
		t.Fatal("expected rate limit error, got nil")
	}

	if err.Error() != "rate limited by Authelia server, try again later" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSpecialCharsInPassword(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/firstfactor", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if body["password"] != `p@ss"word\with/special` {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, `{"status":"KO","received":"%s"}`, body["password"])

			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  testCookieName,
			Value: "session-123",
		})

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"status":"OK"}`)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := newTestClient(srv)

	if err := client.FirstFactor("user", `p@ss"word\with/special`); err != nil {
		t.Fatalf("FirstFactor() with special chars: %v", err)
	}
}

func TestPrefixedSessionAndCSRF(t *testing.T) {
	cs := newCookieServer(t, "__Host-Http-authelia_session", "__Host-authelia_session_csrf")
	client := cs.client(testCookieName)

	if err := client.FirstFactor("user", "pass"); err != nil {
		t.Fatalf("FirstFactor() unexpected error: %v", err)
	}

	if client.sessionCookieName != "__Host-Http-authelia_session" || client.sessionCookie != "session-1" || client.csrfToken != "csrf-1" {
		t.Fatalf("after first factor: name=%q session=%q csrf=%q", client.sessionCookieName, client.sessionCookie, client.csrfToken)
	}

	if _, err := client.UserInfo(); err != nil {
		t.Fatalf("UserInfo() unexpected error: %v", err)
	}

	if err := client.SecondFactorTOTP("123456"); err != nil {
		t.Fatalf("SecondFactorTOTP() unexpected error: %v", err)
	}

	first := cs.requests[0]
	if len(first.cookieNames) != 0 || first.hasCSRF {
		t.Errorf("first factor: cookies=%v hasCSRF=%v, want none", first.cookieNames, first.hasCSRF)
	}

	totp := cs.requests[2]
	if len(totp.cookieNames) != 1 || totp.cookieNames[0] != "__Host-Http-authelia_session" {
		t.Errorf("totp cookies = %v, want [__Host-Http-authelia_session]", totp.cookieNames)
	}

	if totp.session != "session-1" || totp.csrfHeader != "csrf-1" {
		t.Errorf("totp session=%q csrf=%q, want session-1/csrf-1", totp.session, totp.csrfHeader)
	}
}

func TestLegacyServerWithoutCSRF(t *testing.T) {
	cs := newCookieServer(t, testCookieName, "")
	client := cs.client(testCookieName)

	if err := client.FirstFactor("user", "pass"); err != nil {
		t.Fatalf("FirstFactor() unexpected error: %v", err)
	}

	if _, err := client.UserInfo(); err != nil {
		t.Fatalf("UserInfo() unexpected error: %v", err)
	}

	if err := client.SecondFactorTOTP("123456"); err != nil {
		t.Fatalf("SecondFactorTOTP() unexpected error: %v", err)
	}

	if err := client.SecondFactorDuoPush(); err != nil {
		t.Fatalf("SecondFactorDuoPush() unexpected error: %v", err)
	}

	for _, rec := range cs.requests {
		if rec.hasCSRF {
			t.Errorf("%s: unexpected %s header", rec.path, HeaderCSRFToken)
		}

		if rec.path != "/api/firstfactor" && (len(rec.cookieNames) != 1 || rec.cookieNames[0] != testCookieName) {
			t.Errorf("%s: cookies = %v, want [%s]", rec.path, rec.cookieNames, testCookieName)
		}
	}

	if client.sessionCookieName != testCookieName {
		t.Errorf("sessionCookieName = %q, want %q", client.sessionCookieName, testCookieName)
	}
}

func TestCSRFTokenRotation(t *testing.T) {
	cs := newCookieServer(t, "__Host-Http-authelia_session", "__Host-authelia_session_csrf")
	client := cs.client(testCookieName)

	if err := client.FirstFactor("user", "pass"); err != nil {
		t.Fatalf("FirstFactor() unexpected error: %v", err)
	}

	if err := client.SecondFactorTOTP("123456"); err != nil {
		t.Fatalf("SecondFactorTOTP() unexpected error: %v", err)
	}

	if client.sessionCookie != "session-2" || client.csrfToken != "csrf-2" {
		t.Fatalf("after rotation: session=%q csrf=%q, want session-2/csrf-2", client.sessionCookie, client.csrfToken)
	}

	if err := client.SecondFactorDuoPush(); err != nil {
		t.Fatalf("SecondFactorDuoPush() after rotation: %v", err)
	}

	last := cs.requests[len(cs.requests)-1]
	if last.session != "session-2" || last.csrfHeader != "csrf-2" {
		t.Errorf("duo session=%q csrf=%q, want session-2/csrf-2", last.session, last.csrfHeader)
	}
}

func TestCustomCookieNameDerivesPrefixedNames(t *testing.T) {
	cs := newCookieServer(t, "__Host-Http-my_session", "__Host-my_session_csrf")
	client := cs.client("my_session")

	if err := client.FirstFactor("user", "pass"); err != nil {
		t.Fatalf("FirstFactor() unexpected error: %v", err)
	}

	if err := client.SecondFactorTOTP("123456"); err != nil {
		t.Fatalf("SecondFactorTOTP() unexpected error: %v", err)
	}

	if client.sessionCookieName != "__Host-Http-my_session" || client.csrfToken != "csrf-2" {
		t.Errorf("name=%q csrf=%q, want __Host-Http-my_session/csrf-2", client.sessionCookieName, client.csrfToken)
	}
}

func TestExtractCookiesDeletionThenNewValue(t *testing.T) {
	client := &Client{cookieName: testCookieName}

	extractFrom(t, client,
		"__Host-Http-authelia_session=; Path=/; Max-Age=0; Secure; HttpOnly",
		"__Host-Http-authelia_session=new-session; Path=/; Secure; HttpOnly",
		"__Host-authelia_session_csrf=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure",
		"__Host-authelia_session_csrf=new-csrf; Path=/; Secure",
	)

	if client.sessionCookieName != "__Host-Http-authelia_session" || client.sessionCookie != "new-session" || client.csrfToken != "new-csrf" {
		t.Errorf("name=%q session=%q csrf=%q, want __Host-Http-authelia_session/new-session/new-csrf",
			client.sessionCookieName, client.sessionCookie, client.csrfToken)
	}
}

func TestExtractCookiesDeletionClears(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"empty value", "__Host-Http-authelia_session=; Path=/"},
		{"max-age", "__Host-Http-authelia_session=x; Path=/; Max-Age=0"},
		{"expired", "__Host-Http-authelia_session=x; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{
				cookieName:        testCookieName,
				sessionCookieName: "__Host-Http-authelia_session",
				sessionCookie:     "old",
				csrfToken:         "old-csrf",
			}

			extractFrom(t, client, tc.header, strings.Replace(tc.header, "__Host-Http-authelia_session", "__Host-authelia_session_csrf", 1))

			if client.sessionCookie != "" || client.sessionCookieName != "" || client.csrfToken != "" {
				t.Errorf("name=%q session=%q csrf=%q, want all cleared", client.sessionCookieName, client.sessionCookie, client.csrfToken)
			}
		})
	}
}

func TestExtractCookiesMaxAgeOverridesExpires(t *testing.T) {
	client := &Client{cookieName: testCookieName}

	extractFrom(t, client,
		"__Host-Http-authelia_session=kept; Path=/; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
		"__Host-authelia_session_csrf=kept-csrf; Path=/; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
	)

	if client.sessionCookieName != "__Host-Http-authelia_session" || client.sessionCookie != "kept" || client.csrfToken != "kept-csrf" {
		t.Errorf("name=%q session=%q csrf=%q, want __Host-Http-authelia_session/kept/kept-csrf",
			client.sessionCookieName, client.sessionCookie, client.csrfToken)
	}
}

func TestExtractCookiesLastWins(t *testing.T) {
	client := &Client{cookieName: testCookieName}

	extractFrom(t, client,
		"__Host-Http-authelia_session=first; Path=/",
		"__Host-Http-authelia_session=second; Path=/",
	)

	if client.sessionCookie != "second" {
		t.Errorf("sessionCookie = %q, want %q", client.sessionCookie, "second")
	}
}

func TestExtractCookiesPrefersPrefixed(t *testing.T) {
	client := &Client{cookieName: testCookieName}

	extractFrom(t, client,
		"__Host-Http-authelia_session=prefixed; Path=/",
		"authelia_session=bare; Path=/",
	)

	if client.sessionCookieName != "__Host-Http-authelia_session" || client.sessionCookie != "prefixed" {
		t.Errorf("name=%q session=%q, want __Host-Http-authelia_session/prefixed", client.sessionCookieName, client.sessionCookie)
	}
}

func TestExtractCookiesIgnoresAuthzAndOtherNameDeletion(t *testing.T) {
	client := &Client{
		cookieName:        testCookieName,
		sessionCookieName: testCookieName,
		sessionCookie:     "legacy",
	}

	extractFrom(t, client,
		"__Secure-authelia_session_authz=authz; Path=/",
		"__Host-Http-authelia_session=; Path=/; Max-Age=0",
	)

	if client.sessionCookieName != testCookieName || client.sessionCookie != "legacy" || client.csrfToken != "" {
		t.Errorf("name=%q session=%q csrf=%q, want legacy session untouched", client.sessionCookieName, client.sessionCookie, client.csrfToken)
	}
}

func TestMisconfiguredCookieNameDiagnostics(t *testing.T) {
	logs := captureLog(t)

	cs := newCookieServer(t, "__Host-Http-authelia_session", "__Host-authelia_session_csrf")
	client := cs.client("__Host-Http-authelia_session")
	client.debug = true

	if err := client.FirstFactor("user", "pass"); err != nil {
		t.Fatalf("FirstFactor() unexpected error: %v", err)
	}

	if client.csrfToken != "" {
		t.Fatalf("csrfToken = %q, want empty for misconfigured cookie name", client.csrfToken)
	}

	if !strings.Contains(logs.String(), "warning:") || !strings.Contains(logs.String(), "__Host-__Host-Http-authelia_session_csrf") {
		t.Errorf("first factor log = %q, want warning naming the expected CSRF cookie", logs.String())
	}

	logs.Reset()

	if err := client.SecondFactorTOTP("123456"); err == nil {
		t.Fatal("SecondFactorTOTP() expected error without CSRF token")
	}

	if !strings.Contains(logs.String(), "without a CSRF token") {
		t.Errorf("totp log = %q, want missing CSRF token hint", logs.String())
	}
}

func TestCSRFDiagnosticsQuietWhenConfigured(t *testing.T) {
	testCases := []struct {
		name        string
		sessionName string
		csrfName    string
	}{
		{"Prefixed", "__Host-Http-authelia_session", "__Host-authelia_session_csrf"},
		{"Legacy", testCookieName, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLog(t)

			cs := newCookieServer(t, tc.sessionName, tc.csrfName)
			client := cs.client(testCookieName)

			if err := client.FirstFactor("user", "pass"); err != nil {
				t.Fatalf("FirstFactor() unexpected error: %v", err)
			}

			if logs.Len() != 0 {
				t.Errorf("log = %q, want no output", logs.String())
			}
		})
	}
}

func TestMissingCSRFHintOnlyWithoutToken(t *testing.T) {
	logs := captureLog(t)

	cs := newCookieServer(t, "__Host-Http-authelia_session", "__Host-authelia_session_csrf")
	client := cs.client(testCookieName)
	client.debug = true

	if err := client.FirstFactor("user", "pass"); err != nil {
		t.Fatalf("FirstFactor() unexpected error: %v", err)
	}

	cs.csrf = "csrf-other"

	if err := client.SecondFactorTOTP("123456"); err == nil {
		t.Fatal("SecondFactorTOTP() expected error with mismatched CSRF token")
	}

	if strings.Contains(logs.String(), "without a CSRF token") {
		t.Errorf("log = %q, want no missing CSRF token hint when a token was sent", logs.String())
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer

	writer, flags := log.Writer(), log.Flags()

	log.SetOutput(&buf)
	log.SetFlags(0)

	t.Cleanup(func() {
		log.SetOutput(writer)
		log.SetFlags(flags)
	})

	return &buf
}

func newTestClient(srv *httptest.Server) *Client {
	return &Client{
		client:     srv.Client(),
		baseURL:    srv.URL,
		cookieName: testCookieName,
	}
}

type cookieServer struct {
	t           *testing.T
	srv         *httptest.Server
	sessionName string
	csrfName    string

	session string
	csrf    string

	requests []recordedRequest
}

type recordedRequest struct {
	path        string
	cookieNames []string
	session     string
	csrfHeader  string
	hasCSRF     bool
}

func newCookieServer(t *testing.T, sessionName, csrfName string) *cookieServer {
	t.Helper()

	cs := &cookieServer{t: t, sessionName: sessionName, csrfName: csrfName}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/firstfactor", func(w http.ResponseWriter, r *http.Request) {
		cs.record(r)
		cs.rotate(w, "1")
		_, _ = fmt.Fprint(w, `{"status":"OK"}`)
	})

	mux.HandleFunc("/api/user/info", func(w http.ResponseWriter, r *http.Request) {
		cs.record(r)

		if !cs.authorized(r, false) {
			w.WriteHeader(http.StatusForbidden)

			return
		}

		_, _ = fmt.Fprint(w, `{"status":"OK","data":{"method":"totp","has_totp":true}}`)
	})

	mux.HandleFunc("/api/secondfactor/totp", func(w http.ResponseWriter, r *http.Request) {
		cs.record(r)

		if !cs.authorized(r, true) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"status":"KO"}`)

			return
		}

		cs.rotate(w, "2")
		_, _ = fmt.Fprint(w, `{"status":"OK"}`)
	})

	mux.HandleFunc("/api/secondfactor/duo", func(w http.ResponseWriter, r *http.Request) {
		cs.record(r)

		if !cs.authorized(r, true) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"status":"KO"}`)

			return
		}

		_, _ = fmt.Fprint(w, `{"status":"OK"}`)
	})

	cs.srv = httptest.NewTLSServer(mux)
	t.Cleanup(cs.srv.Close)

	return cs
}

func (cs *cookieServer) rotate(w http.ResponseWriter, generation string) {
	cs.session = "session-" + generation
	http.SetCookie(w, &http.Cookie{Name: cs.sessionName, Value: cs.session, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})

	if cs.csrfName != "" {
		cs.csrf = "csrf-" + generation
		http.SetCookie(w, &http.Cookie{Name: cs.csrfName, Value: cs.csrf, Path: "/", Secure: true, SameSite: http.SameSiteStrictMode})
	}
}

func (cs *cookieServer) record(r *http.Request) {
	cs.t.Helper()

	for _, h := range []string{"Origin", "Referer", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User"} {
		if v := r.Header.Get(h); v != "" {
			cs.t.Errorf("%s %s: unexpected %s header %q", r.Method, r.URL.Path, h, v)
		}
	}

	rec := recordedRequest{path: r.URL.Path}

	for _, c := range r.Cookies() {
		rec.cookieNames = append(rec.cookieNames, c.Name)

		if c.Name == cs.sessionName {
			rec.session = c.Value
		}
	}

	_, rec.hasCSRF = r.Header[http.CanonicalHeaderKey(HeaderCSRFToken)]
	rec.csrfHeader = r.Header.Get(HeaderCSRFToken)

	cs.requests = append(cs.requests, rec)
}

func (cs *cookieServer) authorized(r *http.Request, stateChanging bool) bool {
	c, err := r.Cookie(cs.sessionName)
	if err != nil || c.Value != cs.session {
		return false
	}

	if stateChanging && cs.csrfName != "" && r.Header.Get(HeaderCSRFToken) != cs.csrf {
		return false
	}

	return true
}

func (cs *cookieServer) client(cookieName string) *Client {
	return &Client{
		client:     cs.srv.Client(),
		baseURL:    cs.srv.URL,
		cookieName: cookieName,
	}
}

func writeSetCookies(w http.ResponseWriter, headers ...string) {
	for _, h := range headers {
		w.Header().Add("Set-Cookie", h)
	}
}

func extractFrom(t *testing.T, client *Client, headers ...string) {
	t.Helper()

	rec := httptest.NewRecorder()
	writeSetCookies(rec, headers...)
	client.extractCookies(rec.Result())
}
