package authelia

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPollDeviceTokenFirstPollImmediate(t *testing.T) {
	ds := newDeviceServer(t, 5*time.Second)
	ds.approveAfter = 0

	accessToken, idToken, err := ds.client().PollDeviceToken("client", "", ds.auth(300, 5))
	if err != nil {
		t.Fatalf("PollDeviceToken() unexpected error: %v", err)
	}

	if accessToken != "access-token" || idToken != "id-token" {
		t.Errorf("PollDeviceToken() = %q, %q", accessToken, idToken)
	}

	assertDurations(t, "sleeps", ds.sleeps, nil)
}

func TestPollDeviceTokenHonoursInterval(t *testing.T) {
	ds := newDeviceServer(t, 5*time.Second)
	ds.approveAfter = 2

	if _, _, err := ds.client().PollDeviceToken("client", "", ds.auth(300, 5)); err != nil {
		t.Fatalf("PollDeviceToken() unexpected error: %v", err)
	}

	assertDurations(t, "sleeps", ds.sleeps, seconds(5, 5))
	assertDurations(t, "poll times", ds.pollTime, seconds(0, 5, 10))
}

func TestPollDeviceTokenDefaultInterval(t *testing.T) {
	ds := newDeviceServer(t, 5*time.Second)
	ds.approveAfter = 1

	if _, _, err := ds.client().PollDeviceToken("client", "", ds.auth(300, 0)); err != nil {
		t.Fatalf("PollDeviceToken() unexpected error: %v", err)
	}

	assertDurations(t, "sleeps", ds.sleeps, seconds(5))
}

func TestPollDeviceTokenSlowDownGrowsIntervalPermanently(t *testing.T) {
	ds := newDeviceServer(t, 5*time.Second)
	ds.approveAfter = 4
	ds.forceSlowDown[2] = true

	if _, _, err := ds.client().PollDeviceToken("client", "", ds.auth(300, 5)); err != nil {
		t.Fatalf("PollDeviceToken() unexpected error: %v", err)
	}

	assertDurations(t, "sleeps", ds.sleeps, seconds(5, 10, 10, 10, 10))
}

func TestPollDeviceTokenSlowDownBeyondSixtySeconds(t *testing.T) {
	ds := newDeviceServer(t, 55*time.Second)
	ds.approveAfter = 3
	ds.forceSlowDown[2] = true
	ds.forceSlowDown[3] = true

	if _, _, err := ds.client().PollDeviceToken("client", "", ds.auth(600, 55)); err != nil {
		t.Fatalf("PollDeviceToken() unexpected error: %v", err)
	}

	assertDurations(t, "sleeps", ds.sleeps, seconds(55, 60, 65, 65, 65))
}

func TestPollDeviceTokenHonoursLongServerInterval(t *testing.T) {
	ds := newDeviceServer(t, 90*time.Second)
	ds.approveAfter = 1

	if _, _, err := ds.client().PollDeviceToken("client", "", ds.auth(600, 90)); err != nil {
		t.Fatalf("PollDeviceToken() unexpected error: %v", err)
	}

	assertDurations(t, "sleeps", ds.sleeps, seconds(90))

	if ds.slowDowns != 0 {
		t.Errorf("server answered %d slow_down responses, want 0", ds.slowDowns)
	}
}

func TestPollDeviceTokenSlowDownLimitInvalidates(t *testing.T) {
	ds := newDeviceServer(t, 5*time.Second)
	ds.slowDownLimit = 1
	ds.forceSlowDown[2] = true
	ds.forceSlowDown[3] = true

	_, _, err := ds.client().PollDeviceToken("client", "", ds.auth(300, 5))
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("PollDeviceToken() error = %v, want invalid_grant", err)
	}
}

func TestPollDeviceTokenTimeoutBacksOff(t *testing.T) {
	ds := newDeviceServer(t, 5*time.Second)
	ds.approveAfter = 2
	ds.timeout[2] = true

	if _, _, err := ds.client().PollDeviceToken("client", "", ds.auth(300, 5)); err != nil {
		t.Fatalf("PollDeviceToken() unexpected error: %v", err)
	}

	assertDurations(t, "sleeps", ds.sleeps, seconds(5, 10, 10))
}

func TestPollDeviceTokenExpires(t *testing.T) {
	ds := newDeviceServer(t, 5*time.Second)

	auth := ds.auth(12, 5)
	ds.clock = ds.start.Add(3 * time.Second)

	_, _, err := ds.client().PollDeviceToken("client", "", auth)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("PollDeviceToken() error = %v, want expiry", err)
	}

	assertDurations(t, "sleeps", ds.sleeps, seconds(5))
	assertDurations(t, "poll times", ds.pollTime, seconds(3, 8))
}

func TestPollDeviceTokenAccessDenied(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTokenError(w, "access_denied")
	}))
	defer srv.Close()

	_, _, err := newTestClient(srv).PollDeviceToken("client", "", &DeviceAuthorizationResponse{DeviceCode: "device-code", ExpiresIn: 300, Interval: 5})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("PollDeviceToken() error = %v, want denial", err)
	}
}

func TestPollDeviceTokenNilResponse(t *testing.T) {
	if _, _, err := (&Client{}).PollDeviceToken("client", "", nil); err == nil {
		t.Fatal("PollDeviceToken(nil) expected error")
	}
}

type deviceServer struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex

	clock time.Time
	last  time.Time

	interval      time.Duration
	slowDowns     int
	slowDownLimit int
	invalidated   bool

	approveAfter int
	accepted     int

	forceSlowDown map[int]bool

	timeout map[int]bool

	polls    int
	pollTime []time.Duration
	start    time.Time
	sleeps   []time.Duration
}

func newDeviceServer(t *testing.T, interval time.Duration) *deviceServer {
	t.Helper()

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	ds := &deviceServer{
		t:             t,
		clock:         start,
		start:         start,
		interval:      interval,
		slowDownLimit: 3,
		approveAfter:  -1,
		forceSlowDown: map[int]bool{},
		timeout:       map[int]bool{},
	}

	ds.srv = httptest.NewTLSServer(http.HandlerFunc(ds.handle))
	t.Cleanup(ds.srv.Close)

	return ds
}

func (ds *deviceServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/oidc/token" || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)

		return
	}

	if err := r.ParseForm(); err != nil || r.PostForm.Get("device_code") != "device-code" {
		ds.t.Errorf("unexpected token request form: %v", r.PostForm)
	}

	n, _ := strconv.Atoi(r.Header.Get(headerPoll))

	ds.mu.Lock()
	defer ds.mu.Unlock()

	now := ds.clock

	if ds.invalidated {
		writeTokenError(w, "invalid_grant")

		return
	}

	if (!ds.last.IsZero() && ds.last.Add(ds.interval).After(now)) || ds.forceSlowDown[n] {
		ds.slowDowns++

		if ds.slowDowns > ds.slowDownLimit {
			ds.invalidated = true

			writeTokenError(w, "invalid_grant")

			return
		}

		ds.interval += 5 * time.Second
		ds.last = now

		writeTokenError(w, "slow_down")

		return
	}

	ds.slowDowns = 0
	ds.last = now

	if ds.approveAfter < 0 || ds.accepted < ds.approveAfter {
		ds.accepted++

		writeTokenError(w, "authorization_pending")

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "access-token",
		"id_token":     "id-token",
		"token_type":   "bearer",
		"expires_in":   3600,
	})
}

func writeTokenError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

const headerPoll = "X-Test-Poll"

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// RoundTrip numbers each poll, records when it was made, and fails polls marked in timeout with a
// timeoutError without contacting the server.
func (ds *deviceServer) RoundTrip(req *http.Request) (*http.Response, error) {
	ds.mu.Lock()

	ds.polls++
	n := ds.polls
	ds.pollTime = append(ds.pollTime, ds.clock.Sub(ds.start))
	timeout := ds.timeout[n]

	ds.mu.Unlock()

	if timeout {
		return nil, timeoutError{}
	}

	req = req.Clone(req.Context())
	req.Header.Set(headerPoll, strconv.Itoa(n))

	return ds.srv.Client().Transport.RoundTrip(req)
}

func (ds *deviceServer) client() *Client {
	return &Client{
		client:  &http.Client{Transport: ds},
		baseURL: ds.srv.URL,
		clock: func() time.Time {
			ds.mu.Lock()
			defer ds.mu.Unlock()

			return ds.clock
		},
		sleeper: func(d time.Duration) {
			ds.mu.Lock()
			defer ds.mu.Unlock()

			ds.sleeps = append(ds.sleeps, d)
			ds.clock = ds.clock.Add(d)
		},
	}
}

func (ds *deviceServer) auth(expiresIn, interval int) *DeviceAuthorizationResponse {
	return &DeviceAuthorizationResponse{
		DeviceCode: "device-code",
		ExpiresIn:  expiresIn,
		Interval:   interval,
		IssuedAt:   ds.start,
	}
}

func seconds(values ...int) []time.Duration {
	out := make([]time.Duration, len(values))

	for i, v := range values {
		out[i] = time.Duration(v) * time.Second
	}

	return out
}

func assertDurations(t *testing.T, name string, got, want []time.Duration) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
}
