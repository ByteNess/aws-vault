package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/keyring"
)

// fakeOIDC stands in for the IAM Identity Center OIDC endpoints. It records
// every request so tests can assert on what aws-vault sent.
type fakeOIDC struct {
	mu       sync.Mutex
	requests []map[string]any
	paths    []string
	// refreshStatus, when non-zero, is the HTTP status the refresh_token grant
	// answers with, and refreshErrorType the accompanying error type. The type
	// defaults to InvalidGrantException for a 400 and InternalServerException
	// otherwise.
	refreshStatus    int
	refreshErrorType string
}

func (f *fakeOIDC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.requests = append(f.requests, body)
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/client/register":
		f.reply(w, map[string]any{
			"clientId": "client-1", "clientSecret": "secret-1",
			"clientSecretExpiresAt": time.Now().Add(90 * 24 * time.Hour).Unix(),
		})
	case "/device_authorization":
		f.reply(w, map[string]any{
			"deviceCode": "device-1", "userCode": "ABCD-EFGH",
			"verificationUri": "https://device.example.test", "verificationUriComplete": "https://device.example.test/?user_code=ABCD-EFGH",
			"expiresIn": 600, "interval": 0,
		})
	case "/token":
		switch body["grantType"] {
		case "refresh_token":
			if f.refreshStatus != 0 {
				f.replyRefreshError(w)
				return
			}
			f.reply(w, map[string]any{
				"accessToken": "access-2", "expiresIn": 3600, "refreshToken": "refresh-2", "tokenType": "Bearer",
			})
		default:
			f.reply(w, map[string]any{
				"accessToken": "access-1", "expiresIn": 3600, "refreshToken": "refresh-1", "tokenType": "Bearer",
			})
		}
	default:
		http.NotFound(w, r)
	}
}

// replyRefreshError answers the refresh_token grant with the configured
// failure, the way the OIDC service reports it: an error type header plus an
// OAuth error body.
func (f *fakeOIDC) replyRefreshError(w http.ResponseWriter) {
	errorType := f.refreshErrorType
	if errorType == "" {
		if f.refreshStatus == http.StatusBadRequest {
			errorType = "InvalidGrantException"
		} else {
			errorType = "InternalServerException"
		}
	}
	w.Header().Set("X-Amzn-Errortype", errorType)
	w.WriteHeader(f.refreshStatus)
	f.reply(w, map[string]any{"error": errorType})
}

func (f *fakeOIDC) reply(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}

func (f *fakeOIDC) calls(path string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for i, p := range f.paths {
		if p == path {
			out = append(out, f.requests[i])
		}
	}
	return out
}

// memOIDCCache is an in-memory OIDCTokenCacher that also records removals.
// staleReads, when set, is returned by the first Get calls before the map is
// consulted, to simulate a process that read the entry before another process
// replaced it.
type memOIDCCache struct {
	data       map[string]*OIDCTokenData
	staleReads []*OIDCTokenData
	removed    int
}

func (m *memOIDCCache) Get(k string) (*OIDCTokenData, error) {
	if len(m.staleReads) > 0 {
		d := m.staleReads[0]
		m.staleReads = m.staleReads[1:]
		return d, nil
	}
	d, ok := m.data[k]
	if !ok {
		return nil, keyring.ErrKeyNotFound
	}
	return d, nil
}
func (m *memOIDCCache) Set(k string, d *OIDCTokenData) error { m.data[k] = d; return nil }
func (m *memOIDCCache) Remove(k string) error                { delete(m.data, k); m.removed++; return nil }

func newTestSSOProvider(t *testing.T, f *fakeOIDC, cache OIDCTokenCacher) *SSORoleCredentialsProvider {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	client := ssooidc.New(ssooidc.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	})
	return &SSORoleCredentialsProvider{
		OIDCClient:         client,
		OIDCTokenCache:     cache,
		StartURL:           "https://example.awsapps.com/start",
		UseStdout:          true, // print the URL instead of opening a browser
		RegistrationScopes: []string{"sso:account:access"},
	}
}

func TestGetOIDCTokenRegistersClientWithScopesAndCachesRefreshToken(t *testing.T) {
	f := &fakeOIDC{}
	cache := &memOIDCCache{data: map[string]*OIDCTokenData{}}
	p := newTestSSOProvider(t, f, cache)

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("getOIDCToken: %v", err)
	}
	if cached {
		t.Error("expected a freshly issued token, got cached=true")
	}
	if aws.ToString(token.AccessToken) != "access-1" {
		t.Errorf("AccessToken = %q, want access-1", aws.ToString(token.AccessToken))
	}

	regs := f.calls("/client/register")
	if len(regs) != 1 {
		t.Fatalf("RegisterClient calls = %d, want 1", len(regs))
	}
	scopes, _ := regs[0]["scopes"].([]any)
	if len(scopes) != 1 || scopes[0] != "sso:account:access" {
		t.Errorf("RegisterClient scopes = %v, want [sso:account:access]", regs[0]["scopes"])
	}

	stored := cache.data[p.StartURL]
	if stored == nil {
		t.Fatal("token was not cached")
	}
	if stored.ClientID != "client-1" || stored.ClientSecret != "secret-1" {
		t.Errorf("cached client registration = %q/%q, want client-1/secret-1", stored.ClientID, stored.ClientSecret)
	}
	if aws.ToString(stored.Token.RefreshToken) != "refresh-1" {
		t.Errorf("cached RefreshToken = %q, want refresh-1", aws.ToString(stored.Token.RefreshToken))
	}
	if !stored.Refreshable() {
		t.Error("cached token should be refreshable")
	}
}

func expiredRefreshableToken() *OIDCTokenData {
	return &OIDCTokenData{
		Token: ssooidc.CreateTokenOutput{
			AccessToken:  aws.String("access-old"),
			RefreshToken: aws.String("refresh-1"),
		},
		Expiration:            time.Now().Add(-time.Minute),
		ClientID:              "client-1",
		ClientSecret:          "secret-1",
		ClientSecretExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestGetOIDCTokenRefreshesExpiredTokenWithoutBrowser(t *testing.T) {
	f := &fakeOIDC{}
	cache := &memOIDCCache{data: map[string]*OIDCTokenData{}}
	p := newTestSSOProvider(t, f, cache)
	cache.data[p.StartURL] = expiredRefreshableToken()

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("getOIDCToken: %v", err)
	}
	if !cached {
		t.Error("a refreshed token should count as cached so a 401 clears it and retries")
	}
	if aws.ToString(token.AccessToken) != "access-2" {
		t.Errorf("AccessToken = %q, want access-2", aws.ToString(token.AccessToken))
	}

	if n := len(f.calls("/device_authorization")); n != 0 {
		t.Errorf("device authorization started %d time(s); refresh must not open a browser flow", n)
	}
	if n := len(f.calls("/client/register")); n != 0 {
		t.Errorf("RegisterClient called %d time(s); refresh must reuse the cached client", n)
	}
	tokens := f.calls("/token")
	if len(tokens) != 1 {
		t.Fatalf("CreateToken calls = %d, want 1", len(tokens))
	}
	if tokens[0]["grantType"] != "refresh_token" || tokens[0]["refreshToken"] != "refresh-1" || tokens[0]["clientId"] != "client-1" || tokens[0]["clientSecret"] != "secret-1" {
		t.Errorf("unexpected refresh request: %v", tokens[0])
	}

	stored := cache.data[p.StartURL]
	if aws.ToString(stored.Token.RefreshToken) != "refresh-2" {
		t.Errorf("cached RefreshToken = %q, want the rotated refresh-2", aws.ToString(stored.Token.RefreshToken))
	}
	if stored.ClientID != "client-1" {
		t.Errorf("cached ClientID = %q, want client-1 carried over", stored.ClientID)
	}
}

func TestGetOIDCTokenFallsBackToLoginWhenRefreshFails(t *testing.T) {
	f := &fakeOIDC{refreshStatus: http.StatusBadRequest}
	cache := &memOIDCCache{data: map[string]*OIDCTokenData{}}
	p := newTestSSOProvider(t, f, cache)
	cache.data[p.StartURL] = expiredRefreshableToken()

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("getOIDCToken: %v", err)
	}
	if cached {
		t.Error("expected a freshly issued token after refresh failure")
	}
	if aws.ToString(token.AccessToken) != "access-1" {
		t.Errorf("AccessToken = %q, want access-1 from the new device flow", aws.ToString(token.AccessToken))
	}
	if cache.removed != 1 {
		t.Errorf("stale token removed %d time(s), want 1", cache.removed)
	}
	if n := len(f.calls("/device_authorization")); n != 1 {
		t.Errorf("device authorization started %d time(s), want 1", n)
	}
}

func TestParseSSORegistrationScopes(t *testing.T) {
	cases := map[string][]string{
		"":                   nil,
		"sso:account:access": {"sso:account:access"},
		"sso:account:access,codewhisperer:analysis": {"sso:account:access", "codewhisperer:analysis"},
		" sso:account:access , other ":              {"sso:account:access", "other"},
	}
	for in, want := range cases {
		got := ParseSSORegistrationScopes(in)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("ParseSSORegistrationScopes(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestGetOIDCTokenRefreshesShortlyBeforeExpiry(t *testing.T) {
	f := &fakeOIDC{}
	cache := &memOIDCCache{data: map[string]*OIDCTokenData{}}
	p := newTestSSOProvider(t, f, cache)
	soon := expiredRefreshableToken()
	soon.Expiration = time.Now().Add(oidcRefreshWindow / 2)
	cache.data[p.StartURL] = soon

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("getOIDCToken: %v", err)
	}
	if !cached || aws.ToString(token.AccessToken) != "access-2" {
		t.Errorf("token = %q cached=%t, want the refreshed access-2 from cache", aws.ToString(token.AccessToken), cached)
	}
	if n := len(f.calls("/device_authorization")); n != 0 {
		t.Errorf("device authorization started %d time(s), want 0", n)
	}
}

func TestGetOIDCTokenKeepsValidTokenWhenEarlyRefreshFails(t *testing.T) {
	f := &fakeOIDC{refreshStatus: http.StatusBadRequest}
	cache := &memOIDCCache{data: map[string]*OIDCTokenData{}}
	p := newTestSSOProvider(t, f, cache)
	soon := expiredRefreshableToken()
	soon.Expiration = time.Now().Add(oidcRefreshWindow / 2)
	cache.data[p.StartURL] = soon

	token, _, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("getOIDCToken: %v", err)
	}
	if aws.ToString(token.AccessToken) != "access-old" {
		t.Errorf("AccessToken = %q, want the still-valid access-old", aws.ToString(token.AccessToken))
	}
	if cache.removed != 0 || cache.data[p.StartURL] != soon {
		t.Error("a still-valid entry must not be removed or replaced when its early refresh fails")
	}
	if n := len(f.calls("/device_authorization")); n != 0 {
		t.Errorf("device authorization started %d time(s), want 0", n)
	}
}

// Two processes read the same expired entry. The other one refreshes first, so
// the refresh token this process holds is already consumed and the refresh is
// rejected. It must pick up the entry the other process wrote instead of
// deleting it and opening a browser.
func TestGetOIDCTokenUsesTokenRefreshedByAnotherProcess(t *testing.T) {
	f := &fakeOIDC{refreshStatus: http.StatusBadRequest}
	cache := &memOIDCCache{data: map[string]*OIDCTokenData{}}
	p := newTestSSOProvider(t, f, cache)

	stale := expiredRefreshableToken()
	fresh := expiredRefreshableToken()
	fresh.Token.AccessToken = aws.String("access-2")
	fresh.Token.RefreshToken = aws.String("refresh-2")
	fresh.Expiration = time.Now().Add(time.Hour)
	cache.staleReads = []*OIDCTokenData{stale}
	cache.data[p.StartURL] = fresh

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("getOIDCToken: %v", err)
	}
	if !cached || aws.ToString(token.AccessToken) != "access-2" {
		t.Errorf("token = %q cached=%t, want access-2 written by the other process", aws.ToString(token.AccessToken), cached)
	}
	if cache.removed != 0 || cache.data[p.StartURL] != fresh {
		t.Error("the other process's fresh entry must not be removed")
	}
	if n := len(f.calls("/device_authorization")); n != 0 {
		t.Errorf("device authorization started %d time(s), want 0", n)
	}
}

func TestGetOIDCTokenKeepsRefreshTokenOnTransientError(t *testing.T) {
	f := &fakeOIDC{refreshStatus: http.StatusServiceUnavailable}
	cache := &memOIDCCache{data: map[string]*OIDCTokenData{}}
	p := newTestSSOProvider(t, f, cache)
	entry := expiredRefreshableToken()
	cache.data[p.StartURL] = entry

	_, _, err := p.getOIDCToken(context.Background())
	if err == nil {
		t.Fatal("expected an error when the refresh fails with a 5xx")
	}
	if cache.removed != 0 || cache.data[p.StartURL] != entry {
		t.Error("a transient failure must keep the refresh token for the next attempt")
	}
	if n := len(f.calls("/device_authorization")); n != 0 {
		t.Errorf("device authorization started %d time(s); a transient error must not open a browser", n)
	}
}

// Throttling must not be read as a refusal of the grant: SlowDownException is
// a 400 and API-level throttling a 429, and both are what a burst of parallel
// credential_process callers gets. Treating either as a rejection would drop
// the refresh token and open the browser tab this change exists to avoid.
func TestGetOIDCTokenKeepsRefreshTokenWhenThrottled(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		errorType string
	}{
		{"slow down", http.StatusBadRequest, "SlowDownException"},
		{"too many requests", http.StatusTooManyRequests, "ThrottlingException"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeOIDC{refreshStatus: tc.status, refreshErrorType: tc.errorType}
			cache := &memOIDCCache{data: map[string]*OIDCTokenData{}}
			p := newTestSSOProvider(t, f, cache)
			entry := expiredRefreshableToken()
			cache.data[p.StartURL] = entry

			_, _, err := p.getOIDCToken(context.Background())
			if err == nil {
				t.Fatalf("expected an error when the refresh is throttled with %s", tc.errorType)
			}
			if cache.removed != 0 || cache.data[p.StartURL] != entry {
				t.Error("throttling must keep the refresh token for the next attempt")
			}
			if n := len(f.calls("/device_authorization")); n != 0 {
				t.Errorf("device authorization started %d time(s); throttling must not open a browser", n)
			}
		})
	}
}
