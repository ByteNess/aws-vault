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
	// refreshFails makes the refresh_token grant answer InvalidGrantException.
	refreshFails bool
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
			if f.refreshFails {
				w.Header().Set("X-Amzn-Errortype", "InvalidGrantException")
				w.WriteHeader(http.StatusBadRequest)
				f.reply(w, map[string]any{"error": "invalid_grant", "error_description": "refresh token revoked"})
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
type memOIDCCache struct {
	data    map[string]*OIDCTokenData
	removed int
}

func (m *memOIDCCache) Get(k string) (*OIDCTokenData, error) {
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
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
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
	f := &fakeOIDC{refreshFails: true}
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
