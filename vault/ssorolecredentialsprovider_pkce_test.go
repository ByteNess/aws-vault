package vault

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

const fakeStartURL = "https://d-1234567890.awsapps.com/start"

// fakePKCEOIDC is a minimal IAM Identity Center OIDC service that enforces the
// PKCE authorization code flow.
type fakePKCEOIDC struct {
	t    *testing.T
	deny bool // redirect back with access_denied instead of a code
	// scopes is the provider's sso_registration_scopes; empty expects the default
	scopes []string

	mu          sync.Mutex
	challenge   string
	redirectURI string
	codeUsed    bool
}

func (f *fakePKCEOIDC) wantScopes() []string {
	if len(f.scopes) > 0 {
		return f.scopes
	}
	return []string{"sso:account:access"}
}

func (f *fakePKCEOIDC) fail(w http.ResponseWriter, format string, args ...any) {
	f.t.Errorf(format, args...)
	w.Header().Set("X-Amzn-ErrorType", "InvalidRequestException")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = io.WriteString(w, `{"error":"invalid_request"}`)
}

func (f *fakePKCEOIDC) reply(w http.ResponseWriter, v map[string]any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Errorf("encoding reply: %v", err)
	}
}

func (f *fakePKCEOIDC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/client/register":
		var in struct {
			GrantTypes   []string
			RedirectURIs []string
			Scopes       []string
			IssuerURL    string
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			f.fail(w, "register: %v", err)
			return
		}
		if strings.Join(in.GrantTypes, ",") != "authorization_code,refresh_token" ||
			strings.Join(in.RedirectURIs, ",") != "http://127.0.0.1/oauth/callback" ||
			strings.Join(in.Scopes, ",") != strings.Join(f.wantScopes(), ",") || in.IssuerURL != fakeStartURL {
			f.fail(w, "register: unexpected input %+v", in)
			return
		}
		f.reply(w, map[string]any{
			"clientId": "client-id", "clientSecret": "client-secret",
			"clientIdIssuedAt": time.Now().Unix(), "clientSecretExpiresAt": time.Now().Add(time.Hour).Unix(),
		})

	case r.Method == http.MethodGet && r.URL.Path == "/authorize":
		q := r.URL.Query()
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil || redirect.Scheme != "http" || redirect.Hostname() != "127.0.0.1" || redirect.Path != "/oauth/callback" {
			f.fail(w, "authorize: redirect_uri %q is not the loopback callback", q.Get("redirect_uri"))
			return
		}
		if q.Get("client_id") != "client-id" || q.Get("response_type") != "code" ||
			q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
			q.Get("scopes") != strings.Join(f.wantScopes(), " ") || q.Get("state") == "" {
			f.fail(w, "authorize: unexpected query %v", q)
			return
		}
		f.challenge, f.redirectURI = q.Get("code_challenge"), q.Get("redirect_uri")
		back := url.Values{"state": {q.Get("state")}}
		if f.deny {
			back.Set("error", "access_denied")
			back.Set("error_description", "denied by user")
		} else {
			back.Set("code", "auth-code")
		}
		http.Redirect(w, r, f.redirectURI+"?"+back.Encode(), http.StatusFound)

	case r.Method == http.MethodPost && r.URL.Path == "/token":
		var in struct {
			ClientID, ClientSecret, GrantType, Code, CodeVerifier, RedirectURI string
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			f.fail(w, "token: %v", err)
			return
		}
		// RFC 7636 §4.1: 43-128 characters from the unreserved set
		if !regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`).MatchString(in.CodeVerifier) {
			f.fail(w, "token: code_verifier %q is not a valid RFC 7636 verifier", in.CodeVerifier)
			return
		}
		sum := sha256.Sum256([]byte(in.CodeVerifier))
		switch {
		case in.GrantType != "authorization_code" || in.ClientID != "client-id" || in.ClientSecret != "client-secret":
			f.fail(w, "token: unexpected client or grant %+v", in)
		case in.Code != "auth-code" || f.codeUsed:
			f.fail(w, "token: code %q unknown or already used", in.Code)
		case base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge:
			f.fail(w, "token: code_verifier does not match the S256 code_challenge")
		case in.RedirectURI != f.redirectURI:
			f.fail(w, "token: redirect_uri %q differs from the authorize request's %q", in.RedirectURI, f.redirectURI)
		default:
			f.codeUsed = true
			f.reply(w, map[string]any{
				"accessToken": "access-token", "refreshToken": "refresh-token", "tokenType": "Bearer", "expiresIn": 3600,
			})
		}

	default:
		f.fail(w, "unexpected request %s %s", r.Method, r.URL.Path)
	}
}

// runPKCE runs the PKCE flow against f, with a "browser" that follows the
// redirect to the callback server and returns the page it shows.
func runPKCE(t *testing.T, f *fakePKCEOIDC) (*OIDCTokenData, string, error) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	page := make(chan string, 1)
	orig := openBrowser
	t.Cleanup(func() { openBrowser = orig })
	openBrowser = func(u, _ string) error {
		if !strings.HasPrefix(u, srv.URL+"/authorize?") {
			t.Errorf("browser opened %q, want the authorize endpoint on %s", u, srv.URL)
		}
		go func() {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
			if err != nil {
				page <- "error: " + err.Error()
				return
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				page <- "error: " + err.Error()
				return
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(resp.Body)
			page <- string(b)
		}()
		return nil
	}

	p := &SSORoleCredentialsProvider{
		OIDCClient:         ssooidc.New(ssooidc.Options{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL)}),
		StartURL:           fakeStartURL,
		RegistrationScopes: f.scopes,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := p.newOIDCTokenPKCE(ctx)

	select {
	case shown := <-page:
		return tok, shown, err
	case <-time.After(5 * time.Second):
		t.Fatal("browser never got a response from the callback server")
		return nil, "", nil
	}
}

func TestNewOIDCTokenPKCE_EndToEnd(t *testing.T) {
	tok, shown, err := runPKCE(t, &fakePKCEOIDC{t: t})
	if err != nil {
		t.Fatalf("newOIDCTokenPKCE: %v", err)
	}
	if aws.ToString(tok.Token.AccessToken) != "access-token" {
		t.Errorf("access token = %q, want access-token", aws.ToString(tok.Token.AccessToken))
	}
	if !strings.Contains(shown, "Request approved") {
		t.Errorf("browser showed %q, want the success page", shown)
	}
}

// The configured scopes replace the default, and the authorize URL carries
// them space separated, as in the AWS CLI.
func TestNewOIDCTokenPKCE_ConfiguredScopes(t *testing.T) {
	f := &fakePKCEOIDC{t: t, scopes: []string{"sso:account:access", "codewhisperer:completions"}}
	if _, _, err := runPKCE(t, f); err != nil {
		t.Fatalf("newOIDCTokenPKCE: %v", err)
	}
}

// The client registration is kept with the token so the refresh token can be
// redeemed later.
func TestNewOIDCTokenPKCE_KeepsClientRegistration(t *testing.T) {
	tok, _, err := runPKCE(t, &fakePKCEOIDC{t: t})
	if err != nil {
		t.Fatalf("newOIDCTokenPKCE: %v", err)
	}
	if tok.ClientID != "client-id" || tok.ClientSecret != "client-secret" || tok.ClientSecretExpiresAt.IsZero() {
		t.Errorf("client registration = %q/%q/%s, want client-id/client-secret and an expiry", tok.ClientID, tok.ClientSecret, tok.ClientSecretExpiresAt)
	}
	if !tok.Refreshable() {
		t.Error("a PKCE token with a refresh token should be refreshable")
	}
}

func TestNewOIDCTokenPKCE_UserDenies(t *testing.T) {
	_, shown, err := runPKCE(t, &fakePKCEOIDC{t: t, deny: true})
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("err = %v, want the access_denied authorization error", err)
	}
	var ae interface{ ErrorCode() string }
	if errors.As(err, &ae) {
		t.Errorf("err = %v, want it to come from the callback rather than the token call", err)
	}
	if !strings.Contains(shown, "Sign-in failed") || !strings.Contains(shown, "access_denied") {
		t.Errorf("browser showed %q, want the failure page", shown)
	}
}

func TestNewOIDCTokenPKCE_Timeout(t *testing.T) {
	srv := httptest.NewServer(&fakePKCEOIDC{t: t})
	t.Cleanup(srv.Close)

	origOpen, origTimeout := openBrowser, pkceSignInTimeout
	t.Cleanup(func() { openBrowser, pkceSignInTimeout = origOpen, origTimeout })
	openBrowser = func(string, string) error { return nil } // the user never signs in
	pkceSignInTimeout = 50 * time.Millisecond

	p := &SSORoleCredentialsProvider{
		OIDCClient: ssooidc.New(ssooidc.Options{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL)}),
		StartURL:   fakeStartURL,
	}
	_, err := p.newOIDCTokenPKCE(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not complete") {
		t.Fatalf("err = %v, want the sign-in timeout", err)
	}
}
