package vault

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/keyring"
)

var testClient = &OIDCClient{ID: "client-id", Secret: "client-secret", ExpiresAt: time.Now().Add(24 * time.Hour)}

// refreshTest is an SSO provider with a token cache, backed by a fake OIDC service.
type refreshTest struct {
	oidc  *fakeOIDC
	cache OIDCTokenKeyring
	p     *SSORoleCredentialsProvider
	page  <-chan string // pages shown by the browser; empty unless it signed in
}

func newRefreshTest(t *testing.T, f *fakeOIDC) *refreshTest {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cache := OIDCTokenKeyring{Keyring: keyring.NewArrayKeyring(nil)}
	return &refreshTest{
		oidc:  f,
		cache: cache,
		p: &SSORoleCredentialsProvider{
			OIDCClient:     ssooidc.New(ssooidc.Options{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL)}),
			OIDCTokenCache: cache,
			StartURL:       fakeStartURL,
		},
		page: fakeBrowser(t, srv),
	}
}

func (rt *refreshTest) store(t *testing.T, expiresIn time.Duration, refreshToken string, client *OIDCClient) {
	t.Helper()
	tok := &ssooidc.CreateTokenOutput{AccessToken: aws.String("stored-token"), ExpiresIn: int32(expiresIn / time.Second)}
	if refreshToken != "" {
		tok.RefreshToken = aws.String(refreshToken)
	}
	if err := rt.cache.SetData(fakeStartURL, tok, client); err != nil {
		t.Fatal(err)
	}
}

func (rt *refreshTest) getToken(t *testing.T) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, cached, err := rt.p.getOIDCToken(ctx)
	if err != nil {
		t.Fatalf("getOIDCToken: %v", err)
	}
	return aws.ToString(tok.AccessToken), cached
}

// signedIn reports whether the browser showed a sign-in page within wait.
func (rt *refreshTest) signedIn(wait time.Duration) bool {
	select {
	case <-rt.page:
		return true
	case <-time.After(wait):
		return false
	}
}

func (rt *refreshTest) refreshes() int {
	rt.oidc.mu.Lock()
	defer rt.oidc.mu.Unlock()
	return rt.oidc.refreshes
}

func (rt *refreshTest) stored(t *testing.T) *OIDCTokenData {
	t.Helper()
	d, err := rt.cache.GetData(fakeStartURL)
	if err != nil {
		t.Fatalf("GetData: %v", err)
	}
	return d
}

func TestGetOIDCToken_UsesValidToken(t *testing.T) {
	rt := newRefreshTest(t, &fakeOIDC{t: t})
	rt.store(t, time.Hour, "refresh-token", testClient)

	tok, cached := rt.getToken(t)
	if tok != "stored-token" || !cached {
		t.Errorf("got %q (cached %v), want the stored token", tok, cached)
	}
	if rt.refreshes() != 0 || rt.signedIn(0) {
		t.Error("a token with more than the refresh window left was refreshed or replaced")
	}
}

func TestGetOIDCToken_Refreshes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		expiresIn time.Duration
		noRotate  bool
		wantRT    string
	}{
		{"near expiry", 10 * time.Minute, false, "refresh-token-2"},
		{"expired", -time.Minute, false, "refresh-token-2"},
		{"refresh token not rotated", -time.Minute, true, "refresh-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRefreshTest(t, &fakeOIDC{t: t, noRotate: tc.noRotate})
			rt.store(t, tc.expiresIn, "refresh-token", testClient)

			tok, cached := rt.getToken(t)
			if tok != "refreshed-token" || cached {
				t.Errorf("got %q (cached %v), want the refreshed token", tok, cached)
			}
			if rt.refreshes() != 1 || rt.signedIn(0) {
				t.Errorf("refreshes = %d, signed in = %v, want one refresh and no sign-in", rt.refreshes(), rt.signedIn(0))
			}

			d := rt.stored(t)
			if aws.ToString(d.Token.AccessToken) != "refreshed-token" || aws.ToString(d.Token.RefreshToken) != tc.wantRT || d.Client.ID != testClient.ID {
				t.Errorf("stored %q, refresh token %q, client %+v, want the refreshed token, %q and the same client",
					aws.ToString(d.Token.AccessToken), aws.ToString(d.Token.RefreshToken), d.Client, tc.wantRT)
			}
		})
	}
}

func TestGetOIDCToken_RefreshFailsBeforeExpiry(t *testing.T) {
	rt := newRefreshTest(t, &fakeOIDC{t: t, refreshFails: true})
	rt.store(t, 10*time.Minute, "refresh-token", testClient)

	tok, cached := rt.getToken(t)
	if tok != "stored-token" || !cached {
		t.Errorf("got %q (cached %v), want the stored token while it's still valid", tok, cached)
	}
	if rt.signedIn(0) {
		t.Error("signed in again although the stored token is still valid")
	}
}

func TestGetOIDCToken_SignsInWhenNotRefreshable(t *testing.T) {
	expiredClient := &OIDCClient{ID: "client-id", Secret: "client-secret", ExpiresAt: time.Now().Add(-time.Minute)}
	for _, tc := range []struct {
		name         string
		refreshToken string
		client       *OIDCClient
		refreshFails bool
	}{
		{"refresh rejected", "refresh-token", testClient, true},
		{"stored without client", "refresh-token", nil, false},
		{"no refresh token", "", testClient, false},
		{"client registration expired", "refresh-token", expiredClient, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRefreshTest(t, &fakeOIDC{t: t, refreshFails: tc.refreshFails})
			rt.store(t, -time.Minute, tc.refreshToken, tc.client)

			tok, cached := rt.getToken(t)
			if tok != "access-token" || cached {
				t.Errorf("got %q (cached %v), want a token from a new sign-in", tok, cached)
			}
			if !rt.signedIn(5 * time.Second) {
				t.Error("didn't sign in through the browser")
			}

			d := rt.stored(t)
			if aws.ToString(d.Token.RefreshToken) != "refresh-token" || d.Client == nil || d.Client.ID != "client-id" || d.Client.Secret != "client-secret" {
				t.Errorf("stored refresh token %q and client %+v, want the new sign-in's", aws.ToString(d.Token.RefreshToken), d.Client)
			}
		})
	}
}
