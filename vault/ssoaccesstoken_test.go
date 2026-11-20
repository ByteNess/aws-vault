package vault

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/keyring"
)

func TestAccessToken_ReturnsCachedToken(t *testing.T) {
	p := newTestSSORoleProvider()
	kr := keyring.NewArrayKeyring(nil)
	cache := OIDCTokenKeyring{Keyring: kr}
	if err := cache.Set(p.StartURL, &OIDCTokenData{
		Token: ssooidc.CreateTokenOutput{AccessToken: aws.String("cached-token"), ExpiresIn: 3600},
	}); err != nil {
		t.Fatal(err)
	}
	p.OIDCTokenCache = cache
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		return nil, errUnexpectedSignIn
	}

	token, err := p.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "cached-token" {
		t.Errorf("AccessToken = %q, want cached-token", token.AccessToken)
	}
	if left := time.Until(token.Expiration); left < 59*time.Minute || left > time.Hour {
		t.Errorf("Expiration is %s away, want about 1h", left)
	}
}

func TestAccessToken_SignsInAndCachesWhenCacheEmpty(t *testing.T) {
	p := newTestSSORoleProvider()
	cache := &testTokenCache{}
	p.OIDCTokenCache = cache
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		return &OIDCTokenData{
			Token: ssooidc.CreateTokenOutput{AccessToken: aws.String("new-token"), ExpiresIn: 1800},
		}, nil
	}

	token, err := p.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "new-token" {
		t.Errorf("AccessToken = %q, want new-token", token.AccessToken)
	}
	if left := time.Until(token.Expiration); left < 29*time.Minute || left > 30*time.Minute {
		t.Errorf("Expiration is %s away, want about 30m", left)
	}
	if cache.setCalls != 1 {
		t.Errorf("cache.Set called %d times, want 1", cache.setCalls)
	}
}

func TestAccessToken_SignInError(t *testing.T) {
	p := newTestSSORoleProvider()
	p.OIDCTokenCache = &testTokenCache{}
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		return nil, errUnexpectedSignIn
	}

	if _, err := p.AccessToken(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestNewSSOAccessTokenProvider(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)

	if _, err := NewSSOAccessTokenProvider(kr, &ProfileConfig{ProfileName: "plain"}, false); err == nil {
		t.Error("expected an error for a profile without SSO")
	}

	p, err := NewSSOAccessTokenProvider(kr, &ProfileConfig{
		ProfileName:           "sso",
		SSOStartURL:           "https://sso.example",
		SSORegion:             "eu-west-1",
		SSORegistrationScopes: "sso:account:access",
		SSOUseDeviceCode:      true,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.StartURL != "https://sso.example" || !p.UseDeviceCode || len(p.RegistrationScopes) != 1 {
		t.Errorf("provider not built from the profile config: %+v", p)
	}
	if p.OIDCTokenCache == nil {
		t.Error("the provider must use the keyring as its token cache")
	}
	if !p.UseSSOTokenLock {
		t.Error("parallelSafe must enable the SSO token lock")
	}
}
