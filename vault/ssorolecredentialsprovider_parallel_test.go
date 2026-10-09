package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/keyring"
)

type ssoTestServer struct {
	calls     atomic.Int32
	responses map[string]func(w http.ResponseWriter)
}

func ssoOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"roleCredentials":{"accessKeyId":"AKIAIOSFODNN7EXAMPLE","secretAccessKey":"secret","sessionToken":"session","expiration":%d}}`, time.Now().Add(time.Hour).UnixMilli())
}

func ssoUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Amzn-Errortype", "UnauthorizedException")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, `{"__type":"UnauthorizedException","message":"Session token not found or invalid"}`)
}

func ssoRateLimited(retryAfter string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-Errortype", "TooManyRequestsException")
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"__type":"TooManyRequestsException","message":"Rate exceeded"}`)
	}
}

func newSSOTestClient(t *testing.T, s *ssoTestServer) *sso.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		respond, ok := s.responses[r.Header.Get("X-Amz-Sso_bearer_token")]
		if !ok {
			ssoUnauthorized(w)
			return
		}
		respond(w)
	}))
	t.Cleanup(srv.Close)
	return sso.New(sso.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		RetryMaxAttempts: 1,
	})
}

func newParallelTestSSOProvider(t *testing.T, s *ssoTestServer, cache OIDCTokenCacher) (*SSORoleCredentialsProvider, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Unix(1000000, 0)}
	p := newTestSSORoleProvider()
	p.SSOClient = newSSOTestClient(t, s)
	p.OIDCTokenCache = cache
	p.AccountID = "123456789012"
	p.RoleName = "TestRole"
	p.ssoNow = clock.Now
	p.ssoSleep = clock.Sleep
	p.ssoLogf = func(string, ...any) {}
	return p, clock
}

func TestGetRoleCredentialsDoesNotRetryRateLimitWithoutParallelSafe(t *testing.T) {
	s := &ssoTestServer{responses: map[string]func(http.ResponseWriter){"token": ssoRateLimited("1")}}
	p, clock := newParallelTestSSOProvider(t, s, &testTokenCache{token: newTestOIDCTokenData("token")})

	if _, err := p.getRoleCredentials(context.Background()); err == nil {
		t.Fatal("expected the rate limit error, got nil")
	}
	if got := s.calls.Load(); got != 1 {
		t.Fatalf("expected 1 GetRoleCredentials call, got %d", got)
	}
	if clock.sleepCalls != 0 {
		t.Fatalf("expected no backoff sleeps, got %d", clock.sleepCalls)
	}
}

func TestGetRoleCredentialsHonoursRetryAfter(t *testing.T) {
	var limited atomic.Bool
	s := &ssoTestServer{responses: map[string]func(http.ResponseWriter){"token": func(w http.ResponseWriter) {
		if limited.CompareAndSwap(false, true) {
			ssoRateLimited("3")(w)
			return
		}
		ssoOK(w)
	}}}
	p, clock := newParallelTestSSOProvider(t, s, &testTokenCache{token: newTestOIDCTokenData("token")})
	p.RetryRateLimit = true
	start := clock.now

	if _, err := p.getRoleCredentials(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if waited := clock.now.Sub(start); waited < 3*time.Second {
		t.Fatalf("retried after %s, before the requested Retry-After of 3s", waited)
	}
}

func TestGetRoleCredentialsGivesUpWhenRetryAfterExceedsBudget(t *testing.T) {
	retryAfter := fmt.Sprint(int((ssoRetryTimeout + time.Minute) / time.Second))
	s := &ssoTestServer{responses: map[string]func(http.ResponseWriter){"token": ssoRateLimited(retryAfter)}}
	p, clock := newParallelTestSSOProvider(t, s, &testTokenCache{token: newTestOIDCTokenData("token")})
	p.RetryRateLimit = true

	_, err := p.getRoleCredentials(context.Background())
	if err == nil || !strings.Contains(err.Error(), "more than the") {
		t.Fatalf("expected an error about Retry-After exceeding the budget, got %v", err)
	}
	if clock.sleepCalls != 0 {
		t.Fatalf("expected no shortened retry, got %d sleeps", clock.sleepCalls)
	}
}

func TestGetRoleCredentialsKeepsTokenReplacedByAnotherProcess(t *testing.T) {
	cache := &testTokenCache{token: newTestOIDCTokenData("old")}
	replacement := newTestOIDCTokenData("new")
	s := &ssoTestServer{responses: map[string]func(http.ResponseWriter){
		"old": func(w http.ResponseWriter) {
			cache.token = replacement
			ssoUnauthorized(w)
		},
		"new": ssoOK,
	}}
	p, _ := newParallelTestSSOProvider(t, s, cache)
	lock := &testLock{tryResults: []bool{true, true}}
	p.ssoTokenLock = lock
	p.UseSSOTokenLock = true
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		t.Fatal("a token another process cached must not trigger a new sign-in")
		return nil, nil
	}

	if _, err := p.getRoleCredentials(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cache.token != replacement {
		t.Fatal("the replacement token was removed from the cache")
	}
	if lock.tryCalls < 1 {
		t.Fatal("expected the cached token to be invalidated under the SSO lock")
	}
}

func TestGetRoleCredentialsReauthenticatesOnlyOnce(t *testing.T) {
	cache := &testTokenCache{token: newTestOIDCTokenData("old")}
	s := &ssoTestServer{responses: map[string]func(http.ResponseWriter){
		"old": func(w http.ResponseWriter) {
			cache.token = newTestOIDCTokenData("other")
			ssoUnauthorized(w)
		},
	}}
	p, _ := newParallelTestSSOProvider(t, s, cache)

	if _, err := p.getRoleCredentials(context.Background()); err == nil {
		t.Fatal("expected an unauthorized error, got nil")
	}
	if got := s.calls.Load(); got != 2 {
		t.Fatalf("expected 2 GetRoleCredentials calls, got %d", got)
	}
}

func TestUsableCachedOIDCTokenDoesNotRemoveExpiredToken(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	cache := OIDCTokenKeyring{Keyring: kr}
	expired := OIDCTokenData{Token: ssooidc.CreateTokenOutput{AccessToken: aws.String("expired"), ExpiresIn: -60}}
	if err := cache.Set("https://sso.example", &expired); err != nil {
		t.Fatal(err)
	}

	p := newTestSSORoleProvider()
	p.OIDCTokenCache = cache

	if _, ok, err := p.usableCachedOIDCToken(); err != nil || ok {
		t.Fatalf("usableCachedOIDCToken() = ok %t, err %v, want not usable", ok, err)
	}
	if _, err := kr.Get(cache.fmtKey("https://sso.example")); err != nil {
		t.Fatalf("expired token was removed outside the SSO lock: %v", err)
	}
}

func TestUsableCachedOIDCTokenAcceptsValidNonRefreshableToken(t *testing.T) {
	data := &OIDCTokenData{
		Token:      ssooidc.CreateTokenOutput{AccessToken: aws.String("short")},
		Expiration: time.Now().Add(time.Minute),
	}
	p := newTestSSORoleProvider()
	p.OIDCTokenCache = &testTokenCache{token: data}

	token, ok, err := p.usableCachedOIDCToken()
	if err != nil || !ok || token != &data.Token {
		t.Fatalf("usableCachedOIDCToken() = %v, %t, %v, want the cached token", token, ok, err)
	}
}

func TestSSORoleCredentialsProviderLiteralDoesNotPanic(t *testing.T) {
	s := &ssoTestServer{responses: map[string]func(http.ResponseWriter){"token": ssoOK}}
	p := &SSORoleCredentialsProvider{
		SSOClient:       newSSOTestClient(t, s),
		OIDCTokenCache:  &testTokenCache{token: newTestOIDCTokenData("token")},
		StartURL:        "https://sso.example",
		AccountID:       "123456789012",
		RoleName:        "TestRole",
		UseSSOTokenLock: true,
		RetryRateLimit:  true,
	}

	if _, err := p.Retrieve(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestThrottleRetryerLeavesRateLimitsToProvider(t *testing.T) {
	retryAfter := fmt.Sprint(int((ssoRetryTimeout + time.Minute) / time.Second))
	s := &ssoTestServer{responses: map[string]func(http.ResponseWriter){"token": ssoRateLimited(retryAfter)}}
	srv := newSSOTestClient(t, s)
	client := sso.New(srv.Options(), func(o *sso.Options) {
		o.RetryMaxAttempts = 3
	}, leaveThrottlingToProvider)

	p, _ := newParallelTestSSOProvider(t, s, &testTokenCache{token: newTestOIDCTokenData("token")})
	p.SSOClient = client
	p.RetryRateLimit = true

	if _, err := p.getRoleCredentials(context.Background()); err == nil {
		t.Fatal("expected a rate limit error, got nil")
	}
	if got := s.calls.Load(); got != 1 {
		t.Fatalf("expected the SDK not to retry throttling itself, got %d calls", got)
	}
}
