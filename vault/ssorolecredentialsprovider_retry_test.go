package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/byteness/keyring"
)

func TestRetryAfterFromErrorSeconds(t *testing.T) {
	header := http.Header{}
	header.Set("Retry-After", "120")
	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: header}
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: resp},
		},
	}

	delay, ok := retryAfterFromError(err)
	if !ok {
		t.Fatal("expected retry-after delay to be detected")
	}
	if delay != 120*time.Second {
		t.Fatalf("expected 120s retry-after, got %s", delay)
	}
}

func TestRetryAfterFromErrorMissingHeader(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: resp},
		},
	}

	delay, ok := retryAfterFromError(err)
	if ok {
		t.Fatalf("expected retry-after to be absent, got %s", delay)
	}
}

func TestParseRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		value  string
		want   time.Duration
		wantOK bool
	}{
		{value: "120", want: 120 * time.Second, wantOK: true},
		{value: " 7 ", want: 7 * time.Second, wantOK: true},
		{value: "0"},
		{value: "-5"},
		{value: "Wed, 21 Oct 2015 07:28:00 GMT"},
		{value: "3600", want: ssoRetryTimeout, wantOK: true},
		{value: "9999999999", want: ssoRetryTimeout, wantOK: true},
		{value: "Fri, 01 Jan 2100 00:00:00 GMT", want: ssoRetryTimeout, wantOK: true},
		{value: ""},
		{value: "soon"},
	} {
		got, ok := parseRetryAfter(tc.value)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("parseRetryAfter(%q) = %s, %t; want %s, %t", tc.value, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestIsSSORateLimitError(t *testing.T) {
	if !isSSORateLimitError(&ssotypes.TooManyRequestsException{}) {
		t.Fatal("expected TooManyRequestsException to be rate limit error")
	}

	resp := &http.Response{StatusCode: http.StatusTooManyRequests}
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: resp},
		},
	}
	if !isSSORateLimitError(err) {
		t.Fatal("expected HTTP 429 response error to be rate limit error")
	}

	if isSSORateLimitError(errors.New("boom")) {
		t.Fatal("expected non-rate-limit error to be false")
	}
}

func TestJitterDelayRange(t *testing.T) {
	base := 10 * time.Second
	lo := time.Duration(float64(base) * ssoRetryAfterJitterMin)
	hi := time.Duration(float64(base) * ssoRetryAfterJitterMax)

	for i := 0; i < 10; i++ {
		delay := jitterDelay(base)
		if delay < lo || hi < delay {
			t.Fatalf("expected delay in range %s-%s, got %s", lo, hi, delay)
		}
	}
}

func TestJitteredBackoffProgression(t *testing.T) {
	base := 200 * time.Millisecond
	capDelay := 5 * time.Second

	// Each attempt should double the cap: 200ms, 400ms, 800ms, 1600ms, 3200ms, 5000ms (capped)
	for attempt := 1; attempt <= 8; attempt++ {
		expectedCap := base << uint(attempt-1)
		if capDelay < expectedCap {
			expectedCap = capDelay
		}
		minDelay := time.Duration(float64(expectedCap) * ssoRetryAfterJitterMin)
		maxDelay := time.Duration(float64(expectedCap) * ssoRetryAfterJitterMax)

		for i := 0; i < 20; i++ {
			delay := jitteredBackoff(base, capDelay, attempt)
			if delay < minDelay || maxDelay < delay {
				t.Fatalf("attempt %d: expected delay in range %s-%s, got %s",
					attempt, minDelay, maxDelay, delay)
			}
		}
	}
}

func TestJitteredBackoffRespectsMax(t *testing.T) {
	base := 200 * time.Millisecond
	capDelay := 5 * time.Second

	// At high attempt numbers the cap should be capDelay, not overflow.
	// This includes attempts 37+ where base<<(attempt-1) overflows int64;
	// the delay must stay clamped to capDelay, not collapse to base.
	minDelay := time.Duration(float64(capDelay) * ssoRetryAfterJitterMin)
	maxDelay := time.Duration(float64(capDelay) * ssoRetryAfterJitterMax)
	for attempt := 20; attempt <= 60; attempt++ {
		for i := 0; i < 10; i++ {
			delay := jitteredBackoff(base, capDelay, attempt)
			if maxDelay < delay {
				t.Fatalf("attempt %d: delay %s exceeds max jittered cap %s", attempt, delay, maxDelay)
			}
			if delay < minDelay {
				t.Fatalf("attempt %d: delay %s below min jittered cap %s (overflow regression)", attempt, delay, minDelay)
			}
		}
	}
}

func TestJitteredBackoffDoublesPerAttempt(t *testing.T) {
	base := 1 * time.Second
	maxDelay := 1 * time.Hour // very high cap so we never hit it

	// Verify the cap doubles by checking that the median of many samples
	// roughly doubles. Instead, verify the deterministic cap calculation:
	// cap(attempt) = base << (attempt-1)
	for attempt := 1; attempt <= 5; attempt++ {
		expectedCap := base << uint(attempt-1)
		minBound := time.Duration(float64(expectedCap) * ssoRetryAfterJitterMin)
		maxBound := time.Duration(float64(expectedCap) * ssoRetryAfterJitterMax)

		delay := jitteredBackoff(base, maxDelay, attempt)
		if delay < minBound || maxBound < delay {
			t.Fatalf("attempt %d: expected delay in [%s, %s], got %s",
				attempt, minBound, maxBound, delay)
		}
	}
}

func TestJitterRetryAfterRange(t *testing.T) {
	base := 2 * time.Second
	// jitterRetryAfter clamps to >= base so the server's Retry-After is
	// always respected, even though jitterDelay can go as low as 0.5*base.
	maxDelay := time.Duration(float64(base) * ssoRetryAfterJitterMax)

	for i := 0; i < 50; i++ {
		delay := jitterRetryAfter(base)
		if delay < base || maxDelay < delay {
			t.Fatalf("jitterRetryAfter(%s): expected delay in range %s-%s, got %s",
				base, base, maxDelay, delay)
		}
	}
}

func TestJitterRetryAfterZeroBase(t *testing.T) {
	delay := jitterRetryAfter(0)
	if delay != 0 {
		t.Fatalf("expected 0 delay for zero base, got %s", delay)
	}
}

func TestJitterRetryAfterNegativeBase(t *testing.T) {
	delay := jitterRetryAfter(-1 * time.Second)
	if delay != 0 {
		t.Fatalf("expected 0 delay for negative base, got %s", delay)
	}
}

func TestGetRoleCredentialsTimeoutOnPersistentRateLimit(t *testing.T) {
	// Set up an HTTP server that always returns 429 with a TooManyRequestsException
	// body that the AWS SDK will deserialize into a TooManyRequestsException error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-Errortype", "TooManyRequestsException")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, `{"__type":"TooManyRequestsException","message":"Rate exceeded"}`)
	}))
	defer srv.Close()

	// Disable SDK retries so our retry loop handles them
	ssoClient := sso.New(sso.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		RetryMaxAttempts: 1,
	})

	startTime := time.Unix(1000000, 0)
	clock := &testClock{now: startTime}

	p := newTestSSORoleProvider()
	p.SSOClient = ssoClient
	p.AccountID = "123456789012"
	p.RoleName = "TestRole"
	p.RetryRateLimit = true
	p.ssoNow = clock.Now
	p.ssoSleep = clock.Sleep
	p.ssoLogf = func(string, ...any) {} // suppress log output

	// Provide a cached OIDC token so getOIDCToken succeeds
	cache := &testTokenCache{
		token: testToken("test-token"),
	}
	p.OIDCTokenCache = cache

	_, err := p.getRoleCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error after timeout, got nil")
	}

	if !strings.Contains(err.Error(), "persistently") {
		t.Fatalf("expected timeout error mentioning 'persistently', got: %v", err)
	}
	if !strings.Contains(err.Error(), ssoRetryTimeout.String()) {
		t.Fatalf("expected error to mention timeout duration %s, got: %v", ssoRetryTimeout, err)
	}

	// Verify the clock advanced past the retry timeout
	elapsed := clock.now.Sub(time.Unix(1000000, 0))
	if elapsed < ssoRetryTimeout {
		t.Fatalf("expected clock to advance at least %s, advanced %s", ssoRetryTimeout, elapsed)
	}
}

// rateLimitServer answers GetRoleCredentials from the replies queue, one per
// call, and then with credentials. It records the bearer token of each call,
// and runs onCall, if set, before replying.
type rateLimitServer struct {
	replies    []int
	tokens     []string
	onCall     func(call int)
	retryAfter string
}

func (s *rateLimitServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.tokens = append(s.tokens, r.Header.Get("X-Amz-Sso_bearer_token"))
	if s.onCall != nil {
		s.onCall(len(s.tokens))
	}
	w.Header().Set("Content-Type", "application/json")
	if len(s.replies) == 0 {
		_, _ = fmt.Fprint(w, `{"roleCredentials":{"accessKeyId":"AKIAEXAMPLE","secretAccessKey":"secret","sessionToken":"token","expiration":4102444800000}}`)
		return
	}
	status := s.replies[0]
	s.replies = s.replies[1:]
	switch status {
	case http.StatusTooManyRequests:
		w.Header().Set("X-Amzn-Errortype", "TooManyRequestsException")
		if s.retryAfter != "" {
			w.Header().Set("Retry-After", s.retryAfter)
		}
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, `{"__type":"TooManyRequestsException","message":"Rate exceeded"}`)
	case http.StatusUnauthorized:
		w.Header().Set("X-Amzn-Errortype", "UnauthorizedException")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, `{"__type":"UnauthorizedException","message":"Session token not found or invalid"}`)
	default:
		w.WriteHeader(status)
	}
}

func newRateLimitTestProvider(t *testing.T, s *rateLimitServer) (*SSORoleCredentialsProvider, *testClock) {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	clock := &testClock{now: time.Unix(1000000, 0)}
	p := newTestSSORoleProvider()
	p.SSOClient = sso.New(sso.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		RetryMaxAttempts: 1,
	})
	p.AccountID = "123456789012"
	p.RoleName = "TestRole"
	p.OIDCTokenCache = &testTokenCache{token: testToken("cached")}
	p.ssoNow = clock.Now
	p.ssoSleep = clock.Sleep
	return p, clock
}

// The 429 retry belongs to --parallel-safe. Without it a rate limit fails at
// once, as it does on main.
func TestGetRoleCredentialsFailsOnRateLimitWithoutParallelSafe(t *testing.T) {
	s := &rateLimitServer{replies: []int{http.StatusTooManyRequests}}
	p, clock := newRateLimitTestProvider(t, s)

	_, err := p.getRoleCredentials(context.Background())
	if !isSSORateLimitError(err) {
		t.Fatalf("expected the rate limit error, got %v", err)
	}
	if len(s.tokens) != 1 || clock.sleepCalls != 0 {
		t.Fatalf("expected one call and no backoff, got %d calls and %d sleeps", len(s.tokens), clock.sleepCalls)
	}
}

// A 401 leads to a new sign-in, which can take longer than the whole retry
// budget. The 429s after it still get their full budget.
func TestGetRoleCredentialsRestartsRetryBudgetAfterReauthenticating(t *testing.T) {
	s := &rateLimitServer{replies: []int{http.StatusUnauthorized, http.StatusTooManyRequests}}
	p, clock := newRateLimitTestProvider(t, s)
	p.RetryRateLimit = true
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		clock.now = clock.now.Add(defaultPKCESignInTimeout)
		return testToken("signed-in"), nil
	}

	if _, err := p.getRoleCredentials(context.Background()); err != nil {
		t.Fatalf("expected the 429 after the sign-in to be retried, got %v", err)
	}
	if want := []string{"cached", "signed-in", "signed-in"}; strings.Join(s.tokens, ",") != strings.Join(want, ",") {
		t.Fatalf("calls made with tokens %v, want %v", s.tokens, want)
	}
}

func TestGetRoleCredentialsBacksOffOnUnusableRetryAfter(t *testing.T) {
	for _, retryAfter := range []string{"0", "Wed, 21 Oct 2015 07:28:00 GMT", "9999999999"} {
		t.Run(retryAfter, func(t *testing.T) {
			replies := make([]int, 1000)
			for i := range replies {
				replies[i] = http.StatusTooManyRequests
			}
			s := &rateLimitServer{replies: replies, retryAfter: retryAfter}
			p, clock := newRateLimitTestProvider(t, s)
			p.RetryRateLimit = true
			start := clock.now

			_, err := p.getRoleCredentials(context.Background())
			if err == nil || !strings.Contains(err.Error(), "persistently") {
				t.Fatalf("expected to give up once the retry budget is spent, got %v", err)
			}
			if elapsed := clock.now.Sub(start); elapsed < ssoRetryTimeout {
				t.Fatalf("%d calls in %s: the retries didn't back off", len(s.tokens), elapsed)
			}
		})
	}
}

// With --parallel-safe the SDK leaves 429s to getRoleCredentials, which
// honours Retry-After, and still retries everything else itself.
func TestLeaveRateLimitsToProvider(t *testing.T) {
	noBackoff := retry.NewStandard(func(o *retry.StandardOptions) {
		o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
	})
	for _, tc := range []struct {
		name   string
		status int
		want   int
	}{
		{"rate limit", http.StatusTooManyRequests, 1},
		{"server error", http.StatusInternalServerError, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &rateLimitServer{replies: []int{tc.status, tc.status, tc.status}}
			srv := httptest.NewServer(s)
			defer srv.Close()
			client := sso.New(sso.Options{
				Region:       "us-east-1",
				BaseEndpoint: aws.String(srv.URL),
				Retryer:      noBackoff,
			}, leaveRateLimitsToProvider)

			_, err := client.GetRoleCredentials(context.Background(), &sso.GetRoleCredentialsInput{
				AccessToken: aws.String("token"),
				AccountId:   aws.String("123456789012"),
				RoleName:    aws.String("TestRole"),
			})
			if err == nil {
				t.Fatal("expected an error")
			}
			if len(s.tokens) != tc.want {
				t.Fatalf("expected %d calls on the wire, got %d", tc.want, len(s.tokens))
			}
		})
	}
}

// keychainTokenCache reports a missing entry on Remove, as the keychain
// backend does.
type keychainTokenCache struct {
	testTokenCache
}

func (c *keychainTokenCache) Remove(string) error {
	if c.token == nil {
		return keyring.ErrKeyNotFound
	}
	c.token = nil
	return nil
}

func newLockedRejectionTestProvider(t *testing.T, s *rateLimitServer, cache OIDCTokenCacher) (*SSORoleCredentialsProvider, *int) {
	t.Helper()
	p, _ := newRateLimitTestProvider(t, s)
	p.UseSSOTokenLock = true
	p.ssoTokenLock = &recordingLock{}
	p.OIDCTokenCache = cache
	signIns := 0
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		signIns++
		return testToken("signed-in"), nil
	}
	return p, &signIns
}

// Every process holding the same cached token gets a 401 for it at about the
// same time. The first one to remove it must not make the others fail.
func TestGetRoleCredentialsWithLock_RejectedTokenAlreadyRemoved(t *testing.T) {
	cache := &keychainTokenCache{testTokenCache{token: testToken("cached")}}
	s := &rateLimitServer{replies: []int{http.StatusUnauthorized}}
	s.onCall = func(call int) {
		if call == 1 {
			cache.token = nil // another process removed it first
		}
	}
	p, signIns := newLockedRejectionTestProvider(t, s, cache)

	if _, err := p.getRoleCredentials(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *signIns != 1 {
		t.Fatalf("expected 1 sign-in, got %d", *signIns)
	}
	if want := "cached,signed-in"; strings.Join(s.tokens, ",") != want {
		t.Fatalf("calls made with tokens %v, want %s", s.tokens, want)
	}
}

// A process whose 401 arrives after another process has already signed in
// again must use that token, not remove it and open another sign-in.
func TestGetRoleCredentialsWithLock_KeepsTokenAnotherProcessStored(t *testing.T) {
	cache := &keychainTokenCache{testTokenCache{token: testToken("cached")}}
	s := &rateLimitServer{replies: []int{http.StatusUnauthorized}}
	s.onCall = func(call int) {
		if call == 1 {
			cache.token = testToken("other") // another process signed in again
		}
	}
	p, signIns := newLockedRejectionTestProvider(t, s, cache)

	if _, err := p.getRoleCredentials(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *signIns != 0 {
		t.Fatalf("expected no sign-in, got %d", *signIns)
	}
	if want := "cached,other"; strings.Join(s.tokens, ",") != want {
		t.Fatalf("calls made with tokens %v, want %s", s.tokens, want)
	}
	if cache.token == nil || aws.ToString(cache.token.Token.AccessToken) != "other" {
		t.Fatalf("the other process's token was removed from the cache")
	}
}

// A provider re-authenticates once. If the token it gets back is rejected as
// well, it fails instead of taking turns with other processes replacing it.
func TestGetRoleCredentialsReauthenticatesOnce(t *testing.T) {
	cache := &keychainTokenCache{testTokenCache{token: testToken("cached")}}
	s := &rateLimitServer{replies: []int{http.StatusUnauthorized, http.StatusUnauthorized}}
	s.onCall = func(call int) {
		if call == 1 {
			cache.token = testToken("other")
		}
	}
	p, signIns := newLockedRejectionTestProvider(t, s, cache)

	_, err := p.getRoleCredentials(context.Background())
	var rspError *awshttp.ResponseError
	if !errors.As(err, &rspError) || rspError.HTTPStatusCode() != http.StatusUnauthorized {
		t.Fatalf("expected the second 401, got %v", err)
	}
	if *signIns != 0 || len(s.tokens) != 2 {
		t.Fatalf("expected 2 calls and no sign-in, got %d calls and %d sign-ins", len(s.tokens), *signIns)
	}
}
