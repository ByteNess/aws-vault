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
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
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
	min := time.Duration(float64(base) * ssoRetryAfterJitterMin)
	max := time.Duration(float64(base) * ssoRetryAfterJitterMax)

	for i := 0; i < 10; i++ {
		delay := jitterDelay(base)
		if delay < min || max < delay {
			t.Fatalf("expected delay in range %s-%s, got %s", min, max, delay)
		}
	}
}

func TestJitteredBackoffProgression(t *testing.T) {
	base := 200 * time.Millisecond
	max := 5 * time.Second

	// Each attempt should double the cap: 200ms, 400ms, 800ms, 1600ms, 3200ms, 5000ms (capped)
	for attempt := 1; attempt <= 8; attempt++ {
		expectedCap := base << uint(attempt-1)
		if max < expectedCap {
			expectedCap = max
		}
		minDelay := time.Duration(float64(expectedCap) * ssoRetryAfterJitterMin)
		maxDelay := time.Duration(float64(expectedCap) * ssoRetryAfterJitterMax)

		for i := 0; i < 20; i++ {
			delay := jitteredBackoff(base, max, attempt)
			if delay < minDelay || maxDelay < delay {
				t.Fatalf("attempt %d: expected delay in range %s-%s, got %s",
					attempt, minDelay, maxDelay, delay)
			}
		}
	}
}

func TestJitteredBackoffRespectsMax(t *testing.T) {
	base := 200 * time.Millisecond
	max := 5 * time.Second

	// At high attempt numbers the cap should be max, not overflow.
	// This includes attempts 37+ where base<<(attempt-1) overflows int64;
	// the delay must stay clamped to max, not collapse to base.
	minDelay := time.Duration(float64(max) * ssoRetryAfterJitterMin)
	maxDelay := time.Duration(float64(max) * ssoRetryAfterJitterMax)
	for attempt := 20; attempt <= 60; attempt++ {
		for i := 0; i < 10; i++ {
			delay := jitteredBackoff(base, max, attempt)
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
	max := 1 * time.Hour // very high max so we never hit the cap

	// Verify the cap doubles by checking that the median of many samples
	// roughly doubles. Instead, verify the deterministic cap calculation:
	// cap(attempt) = base << (attempt-1)
	for attempt := 1; attempt <= 5; attempt++ {
		expectedCap := base << uint(attempt-1)
		minBound := time.Duration(float64(expectedCap) * ssoRetryAfterJitterMin)
		maxBound := time.Duration(float64(expectedCap) * ssoRetryAfterJitterMax)

		delay := jitteredBackoff(base, max, attempt)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-Errortype", "TooManyRequestsException")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"__type":"TooManyRequestsException","message":"Rate exceeded"}`)
	}))
	defer srv.Close()

	// Disable SDK retries so our retry loop handles them
	ssoClient := sso.New(sso.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		RetryMaxAttempts: 1,
	})

	startTime := time.Unix(1000000, 0)
	clock := &testClock{now: startTime}

	p := newTestSSORoleProvider()
	p.SSOClient = ssoClient
	p.AccountID = "123456789012"
	p.RoleName = "TestRole"
	p.ssoNow = clock.Now
	p.ssoSleep = clock.Sleep
	p.ssoLogf = func(string, ...any) {} // suppress log output

	// Provide a cached OIDC token so getOIDCToken succeeds
	cache := &testTokenCache{
		token: &ssooidc.CreateTokenOutput{AccessToken: aws.String("test-token")},
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
