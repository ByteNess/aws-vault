package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/keyring"
)

// errUnexpectedSignIn marks a sign-in stub that the test expects never to run.
var errUnexpectedSignIn = errors.New("sign-in should not have been attempted")

type testTokenCache struct {
	token    *OIDCTokenData
	setCalls int
	setLock  *testLock
}

func (c *testTokenCache) Get(string) (*OIDCTokenData, error) {
	if c.token == nil {
		return nil, keyring.ErrKeyNotFound
	}
	return c.token, nil
}

func (c *testTokenCache) Set(_ string, data *OIDCTokenData) error {
	c.setCalls++
	if c.setLock != nil && !c.setLock.locked {
		return fmt.Errorf("lock not held during cache set")
	}
	c.token = data
	return nil
}

// testToken is a cache entry that is valid for long enough that the refresh
// window never fires, so these tests exercise the lock and nothing else.
func testToken(accessToken string) *OIDCTokenData {
	return &OIDCTokenData{
		Token:      ssooidc.CreateTokenOutput{AccessToken: aws.String(accessToken)},
		Expiration: time.Now().Add(time.Hour),
	}
}

func (c *testTokenCache) Remove(string) error {
	c.token = nil
	return nil
}

func newTestSSORoleProvider() *SSORoleCredentialsProvider {
	p := &SSORoleCredentialsProvider{
		StartURL: "https://sso.example",
	}
	p.initSSODefaults()
	return p
}

func TestGetOIDCToken_CacheHit_NoLock(t *testing.T) {
	cachedToken := testToken("cached")
	cache := &testTokenCache{token: cachedToken}
	lock := &testLock{}

	p := newTestSSORoleProvider()
	p.OIDCTokenCache = cache
	p.ssoTokenLock = lock
	p.UseSSOTokenLock = true
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		t.Fatal("newOIDCToken should not be called on cache hit")
		return nil, errUnexpectedSignIn
	}

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cached {
		t.Fatalf("expected cached token")
	}
	if token != &cachedToken.Token {
		t.Fatalf("unexpected token returned")
	}
	if lock.tryCalls != 0 {
		t.Fatalf("expected no lock attempts, got %d", lock.tryCalls)
	}
}

func TestGetOIDCToken_LockDisabled_SkipsLock(t *testing.T) {
	freshToken := testToken("fresh")
	cache := &testTokenCache{}
	lock := &testLock{tryResults: []bool{true}}

	p := newTestSSORoleProvider()
	p.OIDCTokenCache = cache
	p.ssoTokenLock = lock
	p.UseSSOTokenLock = false
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		return freshToken, nil
	}

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cached {
		t.Fatalf("expected non-cached token")
	}
	if token != &freshToken.Token {
		t.Fatalf("unexpected token returned")
	}
	if lock.tryCalls != 0 {
		t.Fatalf("expected no lock attempts, got %d", lock.tryCalls)
	}
	if cache.setCalls != 1 {
		t.Fatalf("expected cache set once, got %d", cache.setCalls)
	}
}

func TestGetOIDCToken_LockMiss_ThenCacheHit_NoLock(t *testing.T) {
	cachedToken := testToken("cached")
	cache := &testTokenCache{}
	lock := &testLock{tryResults: []bool{false}}
	clock := &testClock{now: time.Unix(0, 0)}

	p := newTestSSORoleProvider()
	p.OIDCTokenCache = cache
	p.ssoTokenLock = lock
	p.UseSSOTokenLock = true
	p.ssoLockWait = 5 * time.Second
	p.ssoNow = clock.Now
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		t.Fatal("newOIDCToken should not be called when cache fills while waiting")
		return nil, errUnexpectedSignIn
	}
	p.ssoSleep = func(_ context.Context, d time.Duration) error {
		clock.now = clock.now.Add(d)
		cache.token = cachedToken
		return nil
	}

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cached {
		t.Fatalf("expected cached token")
	}
	if token != &cachedToken.Token {
		t.Fatalf("unexpected token returned")
	}
	if lock.tryCalls != 1 {
		t.Fatalf("expected 1 lock attempt, got %d", lock.tryCalls)
	}
	if lock.unlockCalls != 0 {
		t.Fatalf("expected no unlocks, got %d", lock.unlockCalls)
	}
}

func TestGetOIDCToken_LockAcquired_RecheckCache(t *testing.T) {
	cachedToken := testToken("cached")
	cache := &testTokenCache{}
	lock := &testLock{tryResults: []bool{true}}
	lock.onTry = func(l *testLock) {
		if l.locked {
			cache.token = cachedToken
		}
	}

	p := newTestSSORoleProvider()
	p.OIDCTokenCache = cache
	p.ssoTokenLock = lock
	p.UseSSOTokenLock = true
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		t.Fatal("newOIDCToken should not be called when cache is filled after lock")
		return nil, errUnexpectedSignIn
	}

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cached {
		t.Fatalf("expected cached token")
	}
	if token != &cachedToken.Token {
		t.Fatalf("unexpected token returned")
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
}

func TestGetOIDCToken_LockHeldThroughCacheSet(t *testing.T) {
	freshToken := testToken("fresh")
	lock := &testLock{tryResults: []bool{true}}
	cache := &testTokenCache{setLock: lock}

	p := newTestSSORoleProvider()
	p.OIDCTokenCache = cache
	p.ssoTokenLock = lock
	p.UseSSOTokenLock = true
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		return freshToken, nil
	}

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cached {
		t.Fatalf("expected non-cached token")
	}
	if token != &freshToken.Token {
		t.Fatalf("unexpected token returned")
	}
	if cache.setCalls != 1 {
		t.Fatalf("expected cache set once, got %d", cache.setCalls)
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
}

// --stdout selects the device code flow, which starts a device authorization
// and prints a URL per process. That is the same storm the lock exists to
// prevent, so stdout is serialised like the browser flows rather than skipped.
func TestGetOIDCToken_UseStdout_TakesLock(t *testing.T) {
	freshToken := testToken("fresh")
	lock := &testLock{tryResults: []bool{true}}
	cache := &testTokenCache{}

	p := newTestSSORoleProvider()
	p.OIDCTokenCache = cache
	p.ssoTokenLock = lock
	p.UseStdout = true
	p.UseSSOTokenLock = true
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		return freshToken, nil
	}

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cached {
		t.Fatalf("expected non-cached token")
	}
	if token != &freshToken.Token {
		t.Fatalf("unexpected token returned")
	}
	if lock.tryCalls != 1 {
		t.Fatalf("expected the sign-in to be serialised, got %d lock attempts", lock.tryCalls)
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
}

func TestGetOIDCToken_LockWaitLogs(t *testing.T) {
	lock := &testLock{tryResults: []bool{false, false, false, false}}
	cache := &testTokenCache{}
	ctx, cancel := context.WithCancel(context.Background())
	clock := &testClock{now: time.Unix(0, 0), cancel: cancel, cancelAfter: 4}
	var logTimes []time.Time

	p := newTestSSORoleProvider()
	p.OIDCTokenCache = cache
	p.ssoTokenLock = lock
	p.UseSSOTokenLock = true
	p.ssoLockWait = 5 * time.Second
	p.ssoLockLog = 15 * time.Second
	p.ssoNow = clock.Now
	p.ssoSleep = clock.Sleep
	p.ssoLogf = func(string, ...any) {
		logTimes = append(logTimes, clock.Now())
	}
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		t.Fatal("newOIDCToken should not be called when lock never acquired")
		return nil, errUnexpectedSignIn
	}

	_, _, err := p.getOIDCToken(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if len(logTimes) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(logTimes))
	}
	if !logTimes[0].Equal(time.Unix(0, 0)) {
		t.Fatalf("unexpected first log time: %s", logTimes[0])
	}
	if !logTimes[1].Equal(time.Unix(15, 0)) {
		t.Fatalf("unexpected second log time: %s", logTimes[1])
	}
}

func TestGetOIDCToken_WorkNotCancelledByLockTimeout(t *testing.T) {
	// The lock-wait timeout should only bound how long we wait for the
	// lock, not how long the work takes. Simulate work that takes longer
	// than the lock-wait timeout and verify it completes.
	freshToken := testToken("fresh")
	lock := &testLock{tryResults: []bool{true}}
	cache := &testTokenCache{setLock: lock}

	p := newTestSSORoleProvider()
	p.OIDCTokenCache = cache
	p.ssoTokenLock = lock
	p.UseSSOTokenLock = true
	p.ssoLockTimeout = 10 * time.Millisecond
	p.newOIDCTokenFn = func(ctx context.Context) (*OIDCTokenData, error) {
		// Work takes longer than the lock-wait timeout.
		// If the timeout incorrectly cancels work, ctx.Err() fires.
		select {
		case <-time.After(50 * time.Millisecond):
			return freshToken, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	token, cached, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error (work cancelled by lock-wait timeout?): %v", err)
	}
	if cached {
		t.Fatalf("expected non-cached token")
	}
	if token != &freshToken.Token {
		t.Fatalf("unexpected token returned")
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
}

// recordingLock is a ProcessLock whose state another goroutine, such as a
// fake OIDC server, can read without a data race.
type recordingLock struct{ held atomic.Bool }

func (l *recordingLock) TryLock() (bool, error) { l.held.Store(true); return true, nil }
func (l *recordingLock) Unlock() error          { l.held.Store(false); return nil }
func (l *recordingLock) Path() string           { return "recording.lock" }

// A refresh token is single use, so with the lock enabled the refresh_token
// exchange must happen while the lock is held. Otherwise every process that
// sees a token needing a refresh redeems it at once, all but one are
// rejected, and the losers can end up starting a new sign-in.
func TestGetOIDCTokenWithLock_RefreshesUnderTheLock(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expiration time.Duration
	}{
		{"expired", -time.Minute},
		{"inside the refresh window", oidcRefreshWindow / 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeOIDC{}
			lock := &recordingLock{}
			var tokenCalls, unlockedTokenCalls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					tokenCalls.Add(1)
					if !lock.held.Load() {
						unlockedTokenCalls.Add(1)
					}
				}
				f.ServeHTTP(w, r)
			}))
			t.Cleanup(srv.Close)

			cache := &memOIDCCache{data: map[string]*OIDCTokenData{}}
			p := newTestSSORoleProvider()
			p.OIDCClient = ssooidc.New(ssooidc.Options{
				Region:           "us-east-1",
				BaseEndpoint:     aws.String(srv.URL),
				HTTPClient:       srv.Client(),
				RetryMaxAttempts: 1,
			})
			p.OIDCTokenCache = cache
			p.ssoTokenLock = lock
			p.UseSSOTokenLock = true
			entry := expiredRefreshableToken()
			entry.Expiration = time.Now().Add(tc.expiration)
			cache.data[p.StartURL] = entry

			token, _, err := p.getOIDCToken(context.Background())
			if err != nil {
				t.Fatalf("getOIDCToken: %v", err)
			}
			if aws.ToString(token.AccessToken) != "access-2" {
				t.Errorf("AccessToken = %q, want the refreshed access-2", aws.ToString(token.AccessToken))
			}
			if n := tokenCalls.Load(); n != 1 {
				t.Errorf("CreateToken calls = %d, want 1 refresh", n)
			}
			if n := unlockedTokenCalls.Load(); n != 0 {
				t.Errorf("%d CreateToken call(s) made without holding the SSO lock", n)
			}
			if n := len(f.calls("/device_authorization")); n != 0 {
				t.Errorf("device authorization started %d time(s), want 0", n)
			}
		})
	}
}

// A lock waiter's timeout is a safety net for a holder that is alive but
// stuck. It must outlast the longest thing a holder does legitimately, or
// every waiter gives up on a holder that is about to finish. A holder that
// dies releases its lock at once, so a long wait costs nothing then.
func TestLockTimeoutsOutlastTheHolder(t *testing.T) {
	// The SSO lock holder can be in a browser sign-in for up to
	// defaultPKCESignInTimeout.
	if defaultSSOLockTimeout <= defaultPKCESignInTimeout {
		t.Errorf("SSO lock wait %s does not outlast a %s browser sign-in", defaultSSOLockTimeout, defaultPKCESignInTimeout)
	}
	// The session lock holder runs the whole retrieval: waiting for or doing
	// that sign-in, then GetRoleCredentials with up to ssoRetryTimeout of 429
	// retries.
	if holder := defaultSSOLockTimeout + ssoRetryTimeout; defaultSessionLockTimeout < holder {
		t.Errorf("session lock wait %s is shorter than its holder can take (%s)", defaultSessionLockTimeout, holder)
	}
	if p := newTestSSORoleProvider(); p.ssoLockTimeout != defaultSSOLockTimeout {
		t.Errorf("provider SSO lock wait = %s, want %s", p.ssoLockTimeout, defaultSSOLockTimeout)
	}
}
