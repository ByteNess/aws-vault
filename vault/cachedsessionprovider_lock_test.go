package vault

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/byteness/keyring"
)

type testSessionProvider struct {
	creds      *types.Credentials
	calls      int
	onRetrieve func()
}

func (p *testSessionProvider) RetrieveStsCredentials(context.Context) (*types.Credentials, error) {
	p.calls++
	if p.onRetrieve != nil {
		p.onRetrieve()
	}
	return p.creds, nil
}

func (p *testSessionProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, nil
}

type lockCheckingKeyring struct {
	keyring.Keyring
	setCalls int
	setLock  *testLock
}

func (k *lockCheckingKeyring) Set(item keyring.Item) error {
	k.setCalls++
	if k.setLock != nil && !k.setLock.locked {
		return fmt.Errorf("lock not held during cache set")
	}
	return k.Keyring.Set(item)
}

func newTestSessionKey() SessionMetadata {
	return SessionMetadata{
		Type:        "sso.GetRoleCredentials",
		ProfileName: "test-profile",
		MfaSerial:   "https://sso.example",
	}
}

func newTestCreds(expires time.Time) *types.Credentials {
	return &types.Credentials{
		AccessKeyId:     aws.String("AKIATEST"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
		Expiration:      aws.Time(expires),
	}
}

func TestCachedSession_CacheHit_NoLock(t *testing.T) {
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	kr := keyring.NewArrayKeyring(nil)
	sk := &SessionKeyring{Keyring: kr}
	if err := sk.Set(key, creds); err != nil {
		t.Fatalf("set cache: %v", err)
	}

	lock := &testLock{}
	provider := &testSessionProvider{
		onRetrieve: func() { t.Fatal("RetrieveStsCredentials should not be called on cache hit") },
	}

	p := NewCachedSessionProvider(key, provider, sk, 0, true)
	p.sessionLock = lock

	got, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aws.ToString(got.AccessKeyId) != aws.ToString(creds.AccessKeyId) {
		t.Fatalf("unexpected credentials returned")
	}
	if lock.tryCalls != 0 {
		t.Fatalf("expected no lock attempts, got %d", lock.tryCalls)
	}
	if provider.calls != 0 {
		t.Fatalf("expected no provider calls, got %d", provider.calls)
	}
}

func TestCachedSession_LockDisabled_SkipsLock(t *testing.T) {
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	kr := keyring.NewArrayKeyring(nil)
	sk := &SessionKeyring{Keyring: kr}
	lock := &testLock{tryResults: []bool{true}}
	provider := &testSessionProvider{creds: creds}

	p := NewCachedSessionProvider(key, provider, sk, 0, false)
	p.sessionLock = lock

	got, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aws.ToString(got.AccessKeyId) != aws.ToString(creds.AccessKeyId) {
		t.Fatalf("unexpected credentials returned")
	}
	if lock.tryCalls != 0 {
		t.Fatalf("expected no lock attempts, got %d", lock.tryCalls)
	}
	if provider.calls != 1 {
		t.Fatalf("expected 1 provider call, got %d", provider.calls)
	}
	if _, err := sk.Get(key); err != nil {
		t.Fatalf("expected cached credentials, got %v", err)
	}
}

// countingKeyring counts reads of the keyring underneath a SessionKeyring.
type countingKeyring struct {
	keyring.Keyring
	getCalls int
}

func (k *countingKeyring) Get(key string) (keyring.Item, error) {
	k.getCalls++
	return k.Keyring.Get(key)
}

// A waiter does not read the session cache while it waits: every read takes
// the keyring lock, which the holder needs to store the session. It reads
// the cache once it has the lock, and finds the session the holder stored.
func TestCachedSession_WaiterReadsCacheOnlyUnderLock(t *testing.T) {
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	kr := &countingKeyring{Keyring: keyring.NewArrayKeyring(nil)}
	sk := &SessionKeyring{Keyring: kr}
	lock := &testLock{tryResults: []bool{false, false, false, true}}

	provider := &testSessionProvider{
		onRetrieve: func() { t.Fatal("RetrieveStsCredentials should not be called when the holder stored a session") },
	}

	p := NewCachedSessionProvider(key, provider, sk, 0, true)
	p.sessionLock = lock
	p.sessionLockWait = 5 * time.Second
	p.sessionSleep = func(_ context.Context, _ time.Duration) error {
		if lock.tryCalls == 3 {
			return sk.Set(key, creds) // the holder stores the session
		}
		return nil
	}

	got, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aws.ToString(got.AccessKeyId) != aws.ToString(creds.AccessKeyId) {
		t.Fatalf("unexpected credentials returned")
	}
	if kr.getCalls != 2 {
		t.Fatalf("expected 2 cache reads (before the lock and under it), got %d", kr.getCalls)
	}
	if lock.tryCalls != 4 || lock.unlockCalls != 1 {
		t.Fatalf("expected 4 lock attempts and 1 unlock, got %d and %d", lock.tryCalls, lock.unlockCalls)
	}
	if provider.calls != 0 {
		t.Fatalf("expected no provider calls, got %d", provider.calls)
	}
}

func TestCachedSession_LockAcquired_RecheckCache(t *testing.T) {
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	kr := keyring.NewArrayKeyring(nil)
	sk := &SessionKeyring{Keyring: kr}
	lock := &testLock{tryResults: []bool{true}}
	lock.onTry = func(l *testLock) {
		if l.locked {
			_ = sk.Set(key, creds)
		}
	}

	provider := &testSessionProvider{
		onRetrieve: func() { t.Fatal("RetrieveStsCredentials should not be called when cache fills after lock") },
	}

	p := NewCachedSessionProvider(key, provider, sk, 0, true)
	p.sessionLock = lock

	got, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aws.ToString(got.AccessKeyId) != aws.ToString(creds.AccessKeyId) {
		t.Fatalf("unexpected credentials returned")
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
	if provider.calls != 0 {
		t.Fatalf("expected no provider calls, got %d", provider.calls)
	}
}

func TestCachedSession_LockHeldThroughCacheSet(t *testing.T) {
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	lock := &testLock{tryResults: []bool{true}}
	wrappedKeyring := &lockCheckingKeyring{
		Keyring: keyring.NewArrayKeyring(nil),
		setLock: lock,
	}
	sk := &SessionKeyring{Keyring: wrappedKeyring}
	provider := &testSessionProvider{creds: creds}

	p := NewCachedSessionProvider(key, provider, sk, 0, true)
	p.sessionLock = lock

	_, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wrappedKeyring.setCalls != 1 {
		t.Fatalf("expected cache set once, got %d", wrappedKeyring.setCalls)
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
	if provider.calls != 1 {
		t.Fatalf("expected 1 provider call, got %d", provider.calls)
	}
}

func TestCachedSession_LockWaitLogs(t *testing.T) {
	lock := &testLock{tryResults: []bool{false, false, false, false}}
	kr := keyring.NewArrayKeyring(nil)
	sk := &SessionKeyring{Keyring: kr}
	key := newTestSessionKey()
	provider := &testSessionProvider{}

	ctx, cancel := context.WithCancel(context.Background())
	clock := &testClock{now: time.Unix(0, 0), cancel: cancel, cancelAfter: 4}
	var logTimes []time.Time

	p := NewCachedSessionProvider(key, provider, sk, 0, true)
	p.sessionLock = lock
	p.sessionLockWait = 5 * time.Second
	p.sessionLockLog = 15 * time.Second
	p.sessionNow = clock.Now
	p.sessionSleep = clock.Sleep
	p.sessionLogf = func(string, ...any) {
		logTimes = append(logTimes, clock.Now())
	}

	_, err := p.RetrieveStsCredentials(ctx)
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

// ctxAwareSessionProvider is a test StsSessionProvider that respects context
// cancellation, used to verify the work context is not the lock-wait timeout.
type ctxAwareSessionProvider struct {
	creds *types.Credentials
	delay time.Duration
}

func (p *ctxAwareSessionProvider) RetrieveStsCredentials(ctx context.Context) (*types.Credentials, error) {
	select {
	case <-time.After(p.delay):
		return p.creds, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *ctxAwareSessionProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, nil
}

func TestCachedSession_WorkNotCancelledByLockTimeout(t *testing.T) {
	// The lock-wait timeout should only bound how long we wait for the
	// lock, not how long the work takes. Simulate a provider that takes
	// longer than the lock-wait timeout and verify it completes.
	key := newTestSessionKey()
	creds := newTestCreds(time.Now().Add(time.Hour))
	kr := keyring.NewArrayKeyring(nil)
	sk := &SessionKeyring{Keyring: kr}
	lock := &testLock{tryResults: []bool{true}}

	provider := &ctxAwareSessionProvider{creds: creds, delay: 50 * time.Millisecond}

	p := NewCachedSessionProvider(key, provider, sk, 0, true)
	p.sessionLock = lock
	p.sessionLockTimeout = 10 * time.Millisecond

	got, err := p.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error (work cancelled by lock-wait timeout?): %v", err)
	}
	if aws.ToString(got.AccessKeyId) != aws.ToString(creds.AccessKeyId) {
		t.Fatalf("unexpected credentials returned")
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
}
