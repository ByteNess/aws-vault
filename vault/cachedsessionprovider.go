package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type StsSessionProvider interface {
	aws.CredentialsProvider
	RetrieveStsCredentials(ctx context.Context) (*ststypes.Credentials, error)
}

// CachedSessionProvider retrieves cached credentials from the keyring, or if no credentials are cached
// retrieves temporary credentials using the CredentialsFunc
type CachedSessionProvider struct {
	SessionKey      SessionMetadata
	SessionProvider StsSessionProvider
	Keyring         *SessionKeyring
	ExpiryWindow    time.Duration
	UseSessionLock  bool
	sessionLock     SessionCacheLock
	sessionLockWait time.Duration
	sessionLockLog  time.Duration
	sessionNow      func() time.Time
	sessionSleep    func(context.Context, time.Duration) error
	sessionLogf     lockLogger
}

const (
	// defaultSessionLockWaitDelay is the polling interval between lock attempts.
	// 100ms keeps latency low for the typical case where the lock holder
	// finishes quickly (STS call + cache write).
	defaultSessionLockWaitDelay = 100 * time.Millisecond

	// defaultSessionLockLogEvery controls how often we emit a debug log while
	// waiting for the lock. 15s avoids log spam while still showing progress.
	defaultSessionLockLogEvery = 15 * time.Second

	// defaultSessionLockWarnAfter is the delay before printing a user-visible
	// "waiting for lock" message to stderr. 5s is long enough to avoid
	// flashing the message on normal lock contention, short enough to
	// reassure the user that the process isn't hung.
	defaultSessionLockWarnAfter = 5 * time.Second
)


// NewCachedSessionProvider creates a CachedSessionProvider with production
// defaults for all internal dependencies. Tests can override unexported fields
// (sessionLock, sessionNow, etc.) after construction to inject mocks.
func NewCachedSessionProvider(key SessionMetadata, provider StsSessionProvider, keyring *SessionKeyring, expiryWindow time.Duration) *CachedSessionProvider {
	return &CachedSessionProvider{
		SessionKey:      key,
		SessionProvider: provider,
		Keyring:         keyring,
		ExpiryWindow:    expiryWindow,
		sessionLock:     NewDefaultSessionCacheLock(key.StringForMatching()),
		sessionLockWait: defaultSessionLockWaitDelay,
		sessionLockLog:  defaultSessionLockLogEvery,
		sessionNow:      time.Now,
		sessionSleep:    defaultContextSleep,
		sessionLogf:     log.Printf,
	}
}

func (p *CachedSessionProvider) RetrieveStsCredentials(ctx context.Context) (*ststypes.Credentials, error) {
	creds, cached, err := p.getCachedSession()
	if err == nil && cached {
		return creds, nil
	}

	if !p.UseSessionLock {
		return p.getSessionWithoutLock(ctx)
	}

	return p.getSessionWithLock(ctx)
}

func (p *CachedSessionProvider) getCachedSession() (creds *ststypes.Credentials, cached bool, err error) {
	creds, err = p.Keyring.Get(p.SessionKey)
	if err != nil {
		return nil, false, err
	}
	if time.Until(*creds.Expiration) < p.ExpiryWindow {
		return nil, false, nil
	}
	log.Printf("Re-using cached credentials %s from %s, expires in %s", FormatKeyForDisplay(*creds.AccessKeyId), p.SessionKey.Type, time.Until(*creds.Expiration).String())
	return creds, true, nil
}

func (p *CachedSessionProvider) getSessionWithLock(ctx context.Context) (*ststypes.Credentials, error) {
	waiter := newLockWaiter(
		p.sessionLock,
		"Waiting for session lock at %s\n",
		"Waiting for session lock at %s",
		p.sessionLockWait,
		p.sessionLockLog,
		defaultSessionLockWarnAfter,
		p.sessionNow,
		p.sessionSleep,
		p.sessionLogf,
		func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	)

	for {
		creds, cached, err := p.getCachedSession()
		if err == nil && cached {
			return creds, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		locked, err := p.sessionLock.TryLock()
		if err != nil {
			return nil, err
		}
		if locked {
			return p.doLockedSessionWork(ctx)
		}
		if sleepErr := waiter.sleepAfterMiss(ctx); sleepErr != nil {
			return nil, sleepErr
		}
	}
}

func (p *CachedSessionProvider) doLockedSessionWork(ctx context.Context) (creds *ststypes.Credentials, err error) {
	defer func() {
		if unlockErr := p.sessionLock.Unlock(); unlockErr != nil {
			err = errors.Join(err, fmt.Errorf("unlock session lock: %w", unlockErr))
		}
	}()

	creds, cached, cacheErr := p.getCachedSession()
	if cacheErr == nil && cached {
		return creds, nil
	}

	creds, err = p.SessionProvider.RetrieveStsCredentials(ctx)
	if err != nil {
		return nil, err
	}
	if err = p.Keyring.Set(p.SessionKey, creds); err != nil {
		return nil, err
	}

	return creds, nil
}

func (p *CachedSessionProvider) getSessionWithoutLock(ctx context.Context) (*ststypes.Credentials, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	creds, err := p.SessionProvider.RetrieveStsCredentials(ctx)
	if err != nil {
		return nil, err
	}

	if err = p.Keyring.Set(p.SessionKey, creds); err != nil {
		return nil, err
	}

	return creds, nil
}

// Retrieve returns cached credentials from the keyring, or if no credentials are cached
// generates a new set of temporary credentials using the CredentialsFunc
func (p *CachedSessionProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := p.RetrieveStsCredentials(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		CanExpire:       true,
		Expires:         aws.ToTime(creds.Expiration),
	}, nil
}
