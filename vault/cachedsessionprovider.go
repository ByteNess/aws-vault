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
	"github.com/byteness/keyring"
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
	sessionLock        ProcessLock
	sessionLockWait    time.Duration
	sessionLockLog     time.Duration
	sessionLockTimeout time.Duration
	sessionNow         func() time.Time
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

	// defaultSessionLockTimeout is a safety net: if the lock holder is hung,
	// waiters give up after this duration rather than blocking indefinitely.
	// 2 minutes matches the keyring lock timeout.
	defaultSessionLockTimeout = 2 * time.Minute
)

// NewCachedSessionProvider creates a CachedSessionProvider with production
// defaults for all internal dependencies. Tests can override unexported fields
// (sessionLock, sessionNow, etc.) after construction to inject mocks.
func NewCachedSessionProvider(key SessionMetadata, provider StsSessionProvider, keyring *SessionKeyring, expiryWindow time.Duration, useSessionLock bool) *CachedSessionProvider {
	return &CachedSessionProvider{
		SessionKey:      key,
		SessionProvider: provider,
		Keyring:         keyring,
		ExpiryWindow:    expiryWindow,
		UseSessionLock:  useSessionLock,
		sessionLock:        NewDefaultLock("aws-vault.session", key.StringForMatching()),
		sessionLockWait:    defaultSessionLockWaitDelay,
		sessionLockLog:     defaultSessionLockLogEvery,
		sessionLockTimeout: defaultSessionLockTimeout,
		sessionNow:         time.Now,
		sessionSleep:    defaultContextSleep,
		sessionLogf:     log.Printf,
	}
}

func (p *CachedSessionProvider) RetrieveStsCredentials(ctx context.Context) (*ststypes.Credentials, error) {
	creds, cached, err := p.getCachedSession()
	if err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
		log.Printf("Reading cached session for %s: %v; will refresh", p.SessionKey.ProfileName, err)
	}
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
	waitCtx, cancel := context.WithTimeout(ctx, p.sessionLockTimeout)
	defer cancel()

	return withProcessLock(waitCtx, p.sessionLock, lockWaiterOpts{
		LockPath:  p.sessionLock.Path(),
		WarnMsg:   "Waiting for session lock at %s\n",
		LogMsg:    "Waiting for session lock at %s",
		WaitDelay: p.sessionLockWait,
		LogEvery:  p.sessionLockLog,
		WarnAfter: defaultSessionLockWarnAfter,
		Now:       p.sessionNow,
		Sleep:     p.sessionSleep,
		Logf:      p.sessionLogf,
		Warnf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	}, "session", func() (processLockResult[*ststypes.Credentials], error) {
		creds, cached, err := p.getCachedSession()
		if err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
			log.Printf("Reading cached session for %s: %v; will try lock", p.SessionKey.ProfileName, err)
		}
		if err == nil && cached {
			return processLockResult[*ststypes.Credentials]{value: creds, ok: true}, nil
		}
		return processLockResult[*ststypes.Credentials]{}, nil
	}, func() (*ststypes.Credentials, error) {
		// Recheck cache after acquiring lock — another process may have filled it.
		creds, cached, cacheErr := p.getCachedSession()
		if cacheErr == nil && cached {
			return creds, nil
		}

		creds, err := p.SessionProvider.RetrieveStsCredentials(ctx)
		if err != nil {
			return nil, err
		}
		if err = p.Keyring.Set(p.SessionKey, creds); err != nil {
			return nil, err
		}
		return creds, nil
	})
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
