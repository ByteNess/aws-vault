package vault

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/byteness/keyring"
)

type lockedKeyring struct {
	inner keyring.Keyring
	lock  ProcessLock
	// mu serializes in-process access. The flock only coordinates across
	// processes; without this mutex, concurrent goroutines in the same
	// process could race on the try-lock loop.
	mu sync.Mutex

	lockKey     string
	lockTimeout time.Duration
	lockWait    time.Duration
	lockLog     time.Duration
	warnAfter   time.Duration
	lockNow     func() time.Time
	lockSleep   func(context.Context, time.Duration) error
	lockLogf    lockLogger
}

const (
	// defaultKeyringLockWaitDelay is the polling interval between lock attempts.
	// 100ms keeps latency low for the typical case where the lock holder
	// finishes a single keyring read/write quickly.
	defaultKeyringLockWaitDelay = 100 * time.Millisecond

	// defaultKeyringLockLogEvery controls how often we emit a debug log while
	// waiting for the lock. 15s avoids log spam while still showing progress.
	defaultKeyringLockLogEvery = 15 * time.Second

	// defaultKeyringLockWarnAfter is the delay before printing a user-visible
	// "waiting for lock" message to stderr. 5s is long enough to avoid
	// flashing the message on normal lock contention, short enough to
	// reassure the user that the process isn't hung.
	defaultKeyringLockWarnAfter = 5 * time.Second

	// defaultKeyringLockTimeout is a safety net: the keyring.Keyring interface
	// is not context-aware, so if the lock holder is hung (e.g. a stuck gpg
	// subprocess in the pass backend), waiters give up after this duration
	// rather than blocking indefinitely. 2 minutes is generous enough for any
	// reasonable keyring operation.
	defaultKeyringLockTimeout = 2 * time.Minute
)

// NewLockedKeyring wraps the provided keyring with a cross-process lock
// to serialize keyring operations.
func NewLockedKeyring(kr keyring.Keyring, lockKey string) keyring.Keyring {
	return &lockedKeyring{
		inner:       kr,
		lock:        NewDefaultLock("aws-vault.keyring", lockKey),
		lockKey:     lockKey,
		lockTimeout: defaultKeyringLockTimeout,
		lockWait:    defaultKeyringLockWaitDelay,
		lockLog:     defaultKeyringLockLogEvery,
		warnAfter:   defaultKeyringLockWarnAfter,
		lockNow:     time.Now,
		lockSleep:   defaultContextSleep,
		lockLogf:    log.Printf,
	}
}


func (k *lockedKeyring) withLock(fn func() error) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// The keyring.Keyring interface is not context-aware, so we cannot cancel
	// in-flight keyring operations. This timeout is a safety net for the lock-wait
	// loop: if the lock holder is hung (e.g. a stuck gpg subprocess in the pass
	// backend), waiters will eventually give up rather than blocking indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), k.lockTimeout)
	defer cancel()

	_, err := withProcessLock(ctx, k.lock, lockWaiterOpts{
		Lock:      k.lock,
		WarnMsg:   "Waiting for keyring lock at %s\n",
		LogMsg:    "Waiting for keyring lock at %s",
		WaitDelay: k.lockWait,
		LogEvery:  k.lockLog,
		WarnAfter: k.warnAfter,
		Now:       k.lockNow,
		Sleep:     k.lockSleep,
		Logf:      k.lockLogf,
		Warnf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	}, "keyring", nil, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}

func (k *lockedKeyring) Get(key string) (keyring.Item, error) {
	var item keyring.Item
	if err := k.withLock(func() error {
		var err error
		item, err = k.inner.Get(key)
		return err
	}); err != nil {
		return keyring.Item{}, err
	}
	return item, nil
}

func (k *lockedKeyring) GetMetadata(key string) (keyring.Metadata, error) {
	var meta keyring.Metadata
	if err := k.withLock(func() error {
		var err error
		meta, err = k.inner.GetMetadata(key)
		return err
	}); err != nil {
		return keyring.Metadata{}, err
	}
	return meta, nil
}

func (k *lockedKeyring) Set(item keyring.Item) error {
	return k.withLock(func() error {
		return k.inner.Set(item)
	})
}

func (k *lockedKeyring) Remove(key string) error {
	return k.withLock(func() error {
		return k.inner.Remove(key)
	})
}

func (k *lockedKeyring) Keys() ([]string, error) {
	var keys []string
	if err := k.withLock(func() error {
		var err error
		keys, err = k.inner.Keys()
		return err
	}); err != nil {
		return nil, err
	}
	return keys, nil
}
