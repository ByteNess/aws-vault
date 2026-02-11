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
	lock  KeychainLock
	mu    sync.Mutex

	lockKey   string
	lockWait  time.Duration
	lockLog   time.Duration
	warnAfter time.Duration
	lockNow   func() time.Time
	lockSleep func(context.Context, time.Duration) error
	lockLogf  func(string, ...any)
}

const (
	defaultKeychainLockWaitDelay = 100 * time.Millisecond
	defaultKeychainLockLogEvery  = 15 * time.Second
	defaultKeychainLockWarnAfter = 5 * time.Second
)

// NewKeychainLockedKeyring wraps the provided keyring with a cross-process lock
// to serialize keychain operations.
func NewKeychainLockedKeyring(kr keyring.Keyring, lockKey string) keyring.Keyring {
	return &lockedKeyring{
		inner:   kr,
		lock:    NewDefaultKeychainLock(lockKey),
		lockKey: lockKey,
	}
}

func (k *lockedKeyring) ensureLockDependencies() {
	if k.lock == nil {
		lockKey := k.lockKey
		if lockKey == "" {
			lockKey = "aws-vault"
		}
		k.lock = NewDefaultKeychainLock(lockKey)
	}
	if k.lockWait == 0 {
		k.lockWait = defaultKeychainLockWaitDelay
	}
	if k.lockLog == 0 {
		k.lockLog = defaultKeychainLockLogEvery
	}
	if k.warnAfter == 0 {
		k.warnAfter = defaultKeychainLockWarnAfter
	}
	if k.lockNow == nil {
		k.lockNow = time.Now
	}
	if k.lockSleep == nil {
		k.lockSleep = func(_ context.Context, d time.Duration) error {
			time.Sleep(d)
			return nil
		}
	}
	if k.lockLogf == nil {
		k.lockLogf = log.Printf
	}
}

func (k *lockedKeyring) withLock(fn func() error) error {
	k.ensureLockDependencies()

	k.mu.Lock()
	defer k.mu.Unlock()

	waiter := newLockWaiter(
		k.lock,
		"Waiting for keychain lock at %s\n",
		"Waiting for keychain lock at %s",
		k.lockWait,
		k.lockLog,
		k.warnAfter,
		k.lockNow,
		k.lockSleep,
		k.lockLogf,
		func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	)

	ctx := context.Background()
	for {
		locked, err := k.lock.TryLock()
		if err != nil {
			return err
		}
		if locked {
			err = fn()
			unlockErr := k.lock.Unlock()
			if unlockErr != nil {
				return unlockErr
			}
			return err
		}

		if err = waiter.sleepAfterMiss(ctx); err != nil {
			return err
		}
	}
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
