package vault

import (
	"log"
	"sync"
	"time"

	"github.com/byteness/keyring"
)

type lockedKeyring struct {
	inner keyring.Keyring
	lock  ProcessLock
	// mu serializes in-process access. The flock only coordinates across
	// processes; without this mutex, concurrent goroutines in the same
	// process could interleave keyring operations.
	mu sync.Mutex

	warnAfter time.Duration
	lockLogf  lockLogger
}

const (
	keyringLockPrefix = "aws-vault.keyring"

	// defaultKeyringLockWarnAfter is the delay before printing a user-visible
	// "waiting for lock" message to stderr. 5s is long enough to avoid
	// flashing the message on normal lock contention, short enough to
	// reassure the user that the process isn't hung.
	defaultKeyringLockWarnAfter = 5 * time.Second
)

// NewLockedKeyring wraps the provided keyring with a cross-process lock
// to serialize keyring operations.
func NewLockedKeyring(kr keyring.Keyring, lockKey string) keyring.Keyring {
	return &lockedKeyring{
		inner:     kr,
		lock:      NewDefaultLock(keyringLockPrefix, lockKey),
		warnAfter: defaultKeyringLockWarnAfter,
		lockLogf:  log.Printf,
	}
}

func (k *lockedKeyring) withLock(fn func() error) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if err := lockWaiting(k.lock, "keyring", k.warnAfter, k.lockLogf); err != nil {
		return err
	}

	_, err := runLocked(k.lock, "keyring", func() (struct{}, error) {
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
