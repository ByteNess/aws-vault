package vault

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

// ProcessLock coordinates work across processes.
type ProcessLock interface {
	TryLock() (bool, error)
	Lock() error
	Unlock() error
	Path() string
}

func hashedLockFilename(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s.%x.lock", prefix, sum)
}

type defaultProcessLock struct {
	filename string

	once sync.Once
	lock *flock.Flock
	err  error

	held sync.Mutex
}

// NewDefaultLock creates a ProcessLock in the per-user lock directory.
// The lock file name is derived from the prefix and a SHA-256 hash of key.
func NewDefaultLock(prefix, key string) ProcessLock {
	return &defaultProcessLock{filename: hashedLockFilename(prefix, key)}
}

func (l *defaultProcessLock) resolve() error {
	l.once.Do(func() {
		dir, err := lockDir()
		if err != nil {
			l.err = err
			return
		}
		l.lock = flock.New(filepath.Join(dir, l.filename))
	})
	return l.err
}

func (l *defaultProcessLock) TryLock() (bool, error) {
	if err := l.resolve(); err != nil {
		return false, err
	}
	if !l.held.TryLock() {
		return false, nil
	}
	locked, err := l.lock.TryLock()
	if err != nil || !locked {
		l.held.Unlock()
	}
	return locked, err
}

func (l *defaultProcessLock) Lock() error {
	if err := l.resolve(); err != nil {
		return err
	}
	l.held.Lock()
	if err := l.lock.Lock(); err != nil {
		l.held.Unlock()
		return err
	}
	return nil
}

func (l *defaultProcessLock) Unlock() error {
	if err := l.resolve(); err != nil {
		return err
	}
	err := l.lock.Unlock()
	l.held.Unlock()
	return err
}

func lockWaiting(lock ProcessLock, name string, warnAfter time.Duration, logf lockLogger) error {
	locked, err := lock.TryLock()
	if err != nil || locked {
		return err
	}

	path := lock.Path()
	if logf != nil {
		logf("Waiting for %s lock at %s", name, path)
	}
	warning := time.AfterFunc(warnAfter, func() {
		warnToStderr("Waiting for %s lock at %s\n", name, path)
	})
	defer warning.Stop()
	return lock.Lock()
}

// WithKeyringLock runs fn while holding the cross-process keyring lock for
// lockKey, the lock NewLockedKeyring takes for each keyring operation.
func WithKeyringLock(lockKey string, fn func() error) error {
	lock := NewDefaultLock(keyringLockPrefix, lockKey)
	if err := lockWaiting(lock, "keyring", defaultKeyringLockWarnAfter, log.Printf); err != nil {
		return err
	}
	_, err := runLocked(lock, "keyring", func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}

func (l *defaultProcessLock) Path() string {
	if err := l.resolve(); err != nil {
		return l.filename
	}
	return l.lock.Path()
}

// defaultContextSleep sleeps for d, respecting ctx cancellation.
// Shared by all lock-wait loops.
func defaultContextSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
