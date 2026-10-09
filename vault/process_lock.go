package vault

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

// ProcessLock coordinates work across processes.
type ProcessLock interface {
	TryLock() (bool, error)
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
	return l.lock.TryLock()
}

func (l *defaultProcessLock) Unlock() error {
	if err := l.resolve(); err != nil {
		return err
	}
	return l.lock.Unlock()
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
