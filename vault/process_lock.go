package vault

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// ProcessLock coordinates work across processes.
type ProcessLock interface {
	TryLock() (bool, error)
	Unlock() error
	Path() string
}

type fileProcessLock struct {
	lock *flock.Flock
}

// NewFileLock creates a lock at the provided path.
func NewFileLock(path string) ProcessLock {
	return &fileProcessLock{lock: flock.New(path)}
}

func (l *fileProcessLock) TryLock() (bool, error) {
	return l.lock.TryLock()
}

func (l *fileProcessLock) Unlock() error {
	return l.lock.Unlock()
}

func (l *fileProcessLock) Path() string {
	return l.lock.Path()
}

func defaultLockPath(filename string) string {
	return filepath.Join(os.TempDir(), filename)
}

func hashedLockFilename(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s.%x.lock", prefix, sum)
}

// NewDefaultLock creates a ProcessLock in the system temp directory.
// The lock file name is derived from the prefix and a SHA-256 hash of key.
func NewDefaultLock(prefix, key string) ProcessLock {
	return NewFileLock(defaultLockPath(hashedLockFilename(prefix, key)))
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
