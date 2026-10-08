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
	// The directory is created on first use, so building a provider has no
	// effect on disk.
	if err := os.MkdirAll(filepath.Dir(l.lock.Path()), 0o700); err != nil {
		return false, err
	}
	return l.lock.TryLock()
}

func (l *fileProcessLock) Unlock() error {
	return l.lock.Unlock()
}

func (l *fileProcessLock) Path() string {
	return l.lock.Path()
}

// lockDir is where lock files live: a directory of the user's own, never the
// shared temp directory. There, a lock file one user created cannot be opened
// by another user, who would fail instead of waiting, and any local user
// could create or hold someone else's lock file ahead of them.
func lockDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("--parallel-safe needs a per-user directory for its lock files: %w", err)
	}
	return filepath.Join(base, "aws-vault", "locks"), nil
}

func hashedLockFilename(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s.%x.lock", prefix, sum)
}

// NewDefaultLock creates a ProcessLock in the user's lock directory.
// The lock file name is derived from the prefix and a SHA-256 hash of key.
func NewDefaultLock(prefix, key string) ProcessLock {
	name := hashedLockFilename(prefix, key)
	dir, err := lockDir()
	if err != nil {
		return unavailableLock{name: name, err: err}
	}
	return NewFileLock(filepath.Join(dir, name))
}

// unavailableLock stands in for a lock that has nowhere safe to live.
// TryLock reports why, so --parallel-safe fails loudly instead of running
// without the lock.
type unavailableLock struct {
	name string
	err  error
}

func (l unavailableLock) TryLock() (bool, error) { return false, l.err }
func (l unavailableLock) Unlock() error          { return nil }
func (l unavailableLock) Path() string           { return l.name }

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
