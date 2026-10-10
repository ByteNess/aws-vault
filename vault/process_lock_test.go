package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// isolateUserCacheDir points os.UserCacheDir at a fresh directory on every
// platform the tests run on, and returns what it now resolves to.
func isolateUserCacheDir(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("LocalAppData", filepath.Join(home, "AppData", "Local"))
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("UserCacheDir: %v", err)
	}
	return base
}

// Lock files live in a directory of the user's own. In the shared temp
// directory, a lock file one user created cannot be opened by another user,
// who then fails instead of waiting, and any local user can create or hold
// someone else's lock file ahead of them.
func TestNewDefaultLockUsesPerUserDirectory(t *testing.T) {
	base := isolateUserCacheDir(t)

	lock := NewDefaultLock("aws-vault.test", "key")
	dir := filepath.Dir(lock.Path())
	if want := filepath.Join(base, "aws-vault", "locks"); dir != want {
		t.Fatalf("lock directory = %s, want %s", dir, want)
	}

	locked, err := lock.TryLock()
	if err != nil || !locked {
		t.Fatalf("TryLock = %t, %v; want the lock", locked, err)
	}
	t.Cleanup(func() { _ = lock.Unlock() })

	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("lock directory mode = %o, want 700", perm)
		}
	}
}

// Building a provider must not touch the disk; the directory appears when a
// lock is first taken.
func TestNewDefaultLockCreatesDirectoryOnFirstUse(t *testing.T) {
	base := isolateUserCacheDir(t)

	lock := NewDefaultLock("aws-vault.test", "key")
	if _, err := os.Stat(filepath.Join(base, "aws-vault")); !os.IsNotExist(err) {
		t.Fatalf("lock directory exists before the lock was used (stat err %v)", err)
	}
	if locked, err := lock.TryLock(); err != nil || !locked {
		t.Fatalf("TryLock = %t, %v; want the lock", locked, err)
	}
	_ = lock.Unlock()
}

// Without a per-user directory there is nowhere safe to put the lock, so
// --parallel-safe fails loudly instead of running unlocked or falling back to
// the shared temp directory.
func TestNewDefaultLockFailsWithoutAUserCacheDir(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("LocalAppData", "")
	if _, err := os.UserCacheDir(); err == nil {
		t.Skip("this platform resolves a user cache directory without these variables")
	}

	lock := NewDefaultLock("aws-vault.test", "key")
	if locked, err := lock.TryLock(); err == nil || locked {
		t.Fatalf("TryLock = %t, %v; want an error", locked, err)
	}
}
