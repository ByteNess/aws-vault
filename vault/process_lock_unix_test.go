//go:build unix

package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// actAsRootInAnotherUsersDirs makes the lock code run as root while paths
// belong to another user, as when root runs aws-vault with that user's HOME.
func actAsRootInAnotherUsersDirs(t *testing.T, paths ...string) {
	t.Helper()
	if os.Getuid() != 0 {
		currentUID = func() int { return 0 }
		t.Cleanup(func() { currentUID = os.Getuid })
		return
	}
	for _, p := range paths {
		if err := os.Chown(p, 1, -1); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNewDefaultLockAsRootCreatesNothingInAnotherUsersHome(t *testing.T) {
	base := isolateUserCacheDir(t)
	actAsRootInAnotherUsersDirs(t, os.Getenv("HOME"))

	if locked, err := NewDefaultLock("aws-vault.test", "key").TryLock(); err == nil || locked {
		t.Fatalf("TryLock = %t, %v; want an error", locked, err)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatalf("%s was created (stat err %v)", base, err)
	}
}

func TestNewDefaultLockAsRootCreatesNothingInAnotherUsersLockDirectory(t *testing.T) {
	base := isolateUserCacheDir(t)
	dir := filepath.Join(base, "aws-vault", "locks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	actAsRootInAnotherUsersDirs(t, dir)

	lock := NewDefaultLock("aws-vault.test", "key")
	if locked, err := lock.TryLock(); err == nil || locked {
		t.Fatalf("TryLock = %t, %v; want an error", locked, err)
	}
	if _, err := os.Stat(lock.Path()); !os.IsNotExist(err) {
		t.Fatalf("lock file was created (stat err %v)", err)
	}
}
