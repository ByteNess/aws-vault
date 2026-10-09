//go:build unix

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/byteness/keyring"
)

func setRuntimeDir(t *testing.T, dir string) {
	t.Helper()
	t.Cleanup(xdg.Reload)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	xdg.Reload()
}

func setFallbackLockBase(t *testing.T, base string) {
	t.Helper()
	previous := fallbackLockBase
	fallbackLockBase = base
	t.Cleanup(func() { fallbackLockBase = previous })
}

func TestEnsurePrivateDirCreatesOwnerOnlyDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "locks")

	got, err := ensurePrivateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("ensurePrivateDir() = %q, want %q", got, dir)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("permissions = %#o, want 0700", perm)
	}
}

func TestEnsurePrivateDirRejectsUnsafeDirs(t *testing.T) {
	base := t.TempDir()

	symlink := filepath.Join(base, "symlink")
	if err := os.Symlink(t.TempDir(), symlink); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}

	for name, dir := range map[string]string{"symlink": symlink, "file": file, "loose permissions": loose} {
		t.Run(name, func(t *testing.T) {
			if _, err := ensurePrivateDir(dir); err == nil {
				t.Fatalf("ensurePrivateDir(%q) succeeded, want an error", dir)
			}
		})
	}
}

func TestLockDirUsesRuntimeDir(t *testing.T) {
	runtimeDir := t.TempDir()
	setRuntimeDir(t, runtimeDir)

	got, err := lockDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(runtimeDir, "aws-vault"); got != want {
		t.Fatalf("lockDir() = %q, want %q", got, want)
	}
}

func TestLockDirFallsBackToPerUserTmpDir(t *testing.T) {
	worldWritable := t.TempDir()
	if err := os.Chmod(worldWritable, 0o777); err != nil {
		t.Fatal(err)
	}
	groupWritable := t.TempDir()
	if err := os.Chmod(groupWritable, 0o770); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	setFallbackLockBase(t, base)
	want := filepath.Join(base, fmt.Sprintf("aws-vault-%d", os.Getuid()))

	for name, runtimeDir := range map[string]string{
		"missing":        filepath.Join(t.TempDir(), "missing"),
		"world-writable": worldWritable,
		"group-writable": groupWritable,
	} {
		t.Run(name, func(t *testing.T) {
			setRuntimeDir(t, runtimeDir)

			got, err := lockDir()
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("lockDir() = %q, want %q", got, want)
			}
		})
	}
}

func TestDefaultLockExcludesOtherProcesses(t *testing.T) {
	if os.Getenv("AWS_VAULT_TEST_LOCK_CHILD") == "1" {
		locked, err := NewDefaultLock("aws-vault.test", "cross-process").TryLock()
		fmt.Printf("locked=%t err=%v\n", locked, err)
		return
	}

	setRuntimeDir(t, t.TempDir())
	lock := NewDefaultLock("aws-vault.test", "cross-process")

	tryInChild := func() string {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestDefaultLockExcludesOtherProcesses$")
		cmd.Env = append(os.Environ(), "AWS_VAULT_TEST_LOCK_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child process failed: %v\n%s", err, out)
		}
		return string(out)
	}

	locked, err := lock.TryLock()
	if err != nil || !locked {
		t.Fatalf("TryLock() = %t, %v, want true, nil", locked, err)
	}
	if out := tryInChild(); !strings.Contains(out, "locked=false err=<nil>") {
		t.Fatalf("child acquired a lock held by the parent:\n%s", out)
	}

	if err := lock.Unlock(); err != nil {
		t.Fatal(err)
	}
	if out := tryInChild(); !strings.Contains(out, "locked=true err=<nil>") {
		t.Fatalf("child could not acquire a released lock:\n%s", out)
	}
}

func TestLockedKeyringWaitsForHeldLock(t *testing.T) {
	setRuntimeDir(t, t.TempDir())
	held := NewDefaultLock(keyringLockPrefix, "held")
	if err := held.Lock(); err != nil {
		t.Fatal(err)
	}

	kr := NewLockedKeyring(keyring.NewArrayKeyring([]keyring.Item{{Key: "k", Data: []byte("v")}}), "held")
	done := make(chan error, 1)
	go func() {
		_, err := kr.Get("k")
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("Get returned while the lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := held.Unlock(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Get failed after the lock was released: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Get did not proceed after the lock was released")
	}
}

func TestDefaultLockExcludesGoroutinesSharingIt(t *testing.T) {
	setRuntimeDir(t, t.TempDir())
	lock := NewDefaultLock("aws-vault.test", "shared")

	locked, err := lock.TryLock()
	if err != nil || !locked {
		t.Fatalf("TryLock() = %t, %v, want true, nil", locked, err)
	}
	again, err := lock.TryLock()
	if err != nil || again {
		t.Fatalf("second TryLock() on a held lock = %t, %v, want false, nil", again, err)
	}
	if err := lock.Unlock(); err != nil {
		t.Fatal(err)
	}
}
