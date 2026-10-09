package vault

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/byteness/keyring"
)

// testUnlockErrLock is a testLock variant whose Unlock returns a configured error.
type testUnlockErrLock struct {
	testLock
	unlockErr error
}

func (l *testUnlockErrLock) Unlock() error {
	l.unlockCalls++
	l.locked = false
	return l.unlockErr
}

func newTestLockedKeyring(inner keyring.Keyring, lock ProcessLock) *lockedKeyring {
	return &lockedKeyring{
		inner:     inner,
		lock:      lock,
		warnAfter: 5 * time.Second,
		lockLogf:  func(string, ...any) {},
	}
}

func TestLockedKeyring_BlocksWhenLockIsHeld(t *testing.T) {
	lock := &testLock{tryResults: []bool{false}}
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "foo", Data: []byte("bar")},
	})

	lk := newTestLockedKeyring(kr, lock)

	item, err := lk.Get("foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(item.Data) != "bar" {
		t.Fatalf("unexpected data: %s", string(item.Data))
	}
	if lock.tryCalls != 1 || lock.lockCalls != 1 {
		t.Fatalf("expected 1 try and 1 blocking lock, got %d and %d", lock.tryCalls, lock.lockCalls)
	}
	if lock.unlockCalls != 1 {
		t.Fatalf("expected 1 unlock, got %d", lock.unlockCalls)
	}
}

func TestLockedKeyring_UnlockErrorJoined(t *testing.T) {
	// Both the work function and Unlock return errors; they should be joined
	// via errors.Join so that errors.Is can unwrap both.
	workErr := fmt.Errorf("work failed")
	unlockErr := fmt.Errorf("unlock broken")

	lock := &testUnlockErrLock{
		testLock:  testLock{tryResults: []bool{true}},
		unlockErr: unlockErr,
	}

	// Use a keyring whose Remove always fails with workErr.
	inner := &failingKeyring{removeErr: workErr}

	lk := newTestLockedKeyring(inner, lock)

	err := lk.Remove("anything")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, workErr) {
		t.Fatalf("expected joined error to contain work error, got: %v", err)
	}
	// The unlock error is wrapped as "unlock keyring lock: <unlockErr>"
	// using %w, so errors.Is can unwrap through the wrapping.
	if !errors.Is(err, unlockErr) {
		t.Fatalf("expected joined error to contain unlock error, got: %v", err)
	}
}

// failingKeyring is a keyring.Keyring that returns configured errors.
type failingKeyring struct {
	keyring.Keyring
	removeErr error
}

func (k *failingKeyring) Remove(string) error {
	return k.removeErr
}
