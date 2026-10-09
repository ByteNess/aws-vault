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

func newTestLockedKeyring(inner keyring.Keyring, lock ProcessLock, clock *testClock) *lockedKeyring {
	return &lockedKeyring{
		inner:     inner,
		lock:      lock,
		lockKey:   "test",
		lockWait:  100 * time.Millisecond,
		lockLog:   15 * time.Second,
		warnAfter: 5 * time.Second,
		lockNow:   clock.Now,
		lockSleep: clock.Sleep,
		lockLogf:  func(string, ...any) {},
	}
}

func TestLockedKeyring_LockWaitRetries(t *testing.T) {
	// Lock fails twice, then succeeds on the third attempt.
	lock := &testLock{tryResults: []bool{false, false, true}}
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "foo", Data: []byte("bar")},
	})
	clock := &testClock{now: time.Unix(0, 0)}

	lk := newTestLockedKeyring(kr, lock, clock)

	item, err := lk.Get("foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(item.Data) != "bar" {
		t.Fatalf("unexpected data: %s", string(item.Data))
	}
	if lock.tryCalls != 3 {
		t.Fatalf("expected 3 lock attempts, got %d", lock.tryCalls)
	}
	if clock.sleepCalls != 2 {
		t.Fatalf("expected 2 sleep calls, got %d", clock.sleepCalls)
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
	clock := &testClock{now: time.Unix(0, 0)}

	lk := newTestLockedKeyring(inner, lock, clock)

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

func TestLockedKeyring_WaitsWithoutTimeout(t *testing.T) {
	waits := int((15 * time.Minute) / (100 * time.Millisecond))
	lock := &testLock{tryResults: append(make([]bool, waits), true)}
	kr := keyring.NewArrayKeyring([]keyring.Item{{Key: "k", Data: []byte("v")}})
	clock := &testClock{now: time.Unix(0, 0)}

	lk := newTestLockedKeyring(kr, lock, clock)

	item, err := lk.Get("k")
	if err != nil {
		t.Fatalf("unexpected error after a long wait: %v", err)
	}
	if string(item.Data) != "v" {
		t.Fatalf("unexpected item data %q", item.Data)
	}
	if clock.sleepCalls != waits {
		t.Fatalf("expected %d sleeps, got %d", waits, clock.sleepCalls)
	}
}
