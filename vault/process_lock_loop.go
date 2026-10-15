package vault

import (
	"context"
	"errors"
	"fmt"
)

// withProcessLock tries the lock until it gets it, sleeping between tries,
// and calls doWork under it, unlocking on return.
//
// Waiting touches nothing but the lock file. Callers check their cache before
// calling and again in doWork, under the lock, which is where they find what
// the previous holder stored. Waiters do not poll the cache themselves: every
// cache read takes the keyring lock, and with many waiters polling, the
// holder's own write to the cache would queue behind their reads.
//
// doWork does not receive a context because ctx is typically a lock-wait
// timeout that should NOT bound the actual work. Callers that need a context
// for work should capture it through the closure.
func withProcessLock[T any](
	ctx context.Context,
	lock ProcessLock,
	waiterOpts lockWaiterOpts,
	lockName string,
	doWork func() (T, error),
) (T, error) {
	waiter := newLockWaiter(waiterOpts)

	for {
		if ctx.Err() != nil {
			var zero T
			return zero, ctx.Err()
		}

		locked, err := lock.TryLock()
		if err != nil {
			var zero T
			return zero, err
		}
		if locked {
			result, workErr := doWork()
			if unlockErr := lock.Unlock(); unlockErr != nil {
				return result, errors.Join(workErr, fmt.Errorf("unlock %s lock: %w", lockName, unlockErr))
			}
			return result, workErr
		}

		if err = waiter.sleepAfterMiss(ctx); err != nil {
			var zero T
			return zero, err
		}
	}
}
