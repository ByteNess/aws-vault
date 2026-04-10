package vault

import (
	"context"
	"errors"
	"fmt"
)

// processLockResult is the result of a cache check or locked work function.
// ok indicates whether a cached result was found.
type processLockResult[T any] struct {
	value T
	ok    bool
}

// withProcessLock implements the try/sleep/recheck lock protocol.
//
// On each iteration it calls checkCache; if that returns ok=true, the cached
// value is returned without acquiring the lock. Otherwise it tries the lock:
// if acquired, it calls doWork under the lock (unlocking on return). If the
// lock is not acquired, it sleeps and retries.
//
// checkCache may be nil, in which case the cache check is skipped.
func withProcessLock[T any](
	ctx context.Context,
	lock ProcessLock,
	waiterOpts lockWaiterOpts,
	lockName string,
	checkCache func() (processLockResult[T], error),
	doWork func(ctx context.Context) (T, error),
) (T, error) {
	waiter := newLockWaiter(waiterOpts)

	for {
		if checkCache != nil {
			result, err := checkCache()
			if err != nil {
				var zero T
				return zero, err
			}
			if result.ok {
				return result.value, nil
			}
		}
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
			result, workErr := doWork(ctx)
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
