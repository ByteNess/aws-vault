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
// On each iteration it tries the lock: if acquired, it calls doWork under the
// lock (unlocking on return). If the lock is not acquired, it sleeps and then
// calls checkCache; if that returns ok=true, the cached value is returned
// without acquiring the lock. Callers check the cache themselves before the
// first attempt, and doWork must recheck it once the lock is held.
//
// checkCache may be nil, in which case the cache check is skipped.
//
// ctx bounds only the wait for the lock. doWork does not receive it; callers
// that need a context for the work capture it through the closure.
func withProcessLock[T any](
	ctx context.Context,
	lock ProcessLock,
	waiterOpts lockWaiterOpts,
	lockName string,
	checkCache func() (processLockResult[T], error),
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
			return runLocked(lock, lockName, doWork)
		}

		if sleepErr := waiter.sleepAfterMiss(ctx); sleepErr != nil {
			var zero T
			return zero, sleepErr
		}

		if checkCache != nil {
			result, cacheErr := checkCache()
			if cacheErr != nil {
				var zero T
				return zero, cacheErr
			}
			if result.ok {
				return result.value, nil
			}
		}
	}
}

func runLocked[T any](lock ProcessLock, lockName string, doWork func() (T, error)) (result T, err error) {
	defer func() {
		if unlockErr := lock.Unlock(); unlockErr != nil {
			err = errors.Join(err, fmt.Errorf("unlock %s lock: %w", lockName, unlockErr))
		}
	}()
	return doWork()
}
