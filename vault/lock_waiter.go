package vault

import (
	"context"
	"time"
)

type lockLogger func(string, ...any)

// lockWaiterOpts configures a lockWaiter. All fields are required except
// Now, Sleep, and Warnf which have sensible defaults.
type lockWaiterOpts struct {
	LockPath  string
	WarnMsg   string
	LogMsg    string
	WaitDelay time.Duration
	LogEvery  time.Duration
	WarnAfter time.Duration
	Now       func() time.Time
	Sleep     func(context.Context, time.Duration) error
	Logf      lockLogger
	Warnf     lockLogger
}

type lockWaiter struct {
	opts lockWaiterOpts

	lastLog   time.Time
	waitStart time.Time
	warned    bool
}

func newLockWaiter(opts lockWaiterOpts) *lockWaiter {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = defaultContextSleep
	}
	return &lockWaiter{opts: opts}
}

func (w *lockWaiter) sleepAfterMiss(ctx context.Context) error {
	now := w.opts.Now()
	if w.waitStart.IsZero() {
		w.waitStart = now
	}
	if !w.warned && w.opts.WarnAfter <= now.Sub(w.waitStart) {
		if w.opts.Warnf != nil {
			w.opts.Warnf(w.opts.WarnMsg, w.opts.LockPath)
		}
		w.warned = true
	}
	if w.opts.Logf != nil && (w.lastLog.IsZero() || w.opts.LogEvery <= now.Sub(w.lastLog)) {
		w.opts.Logf(w.opts.LogMsg, w.opts.LockPath)
		w.lastLog = now
	}

	return w.opts.Sleep(ctx, w.opts.WaitDelay)
}
