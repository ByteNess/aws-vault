//go:build linux || darwin || freebsd || openbsd
// +build linux darwin freebsd openbsd

// Package tty opens the controlling terminal for use as a subprocess's
// stdin/stderr. This lets interactive prompts (e.g. "Touch your YubiKey...")
// reach the user even when aws-vault is run as a credential_process subprocess
// whose stdin/stderr are piped by the parent (aws CLI, kubectl, docker, etc.).
package tty

import "os"

// Open returns file handles suitable for use as a subprocess's stdin and
// stderr. On unix, both handles are the same /dev/tty fd opened read-write.
// Callers must defer cleanup() unconditionally. Either or both of in/out may
// be nil if no controlling terminal is available (headless CI, daemonized
// process); callers should fall back to inherited descriptors in that case.
func Open() (in, out *os.File, cleanup func()) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, func() {}
	}
	return f, f, func() { f.Close() }
}
