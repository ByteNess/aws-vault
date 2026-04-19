//go:build windows
// +build windows

// Package tty opens the console for use as a subprocess's stdin/stderr. This
// lets interactive prompts (e.g. "Touch your YubiKey...") reach the user even
// when aws-vault is run as a credential_process subprocess whose stdin/stderr
// are piped by the parent (aws CLI, kubectl, docker, etc.).
package tty

import "os"

// Open returns file handles suitable for use as a subprocess's stdin and
// stderr. Windows has no single read-write console device, so stdin uses
// CONIN$ and stderr uses CONOUT$. Callers must defer cleanup() unconditionally.
// Either or both of in/out may be nil if the corresponding console handle is
// unavailable; callers should fall back to inherited descriptors in that case.
func Open() (in, out *os.File, cleanup func()) {
	in, _ = os.OpenFile("CONIN$", os.O_RDONLY, 0)
	out, _ = os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	return in, out, func() {
		if in != nil {
			in.Close()
		}
		if out != nil {
			out.Close()
		}
	}
}
