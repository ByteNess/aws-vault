//go:build windows
// +build windows

package vault_test

import "os"

// wantTokenPerm is the file mode writeFileAtomic is expected to produce for a
// token file on Windows. Windows has no Unix permission bits; os.Chmod only
// toggles the read-only attribute, so a writable file always reports 0666.
// The owner-only confidentiality that 0600 expresses on Unix is governed by
// ACLs on Windows, which os.FileMode cannot represent.
func wantTokenPerm() os.FileMode { return 0666 }
