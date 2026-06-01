//go:build linux || darwin || freebsd || openbsd
// +build linux darwin freebsd openbsd

package vault_test

import "os"

// wantTokenPerm is the file mode writeFileAtomic is expected to produce for a
// token file on Unix, where 0600 (owner read/write only) is honoured directly.
func wantTokenPerm() os.FileMode { return 0600 }
