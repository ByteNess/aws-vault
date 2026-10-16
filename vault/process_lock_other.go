//go:build !unix

package vault

import "os"

// fileOwner reports no owner, so lock directory ownership isn't checked.
func fileOwner(os.FileInfo) (int, bool) {
	return 0, false
}
