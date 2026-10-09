//go:build unix

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

var fallbackLockBase = "/tmp"

func fallbackLockDir() (string, error) {
	return filepath.Join(fallbackLockBase, fmt.Sprintf("aws-vault-%d", os.Getuid())), nil
}

func isPrivateToUser(fi os.FileInfo) bool {
	if fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || int(st.Uid) == os.Getuid()
}

func ensurePrivateDir(dir string) (string, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return "", err
	}

	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", lockDirError(dir, "it is a symlink")
	}
	if !fi.IsDir() {
		return "", lockDirError(dir, "it is not a directory")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return "", lockDirError(dir, fmt.Sprintf("it is owned by uid %d, not %d", st.Uid, os.Getuid()))
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		return "", lockDirError(dir, fmt.Sprintf("its permissions are %#o, not 0700", perm))
	}

	return dir, nil
}
