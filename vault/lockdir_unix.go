//go:build unix

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func fallbackLockDir() (string, error) {
	return filepath.Join("/tmp", fmt.Sprintf("aws-vault-%d", os.Getuid())), nil
}

func isWorldWritable(fi os.FileInfo) bool {
	return fi.Mode().Perm()&0o002 != 0
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
