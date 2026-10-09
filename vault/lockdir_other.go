//go:build !unix

package vault

import (
	"errors"
	"os"
)

func fallbackLockDir() (string, error) {
	return "", errors.New("no runtime directory is available for lock files")
}

func isPrivateToUser(os.FileInfo) bool {
	return true
}

func ensurePrivateDir(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}
