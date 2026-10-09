package vault

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/adrg/xdg"
)

func lockDir() (string, error) {
	if base, ok := usableRuntimeDir(xdg.RuntimeDir); ok {
		return ensurePrivateDir(filepath.Join(base, "aws-vault"))
	}

	dir, err := fallbackLockDir()
	if err != nil {
		return "", err
	}
	log.Printf("Runtime directory %q is unavailable, using %s for lock files", xdg.RuntimeDir, dir)
	return ensurePrivateDir(dir)
}

func usableRuntimeDir(dir string) (string, bool) {
	if dir == "" {
		return "", false
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() || !isPrivateToUser(fi) {
		return "", false
	}
	return dir, true
}

func lockDirError(dir, reason string) error {
	return fmt.Errorf("refusing to use lock directory %s: %s", dir, reason)
}
