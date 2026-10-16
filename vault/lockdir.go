package vault

import (
	"log"
	"os"
	"path/filepath"
)

func runtimeDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir
	}
	if dir := userRuntimeDir(); dir != "" {
		return dir
	}
	return os.TempDir()
}

func lockDir() (string, error) {
	base := runtimeDir()
	if dir, ok := usableRuntimeDir(base); ok {
		return ensurePrivateDir(filepath.Join(dir, "aws-vault"))
	}

	dir, err := fallbackLockDir()
	if err != nil {
		return "", err
	}
	log.Printf("Runtime directory %q is unavailable, using %s for lock files", base, dir)
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
