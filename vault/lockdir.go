package vault

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/adrg/xdg"
)

// runtimeDir returns the XDG runtime directory. adrg/xdg v0.5.3 maps it to
// persistent directories on macOS (~/Library/Application Support) and Windows
// (%LOCALAPPDATA%); https://github.com/adrg/xdg/pull/163, fixing
// https://github.com/adrg/xdg/issues/120, maps it to the temporary directory
// instead but is not in a release yet. Drop this once one includes it.
func runtimeDir() string {
	if os.Getenv("XDG_RUNTIME_DIR") == "" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		return os.TempDir()
	}
	return xdg.RuntimeDir
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

func lockDirError(dir, reason string) error {
	return fmt.Errorf("refusing to use lock directory %s: %s", dir, reason)
}
