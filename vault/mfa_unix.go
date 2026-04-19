//go:build linux || darwin || freebsd || openbsd
// +build linux darwin freebsd openbsd

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/byteness/aws-vault/v7/internal/tty"
)

func executeMFACommand(processCmd string) (string, error) {
	cmd := exec.Command("/bin/sh", "-c", processCmd)

	// Route stdin and stderr to the controlling TTY so that:
	//   - Stderr: interactive prompts (e.g. "Touch your YubiKey...") are
	//     visible even when aws-vault's stderr is captured by the parent
	//     process (e.g. aws CLI or kubectl using credential_process).
	//   - Stdin: the subprocess sees a real TTY, so tools like ykman find
	//     sys.stdin.isatty() == True and can display interactive prompts
	//     (e.g. OATH password) even when aws-vault's stdin is a pipe
	//     (e.g. docker credential helper receiving JSON on stdin).
	ttyIn, ttyOut, cleanup := tty.Open()
	defer cleanup()
	if ttyIn != nil {
		cmd.Stdin = ttyIn
	}
	if ttyOut != nil {
		cmd.Stderr = ttyOut
	} else {
		cmd.Stderr = os.Stderr
	}

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("process provider: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}
