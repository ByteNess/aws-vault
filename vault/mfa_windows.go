//go:build windows
// +build windows

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/byteness/aws-vault/v7/internal/tty"
)

func executeMFACommand(processCmd string) (string, error) {
	// On windows, its quite involved to launch a process if the binary involved is in a path with spaces
	// See https://github.com/golang/go/issues/17149 for details and workaround proposals
	shell := os.Getenv("SystemRoot") + "\\System32\\cmd.exe"
	cmd := exec.Command(shell)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "/C \"" + processCmd + "\""}

	// Route stdin and stderr to the console so that interactive prompts
	// (e.g. "Touch your YubiKey...", OATH password entry) reach the user even
	// when aws-vault's stdin/stderr are piped by the parent process (e.g.
	// docker credential helper).
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
