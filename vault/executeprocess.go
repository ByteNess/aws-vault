package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// nolint: contextcheck // credential and token processes may be interactive, so they aren't cancelled with the caller
func executeProcess(process string) (string, error) {
	var cmdArgs []string
	if runtime.GOOS == "windows" {
		cmdArgs = []string{"cmd.exe", "/C", process}
	} else {
		cmdArgs = []string{"/bin/sh", "-c", process}
	}

	cmd := exec.CommandContext(context.Background(), cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("running command %q: %v", process, err)
	}
	return string(output), nil
}
