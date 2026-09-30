//go:build darwin || freebsd || openbsd
// +build darwin freebsd openbsd

package server

import (
	"context"
	"os/exec"
)

func installEc2EndpointNetworkAlias() ([]byte, error) {
	return exec.CommandContext(context.Background(), "ifconfig", "lo0", "alias", "169.254.169.254").CombinedOutput()
}

// nolint: contextcheck // the alias must be removed even when shutting down
func removeEc2EndpointNetworkAlias() ([]byte, error) {
	return exec.CommandContext(context.Background(), "ifconfig", "lo0", "-alias", "169.254.169.254").CombinedOutput()
}
