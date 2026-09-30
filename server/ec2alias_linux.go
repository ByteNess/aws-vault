//go:build linux
// +build linux

package server

import (
	"context"
	"os/exec"
)

func installEc2EndpointNetworkAlias() ([]byte, error) {
	return exec.CommandContext(context.Background(), "ip", "addr", "add", "169.254.169.254/24", "dev", "lo", "label", "lo:0").CombinedOutput()
}

// nolint: contextcheck // the alias must be removed even when shutting down
func removeEc2EndpointNetworkAlias() ([]byte, error) {
	return exec.CommandContext(context.Background(), "ip", "addr", "del", "169.254.169.254/24", "dev", "lo", "label", "lo:0").CombinedOutput()
}
