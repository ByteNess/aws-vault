//go:build darwin || freebsd || openbsd || linux
// +build darwin freebsd openbsd linux

package server

import (
	"context"
	"log"
	"os"
	"os/exec"
)

// StartEc2EndpointProxyServerProcess starts a `aws-vault proxy` process
func StartEc2EndpointProxyServerProcess() error {
	log.Println("Starting `aws-vault proxy` as root in the background")
	cmd := exec.CommandContext(context.Background(), "sudo", "-b", awsVaultExecutable(), "proxy")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
