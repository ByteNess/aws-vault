//go:build windows
// +build windows

package server

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

var alreadyRegisteredLocalised = []string{
	"The object already exists",
	"Das Objekt ist bereits vorhanden",
	"El objeto ya existe",
	"Objektet findes allerede",
}

var runAsAdministratorLocalised = []string{
	"Run as administrator",
	// truncate before 'Umlaut' to avoid encoding problems coming from Windows cmd
	"Als Administrator ausf",
	"Ejecutar como administrador",
	//  truncate before 'ø' to avoid encoding problems coming from Windows cmd
	"r som administrator",
}

func msgFound(localised []string, toTest string) bool {
	for _, value := range localised {
		if strings.Contains(toTest, value) {
			return true
		}
	}

	return false
}

func runAndWrapAdminErrors(name string, arg ...string) ([]byte, error) {
	out, err := exec.Command(name, arg...).CombinedOutput()
	if msgFound(runAsAdministratorLocalised, string(out)) {
		const msg = "Creation of network alias for server mode requires elevated permissions, run as administrator"
		if err != nil {
			err = fmt.Errorf("%s: %w", msg, err)
		} else {
			err = errors.New(msg)
		}
	}

	return out, err
}

func installEc2EndpointNetworkAlias() ([]byte, error) {
	out, err := runAndWrapAdminErrors("netsh", "interface", "ipv4", "add", "address", "Loopback Pseudo-Interface 1", "169.254.169.254", "255.255.0.0")
	if msgFound(alreadyRegisteredLocalised, string(out)) {
		return []byte{}, nil
	}

	return out, err
}

func removeEc2EndpointNetworkAlias() ([]byte, error) {
	return runAndWrapAdminErrors("netsh", "interface", "ipv4", "delete", "address", "Loopback Pseudo-Interface 1", "169.254.169.254", "255.255.0.0")
}
