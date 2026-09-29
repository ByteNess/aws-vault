package prompt

import (
	"fmt"
	"strings"

	"github.com/mattn/go-tty"
)

// TerminalPrompt shows message on the terminal and returns the line the user types.
func TerminalPrompt(message string) (string, error) {
	tty, err := tty.Open()
	if err != nil {
		return "", err
	}
	defer func() { _ = tty.Close() }()

	if _, err := fmt.Fprint(tty.Output(), message); err != nil {
		return "", err
	}

	text, err := tty.ReadString()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(text), nil
}

// TerminalSecretPrompt is like TerminalPrompt, but doesn't echo what the user types.
func TerminalSecretPrompt(message string) (string, error) {
	tty, err := tty.Open()
	if err != nil {
		return "", err
	}
	defer func() { _ = tty.Close() }()

	if _, err := fmt.Fprint(tty.Output(), message); err != nil {
		return "", err
	}

	text, err := tty.ReadPassword()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(text), nil
}

// TerminalMfaPrompt prompts for an MFA code on the terminal.
func TerminalMfaPrompt(mfaSerial string) (string, error) {
	return TerminalPrompt(mfaPromptMessage(mfaSerial))
}

func init() {
	Methods["terminal"] = TerminalMfaPrompt
}
