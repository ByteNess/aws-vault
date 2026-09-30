package prompt

import (
	"context"
	"os/exec"
	"strings"
)

// ZenityMfaPrompt prompts for an MFA code in a Zenity window.
func ZenityMfaPrompt(mfaSerial string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "zenity", "--entry", "--title", "aws-vault", "--text", mfaPromptMessage(mfaSerial))

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	if _, err := exec.LookPath("zenity"); err == nil {
		Methods["zenity"] = ZenityMfaPrompt
	}
}
