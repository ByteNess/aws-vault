package prompt

import (
	"context"
	"os/exec"
	"strings"
)

// KDialogMfaPrompt prompts for an MFA code in a KDialog window.
func KDialogMfaPrompt(mfaSerial string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "kdialog", "--inputbox", mfaPromptMessage(mfaSerial), "--title", "aws-vault")

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	if _, err := exec.LookPath("kdialog"); err == nil {
		Methods["kdialog"] = KDialogMfaPrompt
	}
}
