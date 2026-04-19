package prompt

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/byteness/aws-vault/v7/internal/tty"
)

// YkmanProvider runs ykman to generate a OATH-TOTP token from the Yubikey device
// To set up ykman, first run `ykman oath accounts add`
func YkmanMfaProvider(mfaSerial string) (string, error) {
	args := []string{}

	yubikeyOathCredName := os.Getenv("YKMAN_OATH_CREDENTIAL_NAME")
	if yubikeyOathCredName == "" {
		yubikeyOathCredName = mfaSerial
	}

	// Get the serial number of the yubikey device to use.
	yubikeyDeviceSerial := os.Getenv("YKMAN_OATH_DEVICE_SERIAL")
	if yubikeyDeviceSerial != "" {
		// If the env var was set, extend args to support passing the serial.
		args = append(args, "--device", yubikeyDeviceSerial)
	}

	// default to v4 and above
	switch os.Getenv("AWS_VAULT_YKMAN_VERSION") {
	case "1", "2", "3":
		args = append(args, "oath", "code", "--single", yubikeyOathCredName)
	default:
		args = append(args, "oath", "accounts", "code", "--single", yubikeyOathCredName)
	}

	log.Printf("Fetching MFA code using `ykman %s`", strings.Join(args, " "))
	cmd := exec.Command("ykman", args...)

	// Route stdin and stderr to the controlling TTY so that:
	//   - Stderr: the "Touch your YubiKey..." prompt is visible even when
	//     aws-vault is spawned as a credential_process subprocess (where the
	//     parent process may capture os.Stderr via a pipe).
	//   - Stdin: ykman sees a real TTY as stdin, so sys.stdin.isatty() == True
	//     and interactive prompts (e.g. OATH password) work even when
	//     aws-vault's stdin is a pipe (e.g. docker credential helper).
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
		return "", fmt.Errorf("ykman: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	if _, err := exec.LookPath("ykman"); err == nil {
		Methods["ykman"] = YkmanMfaProvider
	}
}
