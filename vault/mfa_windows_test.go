//go:build windows
// +build windows

package vault_test

import (
	"os"
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
)

// TestProcessMfaProvider_CapturesStdout verifies that stdout from the
// mfa_process command is correctly captured and returned.
func TestProcessMfaProvider_CapturesStdout(t *testing.T) {
	token, err := vault.ProcessMfaProvider("echo 123456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "123456" {
		t.Errorf("got %q, want %q", token, "123456")
	}
}

// TestProcessMfaProvider_TrimsWhitespace verifies that surrounding whitespace
// and Windows CRLF line endings are stripped from the captured output.
// cmd.exe echo appends \r\n; leading spaces appear when the token is
// preceded by spaces in the echo argument.
func TestProcessMfaProvider_TrimsWhitespace(t *testing.T) {
	token, err := vault.ProcessMfaProvider("echo   123456   ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "123456" {
		t.Errorf("got %q, want %q", token, "123456")
	}
}

// TestProcessMfaProvider_StderrNotCaptured verifies that stderr output from
// the mfa_process command is not mixed into the captured stdout. This is the
// core behaviour that allows tools like ykman to write "Touch your YubiKey..."
// to the console without corrupting the MFA token returned to aws-vault.
func TestProcessMfaProvider_StderrNotCaptured(t *testing.T) {
	token, err := vault.ProcessMfaProvider(
		"echo correct_token & echo noise 1>&2",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "correct_token" {
		t.Errorf("stderr leaked into captured output: got %q, want %q",
			token, "correct_token")
	}
}

// TestProcessMfaProvider_CommandFailure verifies that a non-zero exit code
// from the mfa_process command is propagated as an error.
func TestProcessMfaProvider_CommandFailure(t *testing.T) {
	_, err := vault.ProcessMfaProvider("exit 1")
	if err == nil {
		t.Fatal("expected error for failing command, got nil")
	}
}

// TestProcessMfaProvider_StdinIsConsole verifies that the mfa_process command
// receives the console as stdin when CONIN$ is available. This is required for
// tools like ykman that check whether stdin is interactive before displaying
// prompts (e.g. OATH password entry). Without this, the prompt silently fails
// when aws-vault is used as a docker credential helper, because docker pipes
// JSON to aws-vault's stdin and that pipe propagates down to the subprocess.
func TestProcessMfaProvider_StdinIsConsole(t *testing.T) {
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err != nil {
		t.Skip("console input not available (CONIN$ inaccessible), " +
			"skipping console stdin test")
	} else {
		f.Close()
	}

	// PowerShell [Console]::IsInputRedirected returns True when stdin is a
	// pipe or file, False when it is the real console. Exit 1 on redirect so
	// the test fails if stdin was not wired to CONIN$.
	_, err := vault.ProcessMfaProvider(
		`powershell -NonInteractive -Command ` +
			`"if ([Console]::IsInputRedirected) { exit 1 }"`,
	)
	if err != nil {
		t.Error("mfa_process command should receive the console as stdin " +
			"when CONIN$ is available; interactive prompts " +
			"(e.g. ykman OATH password) will fail otherwise")
	}
}
