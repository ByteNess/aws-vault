//go:build linux || darwin || freebsd || openbsd
// +build linux darwin freebsd openbsd

package vault_test

import (
	"os"
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
)

// TestProcessMfaProvider_CapturesStdout verifies that stdout from the mfa_process
// command is correctly captured and returned.
func TestProcessMfaProvider_CapturesStdout(t *testing.T) {
	token, err := vault.ProcessMfaProvider("echo '123456'")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "123456" {
		t.Errorf("got %q, want %q", token, "123456")
	}
}

// TestProcessMfaProvider_TrimsWhitespace verifies that surrounding whitespace and
// newlines are stripped from the captured output.
func TestProcessMfaProvider_TrimsWhitespace(t *testing.T) {
	token, err := vault.ProcessMfaProvider("printf '  123456  \\n'")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "123456" {
		t.Errorf("got %q, want %q", token, "123456")
	}
}

// TestProcessMfaProvider_StderrNotCaptured verifies that stderr output from the
// mfa_process command is not mixed into the captured stdout. This is the core
// behaviour that allows tools like ykman to write "Touch your YubiKey..." to
// the terminal without corrupting the MFA token returned to aws-vault.
func TestProcessMfaProvider_StderrNotCaptured(t *testing.T) {
	token, err := vault.ProcessMfaProvider("echo 'correct_token'; echo 'stderr_noise' >&2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "correct_token" {
		t.Errorf("stderr leaked into captured output: got %q, want %q", token, "correct_token")
	}
}

// TestProcessMfaProvider_CommandFailure verifies that a non-zero exit code from
// the mfa_process command is propagated as an error.
func TestProcessMfaProvider_CommandFailure(t *testing.T) {
	_, err := vault.ProcessMfaProvider("exit 1")
	if err == nil {
		t.Fatal("expected error for failing command, got nil")
	}
}

// TestProcessMfaProvider_StdinIsTTY verifies that the mfa_process command receives
// a real TTY as stdin when /dev/tty is available. This is required for tools like
// ykman that check sys.stdin.isatty() to decide how to display interactive prompts
// (e.g. OATH password entry). Without this, the prompt silently fails when aws-vault
// is used as a docker credential helper, because docker pipes JSON to aws-vault's
// stdin and that pipe propagates down to the subprocess.
func TestProcessMfaProvider_StdinIsTTY(t *testing.T) {
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err != nil {
		t.Skip("no controlling terminal available (/dev/tty inaccessible), skipping TTY stdin test")
	} else {
		f.Close()
	}

	// test -t 0 exits 0 if fd 0 (stdin) is a terminal, non-zero otherwise.
	_, err := vault.ProcessMfaProvider("test -t 0")
	if err != nil {
		t.Error("mfa_process command should receive a TTY as stdin when /dev/tty is available; " +
			"interactive prompts (e.g. ykman OATH password) will fail otherwise")
	}
}
