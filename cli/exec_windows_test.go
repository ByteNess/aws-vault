//go:build windows
// +build windows

package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// TestExecCommand exercises the exec command's subprocess path on Windows.
//
// Windows has no execve, so ExecCommand always launches the target as a child
// process and returns its exit code, rather than replacing the process image
// the way it does on Unix (see ExampleExecCommand in exec_test.go). We call
// ExecCommand directly instead of going through the kingpin action, because
// the action ends in os.Exit, which is illegal inside the test harness.
//
// The child runs "cmd /c echo %AWS_ACCESS_KEY_ID%" rather than a shell command
// so the test doesn't depend on Git's sh.exe being on PATH. Asserting the
// child prints the injected access key proves credentials are passed through
// to the subprocess environment.
func TestExecCommand(t *testing.T) {
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})

	tmp, err := os.CreateTemp(t.TempDir(), "aws-config-*")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	configFile, err := vault.LoadConfig(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}

	input := ExecCommandInput{
		ProfileName: "llamas",
		Command:     "cmd",
		Args:        []string{"/c", "echo %AWS_ACCESS_KEY_ID%"},
		NoSession:   true,
	}

	out := captureStdout(t, func() {
		exitcode, err := ExecCommand(input, configFile, kr)
		if err != nil {
			t.Fatalf("ExecCommand returned error: %v", err)
		}
		if exitcode != 0 {
			t.Fatalf("ExecCommand exitcode = %d, want 0", exitcode)
		}
	})

	if got := strings.TrimSpace(out); got != "ABC" {
		t.Errorf("child stdout = %q, want %q", got, "ABC")
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns whatever
// was written to it. runSubProcess wires the child's stdout to os.Stdout, so
// this captures the subprocess output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()

	return <-done
}
