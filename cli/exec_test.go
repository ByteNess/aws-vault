//go:build !windows
// +build !windows

// ExampleExecCommand drives the exec command through the kingpin action on
// Unix, where it replaces the process image via execve (syscall.Exec) and so
// never returns to the test harness. Windows has no execve: there the exec
// path runs a subprocess and the action calls os.Exit, which is illegal inside
// a Go example. The Windows subprocess path is covered by TestExecCommand in
// exec_windows_test.go, which calls ExecCommand directly (no os.Exit).

package cli

import (
	"bytes"
	"fmt"
	"os"
	osexec "os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/keyring"
)

func TestExecCommand(t *testing.T) {
	cases := []struct {
		name       string
		mode       string
		wantStdout string
		wantExit   int
	}{
		{
			name:       "injects credentials",
			mode:       "echo-access-key",
			wantStdout: "ABC",
			wantExit:   0,
		},
		{
			name:     "mirrors subprocess exit status",
			mode:     "exit-7",
			wantExit: 7,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writeExecTestConfig(t)

			cmd := osexec.Command(os.Args[0], "-test.run=^TestExecCommandHelper$")
			cmd.Env = execTestEnv(configPath, tc.mode)

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			gotExit, runErr := exitCode(err)
			if runErr != nil {
				t.Fatalf("command failed: %v\nstdout:\n%s\nstderr:\n%s", runErr, stdout.String(), stderr.String())
			}

			if gotExit != tc.wantExit {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", gotExit, tc.wantExit, stdout.String(), stderr.String())
			}

			if got := strings.TrimSpace(stdout.String()); got != tc.wantStdout {
				t.Fatalf("stdout = %q, want %q\nstderr:\n%s", got, tc.wantStdout, stderr.String())
			}
		})
	}
}

func TestExecCommandHelper(t *testing.T) {
	if os.Getenv("AWS_VAULT_EXEC_TEST_HELPER") != "1" {
		return
	}

	app := kingpin.New("aws-vault", "")

	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})

	ConfigureExecCommand(app, awsVault)

	command, args := execTestCommand(os.Getenv("AWS_VAULT_EXEC_TEST_MODE"))

	parseArgs := []string{"--debug", "exec", "--no-session", "llamas", "--", command}
	parseArgs = append(parseArgs, args...)

	kingpin.MustParse(app.Parse(parseArgs))

	t.Fatal("exec command returned without exiting")
}

func execTestCommand(mode string) (string, []string) {
	switch mode {
	case "echo-access-key":
		switch runtime.GOOS {
		case "windows":
			return "cmd", []string{"/c", "echo %AWS_ACCESS_KEY_ID%"}
		default:
			return "sh", []string{"-c", "echo $AWS_ACCESS_KEY_ID"}
		}

	case "exit-7":
		switch runtime.GOOS {
		case "windows":
			return "cmd", []string{"/c", "exit /b 7"}
		default:
			return "sh", []string{"-c", "exit 7"}
		}

	default:
		panic(fmt.Sprintf("unknown exec test mode %q", mode))
	}
}

func writeExecTestConfig(t *testing.T) string {
	t.Helper()

	f, err := os.CreateTemp("", "aws-config")
	if err != nil {
		t.Fatal(err)
	}

	path := f.Name()

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("[profile llamas]\nregion = us-east-1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = os.Remove(path)
	})

	return path
}

func execTestEnv(configPath string, mode string) []string {
	env := os.Environ()
	env = setEnv(env, "AWS_VAULT_EXEC_TEST_HELPER", "1")
	env = setEnv(env, "AWS_VAULT_EXEC_TEST_MODE", mode)
	env = setEnv(env, "AWS_CONFIG_FILE", configPath)
	env = setEnv(env, "AWS_VAULT_DISABLE_HELP_MESSAGE", "1")
	env = unsetEnv(env, "AWS_VAULT")

	return env
}

func exitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}

	if exitErr, ok := err.(*osexec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}

	return 0, err
}

func setEnv(env []string, key string, value string) []string {
	env = unsetEnv(env, key)
	return append(env, key+"="+value)
}

func unsetEnv(env []string, key string) []string {
	prefix := key + "="
	result := env[:0]

	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}

	return result
}
