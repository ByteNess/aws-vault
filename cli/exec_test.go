package cli

import (
	"bytes"
	"os"
	osexec "os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/keyring"
)

// TestExecCommand runs the real exec CLI action inside a child copy of the test
// binary (see TestExecCommandHelper). This avoids stubbing os.Exit or
// syscall.Exec, so both the Unix execve path and the Windows fallback
// (runSubProcess + os.Exit) are exercised with their actual implementations.
func TestExecCommand(t *testing.T) {
	type testCmd struct {
		exe  string
		args []string
	}

	// platformCmd selects the Windows or Unix variant at test run time.
	platformCmd := func(win, unix testCmd) testCmd {
		if runtime.GOOS == "windows" {
			return win
		}
		return unix
	}

	cases := []struct {
		name       string
		cmd        testCmd
		wantStdout string
		wantExit   int
	}{
		{
			name: "injects credentials",
			cmd: platformCmd(
				testCmd{"cmd", []string{"/c", "echo %AWS_ACCESS_KEY_ID%"}},
				testCmd{"sh", []string{"-c", "echo $AWS_ACCESS_KEY_ID"}},
			),
			wantStdout: "ABC",
			wantExit:   0,
		},
		{
			name: "mirrors subprocess exit status",
			cmd: platformCmd(
				testCmd{"cmd", []string{"/c", "exit /b 7"}},
				testCmd{"sh", []string{"-c", "exit 7"}},
			),
			wantExit: 7,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writeExecTestConfig(t)

			// Re-run this test binary as the child. Only TestExecCommandHelper
			// will run because of the -test.run filter; the helper exits (via
			// os.Exit or execve) before t.Fatal can be reached, so the child
			// process exit code is the one produced by the CLI action itself.
			// The command to run is passed as argv after "--" so no JSON or mode
			// string is needed — the test case table is the single source of truth.
			helperArgs := []string{"-test.run=^TestExecCommandHelper$", "--", tc.cmd.exe}
			helperArgs = append(helperArgs, tc.cmd.args...)

			cmd := osexec.Command(os.Args[0], helperArgs...)
			cmd.Env = execTestEnv(configPath)

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

// TestExecCommandHelper is the child-process entry point. It is invoked by
// TestExecCommand via os.Args[0] with AWS_VAULT_EXEC_TEST_HELPER=1. When that
// variable is absent (normal test run) the function returns immediately and has
// no effect. When present, it wires up the real CLI and runs the requested
// mode; the exec command will call os.Exit (Windows) or execve (Unix) and
// never return — if it does return, t.Fatal surfaces the bug.
func TestExecCommandHelper(t *testing.T) {
	if os.Getenv("AWS_VAULT_EXEC_TEST_HELPER") != "1" {
		return
	}

	helperCommand, helperArgs, ok := execTestHelperCommand(os.Args)
	if !ok {
		t.Fatalf("missing helper command in args: %q", os.Args)
	}

	app := kingpin.New("aws-vault", "")

	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})

	ConfigureExecCommand(app, awsVault)

	parseArgs := []string{"--debug", "exec", "--no-session", "llamas", "--", helperCommand}
	parseArgs = append(parseArgs, helperArgs...)

	kingpin.MustParse(app.Parse(parseArgs))

	t.Fatal("exec command returned without exiting")
}

// execTestHelperCommand extracts the command and its arguments from os.Args by
// finding the "--" separator that the parent placed after the -test.run flag.
func execTestHelperCommand(args []string) (string, []string, bool) {
	for i, arg := range args {
		if arg == "--" {
			if i+1 >= len(args) {
				return "", nil, false
			}

			return args[i+1], args[i+2:], true
		}
	}

	return "", nil, false
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

// execTestEnv builds a child environment by inheriting the parent's env and
// then overriding/unsetting the vars the test needs. We manipulate a []string
// slice rather than calling os.Setenv so that the changes are scoped to the
// child process and don't affect the parent test process or parallel tests.
func execTestEnv(configPath string) []string {
	env := os.Environ()
	env = setEnv(env, "AWS_VAULT_EXEC_TEST_HELPER", "1")
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
