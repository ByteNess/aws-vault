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
	"github.com/alecthomas/kingpin/v2"

	"github.com/byteness/keyring"
)

func ExampleExecCommand() {
	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureExecCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"--debug", "exec", "--no-session", "llamas", "--", "sh", "-c", "echo $AWS_ACCESS_KEY_ID",
	}))

	// Output:
	// ABC
}
