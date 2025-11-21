package cli

import (
	"github.com/byteness/keyring"
	"github.com/spf13/cobra"
)

func ExampleExecCommand() {
	rootCmd := &cobra.Command{Use: "aws-vault"}
	awsVault := ConfigureGlobals(rootCmd)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	rootCmd.AddCommand(ConfigureExecCommand(awsVault))
	rootCmd.SetArgs([]string{
		"--debug", "exec", "--no-session", "llamas", "sh", "-c", "echo $AWS_ACCESS_KEY_ID",
	})
	_ = rootCmd.Execute()

	// Output:
	// ABC
}
