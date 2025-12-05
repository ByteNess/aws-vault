package cli

import (
	"github.com/byteness/keyring"
	"github.com/spf13/cobra"
)

func ExampleExportCommand() {
	rootCmd := &cobra.Command{Use: "aws-vault"}
	awsVault := ConfigureGlobals(rootCmd)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	rootCmd.AddCommand(ConfigureExportCommand(awsVault))
	rootCmd.SetArgs([]string{
		"export", "--format=ini", "--no-session", "llamas",
	})
	_ = rootCmd.Execute()

	// Output:
	// [llamas]
	// aws_access_key_id=ABC
	// aws_secret_access_key=XYZ
	// region=us-east-1
}
