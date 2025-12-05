package cli

import (
	"github.com/byteness/keyring"
	"github.com/spf13/cobra"
)

func ExampleListCommand() {
	rootCmd := &cobra.Command{Use: "aws-vault"}
	awsVault := ConfigureGlobals(rootCmd)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	rootCmd.AddCommand(ConfigureListCommand(awsVault))
	rootCmd.SetArgs([]string{
		"list", "--credentials",
	})
	_ = rootCmd.Execute()

	// Output:
	// llamas
}
