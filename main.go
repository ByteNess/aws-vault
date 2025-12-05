package main

import (
	"os"

	"github.com/byteness/aws-vault/v7/cli"
	"github.com/spf13/cobra"
)

// Version is provided at compile time
var Version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "aws-vault",
		Short: "A vault for securely storing and accessing AWS credentials in development environments",
		Long:  "A vault for securely storing and accessing AWS credentials in development environments.",
		Annotations: map[string]string{
			"version": Version,
		},
	}

	rootCmd.Version = Version
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	// Configure globals and get AwsVault instance
	a := cli.ConfigureGlobals(rootCmd)

	// Add all subcommands
	rootCmd.AddCommand(cli.ConfigureAddCommand(a))
	rootCmd.AddCommand(cli.ConfigureRemoveCommand(a))
	rootCmd.AddCommand(cli.ConfigureListCommand(a))
	rootCmd.AddCommand(cli.ConfigureRotateCommand(a))
	rootCmd.AddCommand(cli.ConfigureExecCommand(a))
	rootCmd.AddCommand(cli.ConfigureExportCommand(a))
	rootCmd.AddCommand(cli.ConfigureClearCommand(a))
	rootCmd.AddCommand(cli.ConfigureLoginCommand(a))
	rootCmd.AddCommand(cli.ConfigureProxyCommand())

	// Add completion command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate completion script",
		Long: `To load completions:

Bash:

  $ source <(aws-vault completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ aws-vault completion bash > /etc/bash_completion.d/aws-vault
  # macOS:
  $ aws-vault completion bash > $(brew --prefix)/etc/bash_completion.d/aws-vault

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ aws-vault completion zsh > "${fpath[1]}/_aws-vault"

  # You will need to start a new shell for this setup to take effect.

Fish:

  $ aws-vault completion fish | source

  # To load completions for each session, execute once:
  $ aws-vault completion fish > ~/.config/fish/completions/aws-vault.fish

PowerShell:

  PS> aws-vault completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> aws-vault completion powershell > aws-vault.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletion(os.Stdout)
			case "zsh":
				return rootCmd.GenZshCompletion(os.Stdout)
			case "fish":
				return rootCmd.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return nil
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
