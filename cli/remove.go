package cli

import (
	"fmt"
	"strings"

	"github.com/byteness/keyring"
	"github.com/byteness/aws-vault/v7/prompt"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/spf13/cobra"
)

type RemoveCommandInput struct {
	ProfileName  string
	SessionsOnly bool
	Force        bool
}

func ConfigureRemoveCommand(a *AwsVault) *cobra.Command {
	input := RemoveCommandInput{}

	cmd := &cobra.Command{
		Use:     "remove [profile]",
		Aliases: []string{"rm"},
		Short:   "Remove credentials from the secure keystore",
		Long:    "Remove credentials from the secure keystore",
		Args:    cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return a.CompleteProfileNames()(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			input.ProfileName = args[0]
			keyring, err := a.Keyring()
			if err != nil {
				return err
			}
			return RemoveCommand(input, keyring)
		},
	}

	cmd.Flags().BoolVarP(&input.SessionsOnly, "sessions-only", "s", false, "Only remove sessions, leave credentials intact")
	cmd.Flags().BoolVarP(&input.Force, "force", "f", false, "Force-remove the profile without a prompt")
	_ = cmd.Flags().MarkHidden("sessions-only")

	return cmd
}

func RemoveCommand(input RemoveCommandInput, keyring keyring.Keyring) error {
	ckr := &vault.CredentialKeyring{Keyring: keyring}

	// Legacy --sessions-only option for backwards compatibility, use aws-vault clear instead
	if input.SessionsOnly {
		sk := &vault.SessionKeyring{Keyring: ckr.Keyring}
		n, err := sk.RemoveForProfile(input.ProfileName)
		if err != nil {
			return err
		}
		fmt.Printf("Deleted %d sessions.\n", n)
		return nil
	}

	if !input.Force {
		r, err := prompt.TerminalPrompt(fmt.Sprintf("Delete credentials for profile %q? (y|N) ", input.ProfileName))
		if err != nil {
			return err
		}

		if !strings.EqualFold(r, "y") && !strings.EqualFold(r, "yes") {
			return nil
		}
	}

	if err := ckr.Remove(input.ProfileName); err != nil {
		return err
	}
	fmt.Printf("Deleted credentials.\n")

	return nil
}
