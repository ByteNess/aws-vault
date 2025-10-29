package cli

import (
	"fmt"

	"github.com/byteness/keyring"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/spf13/cobra"
)

type ClearCommandInput struct {
	ProfileName string
}

func ConfigureClearCommand(a *AwsVault) *cobra.Command {
	input := ClearCommandInput{}

	cmd := &cobra.Command{
		Use:   "clear [profile]",
		Short: "Clear temporary credentials from the secure keystore",
		Long:  "Clear temporary credentials from the secure keystore",
		Args:  cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return a.CompleteProfileNames()(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				input.ProfileName = args[0]
			}

			keyring, err := a.Keyring()
			if err != nil {
				return err
			}
			awsConfigFile, err := a.AwsConfigFile()
			if err != nil {
				return err
			}

			return ClearCommand(input, awsConfigFile, keyring)
		},
	}

	return cmd
}

func ClearCommand(input ClearCommandInput, awsConfigFile *vault.ConfigFile, keyring keyring.Keyring) error {
	sessions := &vault.SessionKeyring{Keyring: keyring}
	oidcTokens := &vault.OIDCTokenKeyring{Keyring: keyring}
	var oldSessionsRemoved, numSessionsRemoved, numTokensRemoved int
	var err error
	if input.ProfileName == "" {
		oldSessionsRemoved, err = sessions.RemoveOldSessions()
		if err != nil {
			return err
		}
		numSessionsRemoved, err = sessions.RemoveAll()
		if err != nil {
			return err
		}
		numTokensRemoved, err = oidcTokens.RemoveAll()
		if err != nil {
			return err
		}
	} else {
		numSessionsRemoved, err = sessions.RemoveForProfile(input.ProfileName)
		if err != nil {
			return err
		}

		if profileSection, ok := awsConfigFile.ProfileSection(input.ProfileName); ok {
			if exists, _ := oidcTokens.Has(profileSection.SSOStartURL); exists {
				err = oidcTokens.Remove(profileSection.SSOStartURL)
				if err != nil {
					return err
				}
				numTokensRemoved = 1
			}
		}
	}
	fmt.Printf("Cleared %d sessions.\n", oldSessionsRemoved+numSessionsRemoved+numTokensRemoved)

	return nil
}
