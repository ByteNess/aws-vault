package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/byteness/keyring"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/prompt"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/spf13/cobra"
)

type AddCommandInput struct {
	ProfileName string
	FromEnv     bool
	AddConfig   bool
}

func ConfigureAddCommand(a *AwsVault) *cobra.Command {
	input := AddCommandInput{}

	cmd := &cobra.Command{
		Use:   "add [profile]",
		Short: "Add credentials to the secure keystore",
		Long:  "Add credentials to the secure keystore",
		Args:  cobra.ExactArgs(1),
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
			awsConfigFile, err := a.AwsConfigFile()
			if err != nil {
				return err
			}
			return AddCommand(input, keyring, awsConfigFile)
		},
	}

	// --env flag to read credentials from environment variables
	cmd.Flags().BoolVar(&input.FromEnv, "env", false, "Read the credentials from the environment (AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)")

	// --add-config flag (default is true)
	cmd.Flags().BoolVar(&input.AddConfig, "add-config", true, "Add a profile to ~/.aws/config if one doesn't exist")

	return cmd
}

func AddCommand(input AddCommandInput, keyring keyring.Keyring, awsConfigFile *vault.ConfigFile) error {
	var accessKeyID, secretKey, mfaSerial string

	p, _ := awsConfigFile.ProfileSection(input.ProfileName)
	if p.SourceProfile != "" {
		return fmt.Errorf("Your profile has a source_profile of %s, adding credentials to %s won't have any effect",
			p.SourceProfile, input.ProfileName)
	}

	if input.FromEnv {
		if accessKeyID = os.Getenv("AWS_ACCESS_KEY_ID"); accessKeyID == "" {
			return fmt.Errorf("Missing value for AWS_ACCESS_KEY_ID")
		}
		if secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey == "" {
			return fmt.Errorf("Missing value for AWS_SECRET_ACCESS_KEY")
		}
	} else {
		var err error
		if accessKeyID, err = prompt.TerminalPrompt("Enter Access Key ID: "); err != nil {
			return err
		}
		if secretKey, err = prompt.TerminalSecretPrompt("Enter Secret Access Key: "); err != nil {
			return err
		}
		// PRESERVED: MFA serial prompt functionality
		if mfaSerial, err = prompt.TerminalPrompt("Enter MFA Device ARN (If MFA is not enabled, leave this blank): "); err != nil {
			return err
		}
	}

	creds := aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secretKey}

	ckr := &vault.CredentialKeyring{Keyring: keyring}
	if err := ckr.Set(input.ProfileName, creds); err != nil {
		return err
	}

	fmt.Printf("Added credentials to profile %q in vault\n", input.ProfileName)

	sk := &vault.SessionKeyring{Keyring: keyring}
	if n, _ := sk.RemoveForProfile(input.ProfileName); n > 0 {
		fmt.Printf("Deleted %d existing sessions.\n", n)
	}

	if _, hasProfile := awsConfigFile.ProfileSection(input.ProfileName); !hasProfile {
		if input.AddConfig {
			newProfileSection := vault.ProfileSection{
				Name:      input.ProfileName,
				MfaSerial: mfaSerial, // PRESERVED: MFA serial saved to config
			}
			log.Printf("Adding profile %s to config at %s", input.ProfileName, awsConfigFile.Path)
			if err := awsConfigFile.Add(newProfileSection); err != nil {
				return fmt.Errorf("Error adding profile: %w", err)
			}
		}
	}

	return nil
}
