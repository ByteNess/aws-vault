package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
	"github.com/spf13/cobra"
	ini "gopkg.in/ini.v1"
)

type ExportCommandInput struct {
	ProfileName     string
	Format          string
	Config          vault.ProfileConfig
	SessionDuration time.Duration
	NoSession       bool
	UseStdout       bool
}

var (
	FormatTypeEnv        = "env"
	FormatTypeExportEnv  = "export-env"
	FormatTypeExportJSON = "json"
	FormatTypeExportINI  = "ini"
)

func ConfigureExportCommand(a *AwsVault) *cobra.Command {
	input := ExportCommandInput{}

	cmd := &cobra.Command{
		Use:   "export [profile]",
		Short: "Export AWS credentials",
		Long:  "Export AWS credentials",
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

			input.Config.MfaPromptMethod = a.PromptDriver(false)
			input.Config.NonChainedGetSessionTokenDuration = input.SessionDuration
			input.Config.AssumeRoleDuration = input.SessionDuration
			input.Config.SSOUseStdout = input.UseStdout

			f, err := a.AwsConfigFile()
			if err != nil {
				return err
			}
			keyring, err := a.Keyring()
			if err != nil {
				return err
			}

			if input.ProfileName == "" {
				// If no profile provided select from configured AWS profiles
				ProfileName, err := pickAwsProfile(f.ProfileNames())

				if err != nil {
					return fmt.Errorf("unable to select a 'profile'. Try --help: %w", err)
				}

				input.ProfileName = ProfileName
			}

			return ExportCommand(input, f, keyring)
		},
	}

	// Set default for stdout from environment variable if present
	stdoutDefault := false
	if os.Getenv("AWS_VAULT_STDOUT") != "" {
		stdoutDefault = true
	}

	cmd.Flags().DurationVarP(&input.SessionDuration, "duration", "d", time.Hour, "Duration of the temporary or assume-role session. Defaults to 1h")
	cmd.Flags().BoolVarP(&input.NoSession, "no-session", "n", false, "Skip creating STS session with GetSessionToken")
	cmd.Flags().StringVar(&input.Config.Region, "region", "", "The AWS region")
	cmd.Flags().StringVarP(&input.Config.MfaToken, "mfa-token", "t", "", "The MFA token to use")
	cmd.Flags().StringVar(&input.Format, "format", FormatTypeEnv, fmt.Sprintf("Format to output credentials. Valid formats: %s, %s, %s, %s", FormatTypeEnv, FormatTypeExportEnv, FormatTypeExportJSON, FormatTypeExportINI))
	cmd.Flags().BoolVar(&input.UseStdout, "stdout", stdoutDefault, "Print the SSO link to the terminal without automatically opening the browser")

	cmd.RegisterFlagCompletionFunc("duration", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"1h", "2h", "4h", "8h", "12h"}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("region", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return AwsRegions(), cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{FormatTypeEnv, FormatTypeExportEnv, FormatTypeExportJSON, FormatTypeExportINI}, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

func ExportCommand(input ExportCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) error {
	if os.Getenv("AWS_VAULT") != "" {
		return fmt.Errorf("in an existing aws-vault subshell; 'exit' from the subshell or unset AWS_VAULT to force")
	}

	config, err := vault.NewConfigLoader(input.Config, f, input.ProfileName).GetProfileConfig(input.ProfileName)
	if err != nil {
		return fmt.Errorf("Error loading config: %w", err)
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring}
	credsProvider, err := vault.NewTempCredentialsProvider(config, ckr, input.NoSession, false)
	if err != nil {
		return fmt.Errorf("Error getting temporary credentials: %w", err)
	}

	if input.Format == FormatTypeExportJSON {
		return printJSON(input, credsProvider)
	} else if input.Format == FormatTypeExportINI {
		return printINI(credsProvider, input.ProfileName, config.Region)
	} else if input.Format == FormatTypeExportEnv {
		return printEnv(input, credsProvider, config.Region, "export ")
	} else {
		return printEnv(input, credsProvider, config.Region, "")
	}
}

func printJSON(input ExportCommandInput, credsProvider aws.CredentialsProvider) error {
	// AwsCredentialHelperData is metadata for AWS CLI credential process
	// See https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
	type AwsCredentialHelperData struct {
		Version         int    `json:"Version"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken,omitempty"`
		Expiration      string `json:"Expiration,omitempty"`
	}

	creds, err := credsProvider.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", input.ProfileName, err)
	}

	credentialData := AwsCredentialHelperData{
		Version:         1,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
	}

	if creds.CanExpire {
		credentialData.Expiration = iso8601.Format(creds.Expires)
	}

	json, err := json.MarshalIndent(&credentialData, "", "  ")
	if err != nil {
		return fmt.Errorf("Error creating credential json: %w", err)
	}

	fmt.Print(string(json) + "\n")

	return nil
}

func mustNewKey(s *ini.Section, name, val string) {
	if val != "" {
		_, err := s.NewKey(name, val)
		if err != nil {
			log.Fatalln("Failed to create ini key:", err.Error())
		}
	}
}

func printINI(credsProvider aws.CredentialsProvider, profilename, region string) error {
	creds, err := credsProvider.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", profilename, err)
	}

	f := ini.Empty()
	s, err := f.NewSection(profilename)
	if err != nil {
		return fmt.Errorf("Failed to create ini section: %w", err)
	}

	mustNewKey(s, "aws_access_key_id", creds.AccessKeyID)
	mustNewKey(s, "aws_secret_access_key", creds.SecretAccessKey)
	mustNewKey(s, "aws_session_token", creds.SessionToken)
	if creds.CanExpire {
		mustNewKey(s, "aws_credential_expiration", iso8601.Format(creds.Expires))
	}
	mustNewKey(s, "region", region)

	_, err = f.WriteTo(os.Stdout)
	if err != nil {
		return fmt.Errorf("Failed to output ini: %w", err)
	}

	return nil
}

func printEnv(input ExportCommandInput, credsProvider aws.CredentialsProvider, region, prefix string) error {
	creds, err := credsProvider.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", input.ProfileName, err)
	}

	fmt.Printf("%sAWS_ACCESS_KEY_ID=%s\n", prefix, creds.AccessKeyID)
	fmt.Printf("%sAWS_SECRET_ACCESS_KEY=%s\n", prefix, creds.SecretAccessKey)

	if creds.SessionToken != "" {
		fmt.Printf("%sAWS_SESSION_TOKEN=%s\n", prefix, creds.SessionToken)
	}
	if creds.CanExpire {
		fmt.Printf("%sAWS_CREDENTIAL_EXPIRATION=%s\n", prefix, iso8601.Format(creds.Expires))
	}
	if region != "" {
		fmt.Printf("%sAWS_REGION=%s\n", prefix, region)
		fmt.Printf("%sAWS_DEFAULT_REGION=%s\n", prefix, region)
	}

	return nil
}
