package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

type ssoExportCommandInput struct {
	ProfileName   string
	Format        string
	Config        vault.ProfileConfig
	UseStdout     bool
	UseDeviceCode bool
	Browser       string
	ParallelSafe  bool
}

// Output formats of the sso export command.
const (
	formatTypeSSOPlain = "plain"
	formatTypeSSOJSON  = "json"
)

// ConfigureSSOCommand registers the sso command and its subcommands.
func ConfigureSSOCommand(app *kingpin.Application, a *AwsVault) {
	sso := app.Command("sso", "Work with AWS IAM Identity Center (SSO) sign-ins.")
	configureSSOExportCommand(app, sso, a)
}

func configureSSOExportCommand(app *kingpin.Application, sso *kingpin.CmdClause, a *AwsVault) {
	input := ssoExportCommandInput{}

	cmd := sso.Command("export", "Export the SSO access token of a profile, signing in if needed. The token is a secret.")

	cmd.Flag("format", fmt.Sprintf("Format to output the token. Valid formats: %s, %s", formatTypeSSOPlain, formatTypeSSOJSON)).
		Default(formatTypeSSOPlain).
		EnumVar(&input.Format, formatTypeSSOPlain, formatTypeSSOJSON)

	cmd.Flag("stdout", "Print the SSO link to the terminal without automatically opening the browser").
		OverrideDefaultFromEnvar("AWS_VAULT_STDOUT").
		BoolVar(&input.UseStdout)

	cmd.Flag("device-code", "Use the device-code OAuth2 flow for SSO instead of the default PKCE browser flow").
		OverrideDefaultFromEnvar("AWS_VAULT_DEVICE_CODE").
		BoolVar(&input.UseDeviceCode)

	cmd.Flag("browser", "Browser to open the SSO sign-in page in instead of the default browser, e.g. google-chrome, or \"Google Chrome\" on macOS").
		Envar("AWS_VAULT_BROWSER").
		StringVar(&input.Browser)

	cmd.Arg("profile", "Name of the profile").
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(_ *kingpin.ParseContext) (err error) {
		input.ParallelSafe = a.ParallelSafe
		input.Config.SSOUseStdout = input.UseStdout
		input.Config.SSOUseDeviceCode = input.UseDeviceCode
		input.Config.SSOBrowser = input.Browser

		f, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}

		if input.ProfileName == "" {
			input.ProfileName, err = pickAwsProfile(f.ProfileNames())
			if err != nil {
				return fmt.Errorf("unable to select a 'profile'. Try --help: %w", err)
			}
		}

		err = ssoExportCommand(input, f, keyring, os.Stdout)
		app.FatalIfError(err, "sso export")
		return nil
	})
}

func ssoExportCommand(input ssoExportCommandInput, f *vault.ConfigFile, keyring keyring.Keyring, w io.Writer) error {
	if _, ok := f.ProfileSection(input.ProfileName); !ok {
		return fmt.Errorf("profile '%s' not found in ~/.aws/config", input.ProfileName)
	}

	config, err := vault.NewConfigLoader(input.Config, f, input.ProfileName).GetProfileConfig(input.ProfileName)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	provider, err := vault.NewSSOAccessTokenProvider(keyring, config, input.ParallelSafe)
	if err != nil {
		return err
	}

	token, err := provider.AccessToken(context.TODO())
	if err != nil {
		return fmt.Errorf("getting SSO access token: %w", err)
	}

	if input.Format == formatTypeSSOJSON {
		// Field names follow the AWS CLI's ~/.aws/sso/cache token files.
		out, err := json.MarshalIndent(struct {
			AccessToken string `json:"accessToken"`
			ExpiresAt   string `json:"expiresAt"`
		}{
			AccessToken: token.AccessToken,
			ExpiresAt:   token.Expiration.UTC().Format(time.RFC3339),
		}, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(out))
		return err
	}

	_, err = fmt.Fprintln(w, token.AccessToken)
	return err
}
