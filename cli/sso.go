package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// ssoCommandInput is what every sso subcommand needs to reach a sign-in.
type ssoCommandInput struct {
	ProfileName   string
	Config        vault.ProfileConfig
	UseStdout     bool
	UseDeviceCode bool
	Browser       string
	ParallelSafe  bool
}

type ssoExportCommandInput struct {
	ssoCommandInput
	Format string
}

type ssoListAccountsCommandInput struct {
	ssoCommandInput
	Format string
}

// Output formats of the sso subcommands.
const (
	formatTypeSSOPlain = "plain"
	formatTypeSSOText  = "text"
	formatTypeSSOJSON  = "json"
)

// ConfigureSSOCommand registers the sso command and its subcommands.
func ConfigureSSOCommand(app *kingpin.Application, a *AwsVault) {
	sso := app.Command("sso", "Work with AWS IAM Identity Center (SSO) sign-ins.")
	configureSSOExportCommand(app, sso, a)
	configureSSOListAccountsCommand(app, sso, a)
}

// addSSOCommandFlags adds the sign-in flags and the profile argument shared by
// the sso subcommands.
func addSSOCommandFlags(cmd *kingpin.CmdClause, a *AwsVault, input *ssoCommandInput) {
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
}

// resolveSSOCommandInput completes input from the parsed flags and globals,
// and returns the config file and keyring the subcommand runs against.
func resolveSSOCommandInput(a *AwsVault, input *ssoCommandInput) (*vault.ConfigFile, keyring.Keyring, error) {
	input.ParallelSafe = a.ParallelSafe
	input.Config.SSOUseStdout = input.UseStdout
	input.Config.SSOUseDeviceCode = input.UseDeviceCode
	input.Config.SSOBrowser = input.Browser

	f, err := a.AwsConfigFile()
	if err != nil {
		return nil, nil, err
	}
	keyring, err := a.Keyring()
	if err != nil {
		return nil, nil, err
	}

	if input.ProfileName == "" {
		input.ProfileName, err = pickAwsProfile(f.ProfileNames())
		if err != nil {
			return nil, nil, fmt.Errorf("unable to select a 'profile'. Try --help: %w", err)
		}
	}
	return f, keyring, nil
}

// ssoProvider returns the provider for the sign-in of the input's profile.
func ssoProvider(input ssoCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) (*vault.SSORoleCredentialsProvider, error) {
	if _, ok := f.ProfileSection(input.ProfileName); !ok {
		return nil, fmt.Errorf("profile '%s' not found in ~/.aws/config", input.ProfileName)
	}

	config, err := vault.NewConfigLoader(input.Config, f, input.ProfileName).GetProfileConfig(input.ProfileName)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	return vault.NewSSOAccessTokenProvider(keyring, config, input.ParallelSafe)
}

func configureSSOExportCommand(app *kingpin.Application, sso *kingpin.CmdClause, a *AwsVault) {
	input := ssoExportCommandInput{}

	cmd := sso.Command("export", "Export the SSO access token of a profile, signing in if needed. The token is a secret.")

	cmd.Flag("format", fmt.Sprintf("Format to output the token. Valid formats: %s, %s", formatTypeSSOPlain, formatTypeSSOJSON)).
		Default(formatTypeSSOPlain).
		EnumVar(&input.Format, formatTypeSSOPlain, formatTypeSSOJSON)

	addSSOCommandFlags(cmd, a, &input.ssoCommandInput)

	cmd.Action(func(_ *kingpin.ParseContext) (err error) {
		f, keyring, err := resolveSSOCommandInput(a, &input.ssoCommandInput)
		if err != nil {
			return err
		}

		err = ssoExportCommand(input, f, keyring, os.Stdout)
		app.FatalIfError(err, "sso export")
		return nil
	})
}

func ssoExportCommand(input ssoExportCommandInput, f *vault.ConfigFile, keyring keyring.Keyring, w io.Writer) error {
	provider, err := ssoProvider(input.ssoCommandInput, f, keyring)
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

func configureSSOListAccountsCommand(app *kingpin.Application, sso *kingpin.CmdClause, a *AwsVault) {
	input := ssoListAccountsCommandInput{}

	cmd := sso.Command("list-accounts", "List the AWS accounts the SSO sign-in of a profile gives access to, signing in if needed.")

	cmd.Flag("format", fmt.Sprintf("Format to output the accounts. Valid formats: %s, %s", formatTypeSSOText, formatTypeSSOJSON)).
		Default(formatTypeSSOText).
		EnumVar(&input.Format, formatTypeSSOText, formatTypeSSOJSON)

	addSSOCommandFlags(cmd, a, &input.ssoCommandInput)

	cmd.Action(func(_ *kingpin.ParseContext) (err error) {
		f, keyring, err := resolveSSOCommandInput(a, &input.ssoCommandInput)
		if err != nil {
			return err
		}

		err = ssoListAccountsCommand(input, f, keyring, os.Stdout)
		app.FatalIfError(err, "sso list-accounts")
		return nil
	})
}

func ssoListAccountsCommand(input ssoListAccountsCommandInput, f *vault.ConfigFile, keyring keyring.Keyring, w io.Writer) error {
	provider, err := ssoProvider(input.ssoCommandInput, f, keyring)
	if err != nil {
		return err
	}

	accounts, err := provider.ListAccounts(context.TODO())
	if err != nil {
		return fmt.Errorf("listing SSO accounts: %w", err)
	}

	if input.Format == formatTypeSSOJSON {
		// The shape of `aws sso list-accounts`, so scripts can switch over.
		type account struct {
			AccountID    string `json:"accountId"`
			AccountName  string `json:"accountName"`
			EmailAddress string `json:"emailAddress"`
		}
		list := make([]account, 0, len(accounts))
		for _, a := range accounts {
			list = append(list, account(a))
		}
		out, err := json.MarshalIndent(struct {
			AccountList []account `json:"accountList"`
		}{list}, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(out))
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "Account ID\tAccount Name\tEmail")
	_, _ = fmt.Fprintln(tw, "==========\t============\t=====")
	for _, a := range accounts {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", a.AccountID, a.AccountName, a.EmailAddress)
	}
	return tw.Flush()
}
