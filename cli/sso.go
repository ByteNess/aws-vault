package cli

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// ssoCommandInput is what every sso subcommand needs to reach a sign-in.
type ssoCommandInput struct {
	ProfileName   string
	SSOSession    string
	Config        vault.ProfileConfig
	UseStdout     bool
	UseDeviceCode bool
	Browser       string
	ParallelSafe  bool
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
	configureSSOListAccountRolesCommand(app, sso, a)
}

// addSSOCommandFlags adds the sign-in flags, the --sso-session flag and the
// profile argument shared by the sso subcommands.
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

	cmd.Flag("sso-session", "Name of an [sso-session] section to sign in to, instead of a profile").
		HintAction(a.MustGetSSOSessionNames).
		StringVar(&input.SSOSession)

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

	if input.ProfileName == "" && input.SSOSession == "" {
		input.ProfileName, err = pickAwsProfile(f.ProfileNames())
		if err != nil {
			return nil, nil, fmt.Errorf("unable to select a 'profile'. Try --help: %w", err)
		}
	}
	return f, keyring, nil
}

// ssoProvider returns the provider for the sign-in of the input's profile, or
// of its [sso-session] section when --sso-session names one.
func ssoProvider(input ssoCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) (*vault.SSORoleCredentialsProvider, error) {
	if input.SSOSession != "" {
		if input.ProfileName != "" {
			return nil, fmt.Errorf("--sso-session and the profile '%s' both select a sign-in: pass only one", input.ProfileName)
		}
		config, err := vault.NewConfigLoader(input.Config, f, "").GetSSOSessionConfig(input.SSOSession)
		if err != nil {
			return nil, err
		}
		return vault.NewSSOAccessTokenProvider(keyring, config, input.ParallelSafe)
	}

	if _, ok := f.ProfileSection(input.ProfileName); !ok {
		return nil, fmt.Errorf("profile '%s' not found in ~/.aws/config", input.ProfileName)
	}

	config, err := vault.NewConfigLoader(input.Config, f, input.ProfileName).GetProfileConfig(input.ProfileName)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	return vault.NewSSOAccessTokenProvider(keyring, config, input.ParallelSafe)
}
