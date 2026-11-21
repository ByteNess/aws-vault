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
	ssoCommandInput
	Format string
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

func ssoExportCommand(input ssoExportCommandInput, f *vault.ConfigFile, keyring keyring.Keyring, out io.Writer) error {
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
		data, err := json.MarshalIndent(struct {
			AccessToken string `json:"accessToken"`
			ExpiresAt   string `json:"expiresAt"`
		}{
			AccessToken: token.AccessToken,
			ExpiresAt:   token.Expiration.UTC().Format(time.RFC3339),
		}, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	}

	_, err = fmt.Fprintln(out, token.AccessToken)
	return err
}
