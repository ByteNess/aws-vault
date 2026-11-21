package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

type ssoListAccountsCommandInput struct {
	ssoCommandInput
	Format string
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

func ssoListAccountsCommand(input ssoListAccountsCommandInput, f *vault.ConfigFile, keyring keyring.Keyring, out io.Writer) error {
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
		data, err := json.MarshalIndent(struct {
			AccountList []account `json:"accountList"`
		}{list}, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	}

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "Account ID\tAccount Name\tEmail")
	_, _ = fmt.Fprintln(tw, "==========\t============\t=====")
	for _, a := range accounts {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", a.AccountID, a.AccountName, a.EmailAddress)
	}
	return tw.Flush()
}
