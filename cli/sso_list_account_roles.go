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

type ssoListAccountRolesCommandInput struct {
	ssoCommandInput
	AccountID string
	Format    string
}

func configureSSOListAccountRolesCommand(app *kingpin.Application, sso *kingpin.CmdClause, a *AwsVault) {
	input := ssoListAccountRolesCommandInput{}

	cmd := sso.Command("list-account-roles", "List the roles the SSO sign-in of a profile gives access to in an AWS account, signing in if needed.")

	cmd.Flag("account-id", "The AWS account to list roles for. Defaults to the sso_account_id of the profile").
		StringVar(&input.AccountID)

	cmd.Flag("format", fmt.Sprintf("Format to output the roles. Valid formats: %s, %s", formatTypeSSOText, formatTypeSSOJSON)).
		Default(formatTypeSSOText).
		EnumVar(&input.Format, formatTypeSSOText, formatTypeSSOJSON)

	addSSOCommandFlags(cmd, a, &input.ssoCommandInput)

	cmd.Action(func(_ *kingpin.ParseContext) (err error) {
		f, keyring, err := resolveSSOCommandInput(a, &input.ssoCommandInput)
		if err != nil {
			return err
		}

		err = ssoListAccountRolesCommand(input, f, keyring, os.Stdout)
		app.FatalIfError(err, "sso list-account-roles")
		return nil
	})
}

func ssoListAccountRolesCommand(input ssoListAccountRolesCommandInput, f *vault.ConfigFile, keyring keyring.Keyring, out io.Writer) error {
	provider, err := ssoProvider(input.ssoCommandInput, f, keyring)
	if err != nil {
		return err
	}

	accountID := input.AccountID
	if accountID == "" {
		accountID = provider.AccountID
	}
	if accountID == "" {
		return fmt.Errorf("profile '%s' has no sso_account_id: pass --account-id", input.ProfileName)
	}

	roles, err := provider.ListAccountRoles(context.TODO(), accountID)
	if err != nil {
		return fmt.Errorf("listing SSO roles for account %s: %w", accountID, err)
	}

	if input.Format == formatTypeSSOJSON {
		// The shape of `aws sso list-account-roles`, so scripts can switch over.
		type role struct {
			RoleName  string `json:"roleName"`
			AccountID string `json:"accountId"`
		}
		list := make([]role, 0, len(roles))
		for _, r := range roles {
			list = append(list, role{RoleName: r.RoleName, AccountID: r.AccountID})
		}
		data, err := json.MarshalIndent(struct {
			RoleList []role `json:"roleList"`
		}{list}, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	}

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "Account ID\tRole Name")
	_, _ = fmt.Fprintln(tw, "==========\t=========")
	for _, r := range roles {
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", r.AccountID, r.RoleName)
	}
	return tw.Flush()
}
