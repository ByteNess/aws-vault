package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// listRow holds the display values for one output row.
// Empty string fields are rendered as "-" by writeTo.
type listRow struct {
	Profile     string
	Credentials string
	Sessions    string
}

// display returns s, or "-" if s is empty.
func (r listRow) display(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (r listRow) writeTo(w io.Writer) {
	fmt.Fprintf(w, "%s\t%s\t%s\t\n",
		r.display(r.Profile),
		r.display(r.Credentials),
		r.display(r.Sessions),
	)
}

// listCommandOutput holds all rows to display in the table.
type listCommandOutput struct {
	Rows []listRow
}

func (o listCommandOutput) writeTo(w io.Writer) {
	fmt.Fprintln(w, "Profile\tCredentials\tSessions\t")
	fmt.Fprintln(w, "=======\t===========\t========\t")

	for _, r := range o.Rows {
		r.writeTo(w)
	}
}

type ListCommandInput struct {
	OnlyProfiles    bool
	OnlySessions    bool
	OnlyCredentials bool
}

func ConfigureListCommand(app *kingpin.Application, a *AwsVault) {
	input := ListCommandInput{}

	cmd := app.Command("list", "List profiles, along with their credentials and sessions.")
	cmd.Alias("ls")

	cmd.Flag("profiles", "Show only the profile names").
		BoolVar(&input.OnlyProfiles)

	cmd.Flag("sessions", "Show only the session names").
		BoolVar(&input.OnlySessions)

	cmd.Flag("credentials", "Show only the profiles with stored credential").
		BoolVar(&input.OnlyCredentials)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		awsConfigFile, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		err = ListCommand(input, awsConfigFile, keyring)
		app.FatalIfError(err, "list")
		return nil
	})
}

type stringslice []string

func (ss stringslice) remove(stringsToRemove []string) (newSS []string) {
	xx := stringslice(stringsToRemove)
	for _, s := range ss {
		if !xx.has(s) {
			newSS = append(newSS, s)
		}
	}

	return
}

func (ss stringslice) has(s string) bool {
	for _, t := range ss {
		if s == t {
			return true
		}
	}
	return false
}

func sessionLabel(sess vault.SessionMetadata) string {
	return fmt.Sprintf("%s:%s", sess.Type, time.Until(sess.Expiration).Truncate(time.Second))
}

func ListCommand(input ListCommandInput, awsConfigFile *vault.ConfigFile, keyring keyring.Keyring) (err error) {
	credentialKeyring := &vault.CredentialKeyring{Keyring: keyring}
	oidcTokenKeyring := &vault.OIDCTokenKeyring{Keyring: credentialKeyring.Keyring}
	sessionKeyring := &vault.SessionKeyring{Keyring: credentialKeyring.Keyring}

	credentialsNames, err := credentialKeyring.Keys()
	if err != nil {
		return err
	}

	tokens, err := oidcTokenKeyring.Keys()
	if err != nil {
		return err
	}

	sessions, err := sessionKeyring.GetAllMetadata()
	if err != nil {
		return err
	}

	allSessionLabels := []string{}
	for _, t := range tokens {
		allSessionLabels = append(allSessionLabels, fmt.Sprintf("oidc:%s", t))
	}
	for _, sess := range sessions {
		allSessionLabels = append(allSessionLabels, sessionLabel(sess))
	}

	if input.OnlyCredentials {
		for _, c := range credentialsNames {
			fmt.Println(c)
		}
		return nil
	}

	if input.OnlyProfiles {
		for _, profileName := range awsConfigFile.ProfileNames() {
			fmt.Println(profileName)
		}
		return nil
	}

	if input.OnlySessions {
		for _, l := range allSessionLabels {
			fmt.Println(l)
		}
		return nil
	}

	displayedSessionLabels := []string{}

	var rows []listRow

	// list out known profiles first
	for _, profileName := range awsConfigFile.ProfileNames() {
		row := listRow{Profile: profileName}

		hasCred, err := credentialKeyring.Has(profileName)
		if err != nil {
			return err
		}

		if hasCred {
			row.Credentials = profileName
		}

		var sessionLabels []string

		// check oidc keyring
		if profileSection, ok := awsConfigFile.ProfileSection(profileName); ok {
			if exists, _ := oidcTokenKeyring.Has(profileSection.SSOStartURL); exists {
				sessionLabels = append(sessionLabels, fmt.Sprintf("oidc:%s", profileSection.SSOStartURL))
			}
		}

		// check session keyring
		for _, sess := range sessions {
			if profileName == sess.ProfileName {
				sessionLabels = append(sessionLabels, sessionLabel(sess))
			}
		}

		if len(sessionLabels) > 0 {
			row.Sessions = strings.Join(sessionLabels, ", ")
		}

		rows = append(rows, row)
		displayedSessionLabels = append(displayedSessionLabels, sessionLabels...)
	}

	// show credentials that don't have profiles
	for _, credentialName := range credentialsNames {
		_, ok := awsConfigFile.ProfileSection(credentialName)
		if !ok {
			rows = append(rows, listRow{Credentials: credentialName})
		}
	}

	// show sessions that don't have profiles
	sessionsWithoutProfiles := stringslice(allSessionLabels).remove(displayedSessionLabels)
	for _, s := range sessionsWithoutProfiles {
		rows = append(rows, listRow{Sessions: s})
	}

	w := tabwriter.NewWriter(os.Stdout, 25, 4, 2, ' ', 0)
	o := listCommandOutput{Rows: rows}
	o.writeTo(w)
	return w.Flush()
}
