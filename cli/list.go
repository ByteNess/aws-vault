package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/byteness/keyring"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/spf13/cobra"
)

type ListCommandInput struct {
	OnlyProfiles    bool
	OnlySessions    bool
	OnlyCredentials bool
}

func ConfigureListCommand(a *AwsVault) *cobra.Command {
	input := ListCommandInput{}

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List profiles, along with their credentials and sessions",
		Long:    "List profiles, along with their credentials and sessions",
		Args:    cobra.NoArgs,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			// list command takes no positional arguments, only flags
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			keyring, err := a.Keyring()
			if err != nil {
				return err
			}
			awsConfigFile, err := a.AwsConfigFile()
			if err != nil {
				return err
			}
			return ListCommand(input, awsConfigFile, keyring)
		},
	}

	cmd.Flags().BoolVar(&input.OnlyProfiles, "profiles", false, "Show only the profile names")
	cmd.Flags().BoolVar(&input.OnlySessions, "sessions", false, "Show only the session names")
	cmd.Flags().BoolVar(&input.OnlyCredentials, "credentials", false, "Show only the profiles with stored credential")

	return cmd
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

	w := tabwriter.NewWriter(os.Stdout, 25, 4, 2, ' ', 0)

	fmt.Fprintln(w, "Profile\tCredentials\tSessions\t")
	fmt.Fprintln(w, "=======\t===========\t========\t")

	// list out known profiles first
	for _, profileName := range awsConfigFile.ProfileNames() {
		fmt.Fprintf(w, "%s\t", profileName)

		hasCred, err := credentialKeyring.Has(profileName)
		if err != nil {
			return err
		}

		if hasCred {
			fmt.Fprintf(w, "%s\t", profileName)
		} else {
			fmt.Fprintf(w, "-\t")
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
			fmt.Fprintf(w, "%s\t\n", strings.Join(sessionLabels, ", "))
		} else {
			fmt.Fprintf(w, "-\t\n")
		}

		displayedSessionLabels = append(displayedSessionLabels, sessionLabels...)
	}

	// show credentials that don't have profiles
	for _, credentialName := range credentialsNames {
		_, ok := awsConfigFile.ProfileSection(credentialName)
		if !ok {
			fmt.Fprintf(w, "-\t%s\t-\t\n", credentialName)
		}
	}

	// show sessions that don't have profiles
	sessionsWithoutProfiles := stringslice(allSessionLabels).remove(displayedSessionLabels)
	for _, s := range sessionsWithoutProfiles {
		fmt.Fprintf(w, "-\t-\t%s\t\n", s)
	}

	return w.Flush()
}
