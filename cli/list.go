package cli

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

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
		err = ListCommand(input, awsConfigFile, keyring, os.Stdout)
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

// oidcLabel returns the Sessions-column label for an OIDC token.
// For modern configs the sso-session name is used as the identifier;
// for legacy inline sso_start_url configs the hostname is used instead.
// No TTL is included: reading it requires Get(), which on macOS triggers a
// Keychain unlock prompt and evicts expired tokens — both wrong for a
// read-only listing command.
func oidcLabel(sessionName, startURL string) string {
	id := sessionName
	if id == "" {
		if u, err := url.Parse(startURL); err == nil && u.Host != "" {
			id = u.Host
		} else {
			id = startURL
		}
	}
	return fmt.Sprintf("oidc:%s", id)
}

func ListCommand(input ListCommandInput, awsConfigFile *vault.ConfigFile, keyring keyring.Keyring, out io.Writer) (err error) {
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

	credentialsSet := make(map[string]bool, len(credentialsNames))
	for _, n := range credentialsNames {
		credentialsSet[n] = true
	}

	ssoSessionStartURLs := awsConfigFile.SSOSessionStartURLs()

	// ssoURLToSessionName is the inverse of ssoSessionStartURLs. When two
	// [sso-session] sections share the same sso_start_url, the winning name is
	// non-deterministic (Go map iteration order is random) and one profile may
	// display an incorrect session name in its label. This is a cosmetic edge
	// case: the token itself (keyed by URL) is always correct.
	ssoURLToSessionName := make(map[string]string, len(ssoSessionStartURLs))
	for name, u := range ssoSessionStartURLs {
		ssoURLToSessionName[u] = name
	}

	oidcTokenLabels := make(map[string]string, len(tokens))
	for _, startURL := range tokens {
		oidcTokenLabels[startURL] = oidcLabel(ssoURLToSessionName[startURL], startURL)
	}

	// Pre-fetch all profile sections once to avoid a second per-profile
	// GetSection()+MapTo() pass in the display loop below.
	profileSections := awsConfigFile.ProfileSections()

	profileNamesSet := make(map[string]bool, len(profileSections))
	for _, ps := range profileSections {
		profileNamesSet[ps.Name] = true
	}

	sessionsByProfile := make(map[string][]vault.SessionMetadata, len(sessions))
	for _, sess := range sessions {
		sessionsByProfile[sess.ProfileName] = append(sessionsByProfile[sess.ProfileName], sess)
	}

	allSessionLabels := []string{}
	for _, startURL := range tokens {
		if label, ok := oidcTokenLabels[startURL]; ok {
			allSessionLabels = append(allSessionLabels, label)
		}
	}
	for _, sess := range sessions {
		allSessionLabels = append(allSessionLabels, sessionLabel(sess))
	}

	if input.OnlyCredentials {
		for _, c := range credentialsNames {
			fmt.Fprintln(out, c)
		}
		return nil
	}

	if input.OnlyProfiles {
		for _, ps := range profileSections {
			fmt.Fprintln(out, ps.Name)
		}
		return nil
	}

	if input.OnlySessions {
		for _, l := range allSessionLabels {
			fmt.Fprintln(out, l)
		}
		return nil
	}

	displayedSessionLabels := []string{}

	w := tabwriter.NewWriter(out, 25, 4, 2, ' ', 0)

	fmt.Fprintln(w, "Profile\tCredentials\tSessions\t")
	fmt.Fprintln(w, "=======\t===========\t========\t")

	// list out known profiles first
	for _, profileSection := range profileSections {
		profileName := profileSection.Name
		fmt.Fprintf(w, "%s\t", profileName)

		if credentialsSet[profileName] {
			fmt.Fprintf(w, "%s\t", profileName)
		} else {
			fmt.Fprintf(w, "-\t")
		}

		var sessionLabels []string

		// check oidc keyring. Resolve the start URL via the shared precedence
		// rule, using the prefetched sso-session map to stay O(1) per profile.
		startURL := vault.ResolveSSOStartURL(profileSection.SSOStartURL, ssoSessionStartURLs[profileSection.SSOSession])
		if startURL != "" {
			if label, ok := oidcTokenLabels[startURL]; ok {
				sessionLabels = append(sessionLabels, label)
			}
		}

		// check session keyring
		for _, sess := range sessionsByProfile[profileName] {
			sessionLabels = append(sessionLabels, sessionLabel(sess))
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
		if !profileNamesSet[credentialName] {
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
