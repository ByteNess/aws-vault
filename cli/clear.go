package cli

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

type clearCommandInput struct {
	ProfileName string
}

// ConfigureClearCommand registers the clear command.
func ConfigureClearCommand(app *kingpin.Application, a *AwsVault) {
	input := clearCommandInput{}

	cmd := app.Command("clear", "Clear temporary credentials from the secure keystore.")

	cmd.Arg("profile", "Name of the profile").
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(_ *kingpin.ParseContext) (err error) {
		keyring, sessionKeyring, err := a.Keyrings()
		if err != nil {
			return err
		}
		if !a.hasSeparateSessionKeyring() {
			sessionKeyring = nil
		}
		awsConfigFile, err := a.AwsConfigFile()
		if err != nil {
			return err
		}

		err = clearCommand(input, awsConfigFile, keyring, sessionKeyring)
		app.FatalIfError(err, "clear")
		return nil
	})
}

// clearCommand removes cached sessions and OIDC tokens. A nil sessionKeyring
// means sessions share the primary keyring.
func clearCommand(input clearCommandInput, awsConfigFile *vault.ConfigFile, keyring, sessionKeyring keyring.Keyring) (err error) {
	var numSessionsRemoved int
	for _, kr := range sessionKeyrings(keyring, sessionKeyring) {
		var n int
		if n, err = clearSessions(input, kr); err != nil {
			return err
		}
		numSessionsRemoved += n
	}

	oidcTokens := &vault.OIDCTokenKeyring{Keyring: keyring}
	var numTokensRemoved int
	if input.ProfileName == "" {
		numTokensRemoved, err = oidcTokens.RemoveAll()
		if err != nil {
			return err
		}
	} else {
		if profileSection, ok := awsConfigFile.ProfileSection(input.ProfileName); ok {
			startURL := awsConfigFile.ResolvedSSOStartURL(profileSection)
			if startURL != "" {
				if exists, _ := oidcTokens.Has(startURL); exists {
					err = oidcTokens.Remove(startURL)
					if err != nil {
						return err
					}
					numTokensRemoved = 1
				}
			}
		}
	}

	fmt.Printf("Cleared %d sessions.\n", numSessionsRemoved+numTokensRemoved)

	return nil
}

func clearSessions(input clearCommandInput, keyring keyring.Keyring) (int, error) {
	sessions := &vault.SessionKeyring{Keyring: keyring}
	if input.ProfileName != "" {
		return sessions.RemoveForProfile(input.ProfileName)
	}

	oldSessionsRemoved, err := sessions.RemoveOldSessions()
	if err != nil {
		return 0, err
	}
	numSessionsRemoved, err := sessions.RemoveAll()
	return oldSessionsRemoved + numSessionsRemoved, err
}
