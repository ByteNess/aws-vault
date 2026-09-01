package cli

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

type ClearCommandInput struct {
	ProfileName string
}

func ConfigureClearCommand(app *kingpin.Application, a *AwsVault) {
	input := ClearCommandInput{}

	cmd := app.Command("clear", "Clear temporary credentials from the secure keystore.")

	cmd.Arg("profile", "Name of the profile").
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		keyring, sessionKeyring, err := a.Keyrings()
		if err != nil {
			return err
		}
		awsConfigFile, err := a.AwsConfigFile()
		if err != nil {
			return err
		}

		err = ClearCommand(input, awsConfigFile, keyring, sessionKeyring)
		app.FatalIfError(err, "clear")
		return nil
	})
}

func ClearCommand(input ClearCommandInput, awsConfigFile *vault.ConfigFile, keyring, sessionKeyring keyring.Keyring) error {
	numSessionsRemoved, err := clearSessions(input, keyring)
	if err != nil {
		return err
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

	if keyring != sessionKeyring {
		n, err := clearSessions(input, sessionKeyring)
		if err != nil {
			return err
		}
		numSessionsRemoved += n
	}

	fmt.Printf("Cleared %d sessions.\n", numSessionsRemoved+numTokensRemoved)

	return nil
}

func clearSessions(input ClearCommandInput, keyring keyring.Keyring) (int, error) {
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
