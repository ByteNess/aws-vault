package cli

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

type rotateCommandInput struct {
	NoSession    bool
	ProfileName  string
	Config       vault.ProfileConfig
	ParallelSafe bool
}

// ConfigureRotateCommand registers the rotate command.
func ConfigureRotateCommand(app *kingpin.Application, a *AwsVault) {
	input := rotateCommandInput{}

	cmd := app.Command("rotate", "Rotate credentials.")

	cmd.Flag("no-session", "Use master credentials, no session or role used").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Arg("profile", "Name of the profile").
		//Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(_ *kingpin.ParseContext) (err error) {
		input.ParallelSafe = a.ParallelSafe
		input.Config.MfaPromptMethod = a.PromptDriver(false)

		f, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		keyring, sessionKeyring, err := a.Keyrings()
		if err != nil {
			return err
		}
		if !a.hasSeparateSessionKeyring() {
			sessionKeyring = nil
		}

		if input.ProfileName == "" {
			// If no profile provided select from configured AWS profiles
			ProfileName, err := pickAwsProfile(f.ProfileNames())

			if err != nil {
				return fmt.Errorf("unable to select a 'profile'. Try --help: %w", err)
			}

			input.ProfileName = ProfileName
		}

		err = rotateCommand(input, f, keyring, sessionKeyring)
		app.FatalIfError(err, "rotate")
		return nil
	})
}

func rotateCommand(input rotateCommandInput, f *vault.ConfigFile, keyring, sessionKeyring keyring.Keyring) error {
	if !profileResolvable(f, keyring, input.ProfileName) {
		return fmt.Errorf("profile '%s' not found in ~/.aws/config and no stored credentials exist for it", input.ProfileName)
	}

	configLoader := vault.NewConfigLoader(input.Config, f, input.ProfileName)
	config, err := configLoader.GetProfileConfig(input.ProfileName)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring}
	masterCredentialsName, err := vault.FindMasterCredentialsNameFor(input.ProfileName, ckr, config)
	if err != nil {
		return fmt.Errorf("determining credential name for '%s': %w", input.ProfileName, err)
	}

	if input.NoSession {
		fmt.Printf("Rotating credentials stored for profile '%s' using master credentials (takes 10-20 seconds)\n", masterCredentialsName)
	} else {
		fmt.Printf("Rotating credentials stored for profile '%s' using a session from profile '%s' (takes 10-20 seconds)\n", masterCredentialsName, input.ProfileName)
	}

	// Get the existing credentials access key ID
	oldMasterCreds, err := vault.NewMasterCredentialsProvider(ckr, masterCredentialsName).Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("loading source credentials for '%s': %w", masterCredentialsName, err)
	}
	oldMasterCredsAccessKeyID := vault.FormatKeyForDisplay(oldMasterCreds.AccessKeyID)
	log.Printf("Rotating access key %s\n", oldMasterCredsAccessKeyID)

	fmt.Println("Creating a new access key")

	// create a session to rotate the credentials
	var credsProvider aws.CredentialsProvider
	if input.NoSession {
		credsProvider = vault.NewMasterCredentialsProvider(ckr, masterCredentialsName)
	} else {
		// Can't always disable sessions completely, might need to use session for MFA-Protected API Access
		credsProvider, err = vault.NewTempCredentialsProviderWithOptions(
			config,
			ckr,
			sessionKeyring,
			input.NoSession,
			true,
			vault.TempCredentialsOptions{ParallelSafe: input.ParallelSafe},
		)
		if err != nil {
			return fmt.Errorf("getting temporary credentials: %w", err)
		}
	}

	// IAM takes a while to make a new access key usable, so keep using the credentials from before it was created
	credsProvider = aws.NewCredentialsCache(credsProvider)

	cfg := vault.NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints, config.EndpointURL)

	// A username is needed for some IAM calls if the credentials have assumed a role
	iamUserName, err := getUsernameIfAssumingRole(context.TODO(), cfg, config)
	if err != nil {
		return err
	}

	iamClient := iam.NewFromConfig(cfg)
	// Create a new access key
	createOut, err := iamClient.CreateAccessKey(context.TODO(), &iam.CreateAccessKeyInput{
		UserName: iamUserName,
	})
	if err != nil {
		return fmt.Errorf("creating a new access key: %w", err)
	}
	fmt.Printf("Created new access key %s\n", vault.FormatKeyForDisplay(*createOut.AccessKey.AccessKeyId))

	newMasterCreds := aws.Credentials{
		AccessKeyID:     *createOut.AccessKey.AccessKeyId,
		SecretAccessKey: *createOut.AccessKey.SecretAccessKey,
	}
	newMasterCredsAccessKeyID := vault.FormatKeyForDisplay(newMasterCreds.AccessKeyID)

	// If the new key can't be used, delete it and keep the old one
	rollback := func(cause error) error {
		_, err := iamClient.DeleteAccessKey(context.TODO(), &iam.DeleteAccessKeyInput{
			AccessKeyId: createOut.AccessKey.AccessKeyId,
			UserName:    iamUserName,
		})
		if err != nil {
			return fmt.Errorf("%w; deleting new access key %s also failed: %w\nDelete it with: %s",
				cause, newMasterCredsAccessKeyID, err, deleteAccessKeyCommand(input, newMasterCreds.AccessKeyID, iamUserName))
		}
		return fmt.Errorf("%w; deleted new access key %s and kept old access key %s", cause, newMasterCredsAccessKeyID, oldMasterCredsAccessKeyID)
	}

	fmt.Printf("Waiting for new access key %s to become usable\n", newMasterCredsAccessKeyID)
	if err = waitForAccessKey(newMasterCreds, config); err != nil {
		return rollback(fmt.Errorf("new access key %s never became usable: %w", newMasterCredsAccessKeyID, err))
	}

	err = ckr.Set(masterCredentialsName, newMasterCreds)
	if err != nil {
		return rollback(fmt.Errorf("storing new access key %s: %w", newMasterCredsAccessKeyID, err))
	}

	// Delete old sessions
	profileNames, err := getProfilesInChain(input.ProfileName, configLoader)
	for _, profileName := range profileNames {
		if n, _ := removeSessionsForProfile(profileName, keyring, sessionKeyring); n > 0 {
			fmt.Printf("Deleted %d sessions for %s\n", n, profileName)
		}
	}

	// Delete the old access key
	fmt.Printf("Deleting old access key %s\n", oldMasterCredsAccessKeyID)
	err = retry(accessKeyDeleteTimeout, accessKeyWaitInterval, func() error {
		_, err = iamClient.DeleteAccessKey(context.TODO(), &iam.DeleteAccessKeyInput{
			AccessKeyId: &oldMasterCreds.AccessKeyID,
			UserName:    iamUserName,
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("deleting old access key %s: %w\nThe new access key is stored, but the old one is still active. Delete it with: %s",
			oldMasterCredsAccessKeyID, err, deleteAccessKeyCommand(input, oldMasterCreds.AccessKeyID, iamUserName))
	}
	fmt.Printf("Deleted old access key %s\n", oldMasterCredsAccessKeyID)

	fmt.Println("Finished rotating access key")

	return nil
}

// Variables so tests can shorten the waits
var (
	accessKeyWaitTimeout   = time.Minute
	accessKeyDeleteTimeout = time.Second * 20
	accessKeyWaitInterval  = time.Second * 2
)

// deleteAccessKeyCommand returns a command that deletes accessKeyID by hand, using the profile being rotated.
// Access key IDs are not secret, so the full ID is shown
func deleteAccessKeyCommand(input rotateCommandInput, accessKeyID string, userName *string) string {
	cmd := "aws-vault exec "
	if input.NoSession {
		cmd += "--no-session "
	}
	cmd += input.ProfileName + " -- aws iam delete-access-key --access-key-id " + accessKeyID
	if userName != nil {
		cmd += " --user-name " + *userName
	}
	return cmd
}

// waitForAccessKey retries sts:GetCallerIdentity until IAM accepts creds. The call needs no IAM permissions or MFA
func waitForAccessKey(creds aws.Credentials, config *vault.ProfileConfig) error {
	provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return creds, nil })
	stsClient := sts.NewFromConfig(vault.NewAwsConfigWithCredsProvider(provider, config.Region, config.STSRegionalEndpoints, config.EndpointURL))
	return retry(accessKeyWaitTimeout, accessKeyWaitInterval, func() error {
		_, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
		return err
	})
}

func retry(maxTime time.Duration, sleep time.Duration, f func() error) (err error) {
	t0 := time.Now()
	i := 0
	for {
		i++

		err = f()
		if err == nil {
			return // nolint
		}

		elapsed := time.Since(t0)
		if elapsed > maxTime {
			return fmt.Errorf("after %d attempts, last error: %s", i, err)
		}

		time.Sleep(sleep)
		log.Println("Retrying after error:", err)
	}
}

func getUsernameIfAssumingRole(ctx context.Context, awsCfg aws.Config, config *vault.ProfileConfig) (*string, error) {
	if config.RoleARN != "" {
		n, err := vault.GetUsernameFromSession(ctx, awsCfg)
		if err != nil {
			return nil, fmt.Errorf("getting IAM username from session: %w", err)
		}
		log.Printf("Found IAM username '%s'", n)
		return &n, nil
	}
	return nil, nil //nolint
}

func getProfilesInChain(profileName string, configLoader *vault.ConfigLoader) (profileNames []string, err error) {
	profileNames = append(profileNames, profileName)

	config, err := configLoader.GetProfileConfig(profileName)
	if err != nil {
		return profileNames, err
	}

	if config.SourceProfile != nil {
		newProfileNames, err := getProfilesInChain(config.SourceProfileName, configLoader)
		if err != nil {
			return profileNames, err
		}
		profileNames = append(profileNames, newProfileNames...)
	}

	return profileNames, nil
}
