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
	NoSession   bool
	ProfileName string
	Config      vault.ProfileConfig
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
		input.Config.MfaPromptMethod = a.PromptDriver(false)

		f, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}

		if input.ProfileName == "" {
			// If no profile provided select from configured AWS profiles
			ProfileName, err := pickAwsProfile(f.ProfileNames())

			if err != nil {
				return fmt.Errorf("unable to select a 'profile'. Try --help: %w", err)
			}

			input.ProfileName = ProfileName
		}

		err = rotateCommand(input, f, keyring)
		app.FatalIfError(err, "rotate")
		return nil
	})
}

func rotateCommand(input rotateCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) error {
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
		credsProvider = vault.NewMasterCredentialsProvider(ckr, config.ProfileName)
	} else {
		// Can't always disable sessions completely, might need to use session for MFA-Protected API Access
		credsProvider, err = vault.NewTempCredentialsProvider(config, ckr, input.NoSession, true)
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

	// If IAM never accepts the new key, delete it and keep the old one
	fmt.Printf("Waiting for new access key %s to become usable\n", newMasterCredsAccessKeyID)
	if err = waitForAccessKey(newMasterCreds, config); err != nil {
		_, delErr := iamClient.DeleteAccessKey(context.TODO(), &iam.DeleteAccessKeyInput{
			AccessKeyId: createOut.AccessKey.AccessKeyId,
			UserName:    iamUserName,
		})
		if delErr != nil {
			return fmt.Errorf("new access key %s never became usable (%w), and deleting it failed: %w", newMasterCredsAccessKeyID, err, delErr)
		}
		return fmt.Errorf("new access key %s never became usable, deleted it and kept old access key %s: %w", newMasterCredsAccessKeyID, oldMasterCredsAccessKeyID, err)
	}

	err = ckr.Set(masterCredentialsName, newMasterCreds)
	if err != nil {
		return fmt.Errorf("storing new access key %s: %w", newMasterCredsAccessKeyID, err)
	}

	// Delete old sessions
	sk := &vault.SessionKeyring{Keyring: ckr.Keyring}
	profileNames, err := getProfilesInChain(input.ProfileName, configLoader)
	for _, profileName := range profileNames {
		if n, _ := sk.RemoveForProfile(profileName); n > 0 {
			fmt.Printf("Deleted %d sessions for %s\n", n, profileName)
		}
	}

	// Delete the old access key
	fmt.Printf("Deleting old access key %s\n", oldMasterCredsAccessKeyID)
	err = retry(time.Second*20, time.Second*2, func() error {
		_, err = iamClient.DeleteAccessKey(context.TODO(), &iam.DeleteAccessKeyInput{
			AccessKeyId: &oldMasterCreds.AccessKeyID,
			UserName:    iamUserName,
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("deleting old access key %s: %w", oldMasterCredsAccessKeyID, err)
	}
	fmt.Printf("Deleted old access key %s\n", oldMasterCredsAccessKeyID)

	fmt.Println("Finished rotating access key")

	return nil
}

// Variables so tests can shorten the wait
var (
	accessKeyWaitTimeout  = time.Minute
	accessKeyWaitInterval = time.Second * 2
)

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
