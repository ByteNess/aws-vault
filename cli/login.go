package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
	"github.com/skratchdot/open-golang/open"
)

type LoginCommandInput struct {
	ProfileName     string
	UseStdout       bool
	Path            string
	Config          vault.ProfileConfig
	SessionDuration time.Duration
	NoSession       bool
	AutoLogout      bool
}

func ConfigureLoginCommand(app *kingpin.Application, a *AwsVault) {
	input := LoginCommandInput{}

	cmd := app.Command("login", "Generate a login link for the AWS Console.")

	cmd.Flag("duration", "Duration of the assume-role or federated session. Defaults to 1h").
		Short('d').
		DurationVar(&input.SessionDuration)

	cmd.Flag("no-session", "Skip creating STS session with GetSessionToken").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Flag("auto-logout", "Auto logout when starting a new login").
		Short('a').
		Envar("AWS_VAULT_AUTO_LOGOUT").
		BoolVar(&input.AutoLogout)

	cmd.Flag("mfa-token", "The MFA token to use").
		Short('t').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("path", "The AWS service you would like access").
		StringVar(&input.Path)

	cmd.Flag("region", "The AWS region").
		StringVar(&input.Config.Region)

	cmd.Flag("stdout", "Print login URL to stdout instead of opening in default browser").
		OverrideDefaultFromEnvar("AWS_VAULT_STDOUT").
		Short('s').
		BoolVar(&input.UseStdout)

	cmd.Arg("profile", "Name of the profile. If none given, credentials will be sourced from env vars").
		Default(os.Getenv("AWS_PROFILE")).
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		input.Config.MfaPromptMethod = a.PromptDriver(false)
		input.Config.NonChainedGetSessionTokenDuration = input.SessionDuration
		input.Config.AssumeRoleDuration = input.SessionDuration
		input.Config.GetFederationTokenDuration = input.SessionDuration
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		f, err := a.AwsConfigFile()
		if err != nil {
			return err
		}

		err = LoginCommand(context.Background(), input, f, keyring)
		app.FatalIfError(err, "login")
		return nil
	})
}

func getCredsProvider(input LoginCommandInput, config *vault.ProfileConfig, f *vault.ConfigFile, keyring keyring.Keyring) (credsProvider aws.CredentialsProvider, err error) {
	if input.ProfileName == "" {
		// When no profile is specified, source credentials from the environment
		configFromEnv, err := awsconfig.NewEnvConfig()
		if err != nil {
			return nil, fmt.Errorf("unable to authenticate to AWS through your environment variables: %w", err)
		}

		if configFromEnv.Credentials.AccessKeyID == "" {
			// If no credentials from the environment ask for profile
			ProfileName, err := pickAwsProfile(f.ProfileNames())

			if err != nil {
				return nil, fmt.Errorf("unable to select a 'profile', nor any AWS env vars found. Try --help: %w", err)
			}

			// Load config from selected AWS profile
			config, err := vault.NewConfigLoader(input.Config, f, ProfileName).GetProfileConfig(ProfileName)
			if err != nil {
				return nil, fmt.Errorf("Error loading config: %w", err)
			}

			// Use selected profile from the AWS config file
			ckr := &vault.CredentialKeyring{Keyring: keyring}
			t := vault.TempCredentialsCreator{
				Keyring:                   ckr,
				DisableSessions:           input.NoSession,
				DisableSessionsForProfile: config.ProfileName,
			}
			credsProvider, err = t.GetProviderForProfile(config)
			if err != nil {
				return nil, fmt.Errorf("profile %s: %w", ProfileName, err)
			}

			return credsProvider, err
		}

		credsProvider = credentials.StaticCredentialsProvider{Value: configFromEnv.Credentials}
	} else {
		// Use a profile from the AWS config file
		ckr := &vault.CredentialKeyring{Keyring: keyring}
		t := vault.TempCredentialsCreator{
			Keyring:                   ckr,
			DisableSessions:           input.NoSession,
			DisableSessionsForProfile: config.ProfileName,
		}
		credsProvider, err = t.GetProviderForProfile(config)
		if err != nil {
			return nil, fmt.Errorf("profile %s: %w", input.ProfileName, err)
		}
	}

	return credsProvider, err
}

// LoginCommand creates a login URL for the AWS Management Console using the method described at
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html
func LoginCommand(ctx context.Context, input LoginCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) error {
	config, err := vault.NewConfigLoader(input.Config, f, input.ProfileName).GetProfileConfig(input.ProfileName)
	if err != nil {
		return fmt.Errorf("Error loading config: %w", err)
	}

	credsProvider, err := getCredsProvider(input, config, f, keyring)
	if err != nil {
		return err
	}

	// if we already know the type of credentials being created, avoid calling isCallerIdentityAssumedRole
	canCredsBeUsedInLoginURL, err := canProviderBeUsedForLogin(credsProvider)
	if err != nil {
		return err
	}

	if !canCredsBeUsedInLoginURL {
		// use a static creds provider so that we don't request credentials from AWS more than once
		credsProvider, err = createStaticCredentialsProvider(ctx, credsProvider)
		if err != nil {
			return err
		}

		// if the credentials have come from an unknown source like credential_process, check the
		// caller identity to see if it's an assumed role
		isAssumedRole, err := isCallerIdentityAssumedRole(ctx, credsProvider, config)
		if err != nil {
			return err
		}

		if !isAssumedRole {
			log.Println("Creating a federated session")
			credsProvider, err = vault.NewFederationTokenProvider(ctx, credsProvider, config)
			if err != nil {
				return err
			}
		}
	}

	creds, err := credsProvider.Retrieve(ctx)
	if err != nil {
		return err
	}

	if creds.CanExpire {
		log.Printf("Requesting a signin token for session expiring in %s", time.Until(creds.Expires))
	}

	loginURLPrefix, destination := generateLoginURL(config.Region, input.Path)
	signinToken, err := requestSigninToken(ctx, creds, loginURLPrefix)
	if err != nil {
		return err
	}

	var loginURL string

	if input.AutoLogout {
		// Use logout URL and redirect to login
		redirectURL := fmt.Sprintf("%s?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
			loginURLPrefix, destination, signinToken)
		loginURL = fmt.Sprintf("https://us-east-1.signin.aws.amazon.com/oauth?Action=logout&redirect_uri=%s",
			url.QueryEscape(redirectURL))
	} else {
		// Go directly to login
		loginURL = fmt.Sprintf("%s?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
			loginURLPrefix, url.QueryEscape(destination), url.QueryEscape(signinToken))
	}

	if input.UseStdout {
		fmt.Println(loginURL)
	} else if err = open.Run(loginURL); err != nil {
		return fmt.Errorf("Failed to open %s: %w", loginURL, err)
	}

	return nil
}

func generateLoginURL(region string, path string) (string, string) {
	loginURLPrefix := "https://us-east-1.signin.aws.amazon.com/federation"
	destination := "https://console.aws.amazon.com/"

	if region != "" {
		destinationDomain := "console.aws.amazon.com"
		switch {
		case strings.HasPrefix(region, "cn-"):
			loginURLPrefix = "https://signin.amazonaws.cn/federation"
			destinationDomain = "console.amazonaws.cn"
		case strings.HasPrefix(region, "us-gov-"):
			loginURLPrefix = "https://signin.amazonaws-us-gov.com/federation"
			destinationDomain = "console.amazonaws-us-gov.com"
		}
		if path != "" {
			destination = fmt.Sprintf("https://%s.%s/%s?region=%s",
				region, destinationDomain, path, region)
		} else {
			destination = fmt.Sprintf("https://%s.%s/console/home?region=%s",
				region, destinationDomain, region)
		}
	}
	return loginURLPrefix, destination
}

func isCallerIdentityAssumedRole(ctx context.Context, credsProvider aws.CredentialsProvider, config *vault.ProfileConfig) (bool, error) {
	cfg := vault.NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints, config.EndpointURL)
	client := sts.NewFromConfig(cfg)
	id, err := client.GetCallerIdentity(ctx, nil)
	if err != nil {
		return false, err
	}
	arn := aws.ToString(id.Arn)
	arnParts := strings.Split(arn, ":")
	if len(arnParts) < 6 {
		return false, fmt.Errorf("unable to parse ARN: %s", arn)
	}
	if strings.HasPrefix(arnParts[5], "assumed-role") {
		return true, nil
	}
	return false, nil
}

func createStaticCredentialsProvider(ctx context.Context, credsProvider aws.CredentialsProvider) (sc credentials.StaticCredentialsProvider, err error) {
	creds, err := credsProvider.Retrieve(ctx)
	if err != nil {
		return sc, err
	}
	return credentials.StaticCredentialsProvider{Value: creds}, nil
}

// canProviderBeUsedForLogin returns true if the credentials produced by the provider is known to be usable by the login URL endpoint
func canProviderBeUsedForLogin(credsProvider aws.CredentialsProvider) (bool, error) {
	if _, ok := credsProvider.(*vault.AssumeRoleProvider); ok {
		return true, nil
	}
	if _, ok := credsProvider.(*vault.SSORoleCredentialsProvider); ok {
		return true, nil
	}
	if _, ok := credsProvider.(*vault.AssumeRoleWithWebIdentityProvider); ok {
		return true, nil
	}
	if c, ok := credsProvider.(*vault.CachedSessionProvider); ok {
		return canProviderBeUsedForLogin(c.SessionProvider)
	}

	return false, nil
}

// Create a signin token
func requestSigninToken(ctx context.Context, creds aws.Credentials, loginURLPrefix string) (string, error) {
	jsonSession, err := json.Marshal(map[string]string{
		"sessionId":    creds.AccessKeyID,
		"sessionKey":   creds.SecretAccessKey,
		"sessionToken": creds.SessionToken,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", loginURLPrefix, nil)
	if err != nil {
		return "", err
	}

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonSession))
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Response body was %s", body)
		return "", fmt.Errorf("Call to getSigninToken failed with %v", resp.Status)
	}

	var respParsed map[string]string

	err = json.Unmarshal(body, &respParsed)
	if err != nil {
		return "", err
	}

	signinToken, ok := respParsed["SigninToken"]
	if !ok {
		return "", fmt.Errorf("Expected a response with SigninToken")
	}

	return signinToken, nil
}
