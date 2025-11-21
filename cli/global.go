package cli

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/byteness/aws-vault/v7/prompt"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	isatty "github.com/mattn/go-isatty"
	"golang.org/x/term"
)

var keyringConfigDefaults = keyring.Config{
	ServiceName:              "aws-vault",
	FilePasswordFunc:         fileKeyringPassphrasePrompt,
	LibSecretCollectionName:  "awsvault",
	KWalletAppID:             "aws-vault",
	KWalletFolder:            "aws-vault",
	KeychainTrustApplication: true,
	WinCredPrefix:            "aws-vault",
	OPConnectTokenEnv:        "AWS_VAULT_OP_CONNECT_TOKEN",
	OPTokenEnv:               "AWS_VAULT_OP_SERVICE_ACCOUNT_TOKEN",
	OPTokenFunc:              keyringPassphrasePrompt,
}

type AwsVault struct {
	Debug          bool
	KeyringConfig  keyring.Config
	KeyringBackend string
	promptDriver   string

	keyringImpl   keyring.Keyring
	awsConfigFile *vault.ConfigFile
	UseBiometrics bool
}

func isATerminal() bool {
	fd := os.Stdout.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func (a *AwsVault) PromptDriver(avoidTerminalPrompt bool) string {
	if a.promptDriver == "" {
		a.promptDriver = "terminal"

		if !isATerminal() || avoidTerminalPrompt {
			for _, driver := range prompt.Available() {
				a.promptDriver = driver
				if driver != "terminal" {
					break
				}
			}
		}
	}

	log.Println("Using prompt driver: " + a.promptDriver)

	return a.promptDriver
}

func (a *AwsVault) Keyring() (keyring.Keyring, error) {
	if a.keyringImpl == nil {
		if a.KeyringBackend != "" {
			a.KeyringConfig.AllowedBackends = []keyring.BackendType{keyring.BackendType(a.KeyringBackend)}
		}
		var err error
		a.keyringImpl, err = keyring.Open(a.KeyringConfig)
		if err != nil {
			return nil, err
		}
	}

	return a.keyringImpl, nil
}

func (a *AwsVault) AwsConfigFile() (*vault.ConfigFile, error) {
	if a.awsConfigFile == nil {
		var err error
		a.awsConfigFile, err = vault.LoadConfigFromEnv()
		if err != nil {
			return nil, err
		}
	}

	return a.awsConfigFile, nil
}

func (a *AwsVault) MustGetProfileNames() []string {
	config, err := a.AwsConfigFile()
	if err != nil {
		log.Fatalf("Error loading AWS config: %s", err.Error())
	}
	return config.ProfileNames()
}

// CompleteProfileNames returns a function that provides profile names for cobra completion
func (a *AwsVault) CompleteProfileNames() func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		profiles := a.MustGetProfileNames()
		return profiles, cobra.ShellCompDirectiveNoFileComp
	}
}

// AwsRegions returns a list of all available AWS regions
func AwsRegions() []string {
	return []string{
		// US Regions
		"us-east-1",      // US East (N. Virginia)
		"us-east-2",      // US East (Ohio)
		"us-west-1",      // US West (N. California)
		"us-west-2",      // US West (Oregon)
		// Africa
		"af-south-1", // Africa (Cape Town)
		// Asia Pacific
		"ap-east-1",      // Asia Pacific (Hong Kong)
		"ap-east-2",      // Asia Pacific (Taipei)
		"ap-south-1",     // Asia Pacific (Mumbai)
		"ap-south-2",     // Asia Pacific (Hyderabad)
		"ap-northeast-1", // Asia Pacific (Tokyo)
		"ap-northeast-2", // Asia Pacific (Seoul)
		"ap-northeast-3", // Asia Pacific (Osaka)
		"ap-southeast-1", // Asia Pacific (Singapore)
		"ap-southeast-2", // Asia Pacific (Sydney)
		"ap-southeast-3", // Asia Pacific (Jakarta)
		"ap-southeast-4", // Asia Pacific (Melbourne)
		"ap-southeast-5", // Asia Pacific (Malaysia)
		"ap-southeast-6", // Asia Pacific (New Zealand)
		"ap-southeast-7", // Asia Pacific (Thailand)
		// Canada
		"ca-central-1", // Canada (Central)
		"ca-west-1",    // Canada West (Calgary)
		// Europe
		"eu-central-1", // Europe (Frankfurt)
		"eu-central-2", // Europe (Zurich)
		"eu-west-1",    // Europe (Ireland)
		"eu-west-2",    // Europe (London)
		"eu-west-3",    // Europe (Paris)
		"eu-north-1",   // Europe (Stockholm)
		"eu-south-1",   // Europe (Milan)
		"eu-south-2",   // Europe (Spain)
		// Israel
		"il-central-1", // Israel (Tel Aviv)
		// Mexico
		"mx-central-1", // Mexico (Central)
		// Middle East
		"me-central-1", // Middle East (UAE)
		"me-south-1",   // Middle East (Bahrain)
		// South America
		"sa-east-1", // South America (São Paulo)
	}
}

// ConfigureGlobals configures global flags and returns an AwsVault instance
func ConfigureGlobals(cmd *cobra.Command) *AwsVault {
	a := &AwsVault{
		KeyringConfig: keyringConfigDefaults,
	}
	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}

	promptsAvailable := prompt.Available()

	// Bind environment variables before creating flags
	if backendEnv := os.Getenv("AWS_VAULT_BACKEND"); backendEnv != "" {
		a.KeyringBackend = backendEnv
	}
	if promptEnv := os.Getenv("AWS_VAULT_PROMPT"); promptEnv != "" {
		a.promptDriver = promptEnv
	}
	if keychainEnv := os.Getenv("AWS_VAULT_KEYCHAIN_NAME"); keychainEnv != "" {
		a.KeyringConfig.KeychainName = keychainEnv
	}
	if secretServiceEnv := os.Getenv("AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME"); secretServiceEnv != "" {
		a.KeyringConfig.LibSecretCollectionName = secretServiceEnv
	}
	if passDirEnv := os.Getenv("AWS_VAULT_PASS_PASSWORD_STORE_DIR"); passDirEnv != "" {
		a.KeyringConfig.PassDir = passDirEnv
	}
	if passCmdEnv := os.Getenv("AWS_VAULT_PASS_CMD"); passCmdEnv != "" {
		a.KeyringConfig.PassCmd = passCmdEnv
	}
	if passPrefixEnv := os.Getenv("AWS_VAULT_PASS_PREFIX"); passPrefixEnv != "" {
		a.KeyringConfig.PassPrefix = passPrefixEnv
	}
	if fileDirEnv := os.Getenv("AWS_VAULT_FILE_DIR"); fileDirEnv != "" {
		a.KeyringConfig.FileDir = fileDirEnv
	}
	if opVaultIDEnv := os.Getenv("AWS_VAULT_OP_VAULT_ID"); opVaultIDEnv != "" {
		a.KeyringConfig.OPVaultID = opVaultIDEnv
	}
	if opItemTitlePrefixEnv := os.Getenv("AWS_VAULT_OP_ITEM_TITLE_PREFIX"); opItemTitlePrefixEnv != "" {
		a.KeyringConfig.OPItemTitlePrefix = opItemTitlePrefixEnv
	}
	if opItemTagEnv := os.Getenv("AWS_VAULT_OP_ITEM_TAG"); opItemTagEnv != "" {
		a.KeyringConfig.OPItemTag = opItemTagEnv
	}
	if opConnectHostEnv := os.Getenv("AWS_VAULT_OP_CONNECT_HOST"); opConnectHostEnv != "" {
		a.KeyringConfig.OPConnectHost = opConnectHostEnv
	}
	if biometricsEnv := os.Getenv("AWS_VAULT_BIOMETRICS"); biometricsEnv == "true" {
		a.UseBiometrics = true
	}

	// Set default backend if not set by environment variable
	if a.KeyringBackend == "" {
		a.KeyringBackend = backendsAvailable[0]
	}

	cmd.PersistentFlags().BoolVar(&a.Debug, "debug", false, "Show debugging output")
	cmd.PersistentFlags().StringVar(&a.KeyringBackend, "backend", a.KeyringBackend, fmt.Sprintf("Secret backend to use %v", backendsAvailable))
	cmd.PersistentFlags().StringVar(&a.promptDriver, "prompt", "", fmt.Sprintf("Prompt driver to use %v", promptsAvailable))
	cmd.PersistentFlags().StringVar(&a.KeyringConfig.KeychainName, "keychain", "aws-vault", "Name of macOS keychain to use, if it doesn't exist it will be created")
	cmd.PersistentFlags().StringVar(&a.KeyringConfig.LibSecretCollectionName, "secret-service-collection", "awsvault", "Name of secret-service collection to use, if it doesn't exist it will be created")
	cmd.PersistentFlags().StringVar(&a.KeyringConfig.PassDir, "pass-dir", "", "Pass password store directory")
	cmd.PersistentFlags().StringVar(&a.KeyringConfig.PassCmd, "pass-cmd", "", "Name of the pass executable")
	cmd.PersistentFlags().StringVar(&a.KeyringConfig.PassPrefix, "pass-prefix", "", "Prefix to prepend to the item path stored in pass")
	cmd.PersistentFlags().StringVar(&a.KeyringConfig.FileDir, "file-dir", "~/.awsvault/keys/", "Directory for the \"file\" password store")
	cmd.PersistentFlags().DurationVar(&a.KeyringConfig.OPTimeout, "op-timeout", 15e9, "Timeout for 1Password API operations (1Password Service Accounts only)")
	cmd.PersistentFlags().StringVar(&a.KeyringConfig.OPVaultID, "op-vault-id", "", "UUID of the 1Password vault")
	cmd.PersistentFlags().StringVar(&a.KeyringConfig.OPItemTitlePrefix, "op-item-title-prefix", "aws-vault", "Prefix to prepend to 1Password item titles")
	cmd.PersistentFlags().StringVar(&a.KeyringConfig.OPItemTag, "op-item-tag", "aws-vault", "Tag to apply to 1Password items")
	cmd.PersistentFlags().StringVar(&a.KeyringConfig.OPConnectHost, "op-connect-host", "", "1Password Connect server HTTP(S) URI")
	cmd.PersistentFlags().BoolVar(&a.UseBiometrics, "biometrics", false, "Use biometric authentication if supported")

	// Register flag completions - these trigger when completing flag values
	cmd.RegisterFlagCompletionFunc("backend", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return backendsAvailable, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("prompt", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return promptsAvailable, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("keychain", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("secret-service-collection", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("pass-dir", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{}, cobra.ShellCompDirectiveDefault // Allow directory completion
	})
	cmd.RegisterFlagCompletionFunc("pass-cmd", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("pass-prefix", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("file-dir", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{}, cobra.ShellCompDirectiveDefault // Allow directory completion
	})
	cmd.RegisterFlagCompletionFunc("op-timeout", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"15s", "30s", "60s"}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("op-vault-id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("op-item-title-prefix", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("op-item-tag", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("op-connect-host", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{}, cobra.ShellCompDirectiveNoFileComp
	})

	// Run validation after flags are parsed
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return validateGlobalFlags(a, promptsAvailable)
	}

	cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if !a.Debug {
			log.SetOutput(io.Discard)
		}
		keyring.Debug = a.Debug

		if a.UseBiometrics {
			configureTouchID(&a.KeyringConfig)
		}

		version, _ := cmd.Root().Annotations["version"]
		log.Printf("aws-vault %s", version)
	}

	return a
}

func validateGlobalFlags(a *AwsVault, promptsAvailable []string) error {
	if a.promptDriver == "" {
		return nil
	}
	if a.promptDriver == "pass" {
		log.Fatalf("--prompt=pass (or AWS_VAULT_PROMPT=pass) has been removed from aws-vault as using TOTPs without " +
			"a dedicated device goes against security best practices. If you wish to continue using pass, " +
			"add `mfa_process = pass otp <your mfa_serial>` to profiles in your ~/.aws/config file.")
	}
	for _, v := range promptsAvailable {
		if v == a.promptDriver {
			return nil
		}
	}
	return fmt.Errorf("--prompt value must be one of %s, got '%s'", strings.Join(promptsAvailable, ","), a.promptDriver)
}

func configureTouchID(k *keyring.Config) {
	k.UseBiometrics = true
	k.TouchIDAccount = "cc.byteness.aws-vault.biometrics"
	k.TouchIDService = "aws-vault"
}

func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password, ok := os.LookupEnv("AWS_VAULT_FILE_PASSPHRASE"); ok {
		return password, nil
	}

	return keyringPassphrasePrompt(prompt)
}

func keyringPassphrasePrompt(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}

// Archived library github.com/AlecAivazis/survey/v2
func pickAwsProfile(profiles []string) (string, error) {
	var ProfileName string

	// the questions to ask
	prompt := &survey.Select{
		Message: "Choose AWS profile:",
		Options: profiles,
	}

	// ask the question
	err := survey.AskOne(prompt, &ProfileName)

	return ProfileName, err
}

// Maintained library github.com/charmbracelet/huh (TODO: needs more testing)
func pickAwsProfile2(profiles []string) (string, error) {
	var ProfileName string

	// Convert to []huh.Option
	var opts []huh.Option[string]
	for _, p := range profiles {
		opts = append(opts, huh.NewOption(p, p))
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Choose AWS profile:").
				Options(opts...).
				Value(&ProfileName))).WithHeight(9)

	err := form.Run()
	blue := lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	fmt.Printf("%s %s\n", white.Render("Selected profile:"), blue.Render(fmt.Sprintf("%s", ProfileName)))

	return ProfileName, err
}
