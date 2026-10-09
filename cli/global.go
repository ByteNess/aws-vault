// Package cli implements the aws-vault commands.
package cli

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/prompt"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
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
	OPDesktopAccountID:       "AWS_VAULT_OP_DESKTOP_ACCOUNT_ID",
	OPTokenFunc:              keyringPassphrasePrompt,
	ProtonPassTokenFunc:      keyringPassphrasePrompt,
}

type keyringConfigOverrides struct {
	KeychainName              string
	LibSecretCollectionName   string
	PassDir                   string
	PassCmd                   string
	PassPrefix                string
	PassageIdentitiesFile     string
	FileDir                   string
	OPVaultID                 string
	OPItemTitlePrefix         string
	OPItemTag                 string
	ProtonPassShareID         string
	ProtonPassItemTitlePrefix string
}

func (o keyringConfigOverrides) configured() bool {
	return o.KeychainName != "" ||
		o.LibSecretCollectionName != "" ||
		o.PassDir != "" ||
		o.PassCmd != "" ||
		o.PassPrefix != "" ||
		o.PassageIdentitiesFile != "" ||
		o.FileDir != "" ||
		o.OPVaultID != "" ||
		o.OPItemTitlePrefix != "" ||
		o.OPItemTag != "" ||
		o.ProtonPassShareID != "" ||
		o.ProtonPassItemTitlePrefix != ""
}

func (o keyringConfigOverrides) apply(config keyring.Config) keyring.Config {
	if o.KeychainName != "" {
		config.KeychainName = o.KeychainName
	}
	if o.LibSecretCollectionName != "" {
		config.LibSecretCollectionName = o.LibSecretCollectionName
	}
	if o.PassDir != "" {
		config.PassDir = o.PassDir
	}
	if o.PassCmd != "" {
		config.PassCmd = o.PassCmd
	}
	if o.PassPrefix != "" {
		config.PassPrefix = o.PassPrefix
	}
	if o.PassageIdentitiesFile != "" {
		config.PassageIdentitiesFile = o.PassageIdentitiesFile
	}
	if o.FileDir != "" {
		config.FileDir = o.FileDir
	}
	if o.OPVaultID != "" {
		config.OPVaultID = o.OPVaultID
	}
	if o.OPItemTitlePrefix != "" {
		config.OPItemTitlePrefix = o.OPItemTitlePrefix
	}
	if o.OPItemTag != "" {
		config.OPItemTag = o.OPItemTag
	}
	if o.ProtonPassShareID != "" {
		config.ProtonPassShareID = o.ProtonPassShareID
	}
	if o.ProtonPassItemTitlePrefix != "" {
		config.ProtonPassItemTitlePrefix = o.ProtonPassItemTitlePrefix
	}
	return config
}

// AwsVault holds the global flags and the keyring and AWS config shared by all commands.
type AwsVault struct {
	Debug                   bool
	KeyringConfig           keyring.Config
	KeyringBackend          string
	SessionKeyringBackend   string
	promptDriver            string
	sessionKeyringOverrides keyringConfigOverrides
	ParallelSafe            bool

	keyringImpl              keyring.Keyring
	sessionKeyringImpl       keyring.Keyring
	lockedKeyringImpl        keyring.Keyring
	lockedSessionKeyringImpl keyring.Keyring
	awsConfigFile            *vault.ConfigFile
	UseBiometrics            bool
}

func isATerminal() bool {
	fd := os.Stdout.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// PromptDriver returns the prompt method for MFA codes: the terminal, unless there is none or
// avoidTerminalPrompt is set, in which case the first other available method.
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

// Keyring opens the configured keyring backend on first use and returns it,
// wrapped in a cross-process lock when --parallel-safe is set.
func (a *AwsVault) Keyring() (keyring.Keyring, error) {
	raw, err := a.rawKeyring()
	if err != nil {
		return nil, err
	}
	if !a.ParallelSafe {
		return raw, nil
	}
	if a.lockedKeyringImpl == nil {
		a.lockedKeyringImpl = vault.NewLockedKeyring(raw, keyringLockKey(a.KeyringBackend, a.KeyringConfig))
	}
	return a.lockedKeyringImpl, nil
}

// RawKeyrings returns the primary and session keyrings without the
// parallel-safe lock wrapper. Used by commands like login that are excluded
// from --parallel-safe.
func (a *AwsVault) RawKeyrings() (keyring.Keyring, keyring.Keyring, error) {
	credentials, err := a.rawKeyring()
	if err != nil {
		return nil, nil, err
	}
	if !a.hasSeparateSessionKeyring() {
		log.Println("Using primary keyring for sessions")
		return credentials, credentials, nil
	}
	sessions, err := a.rawSessionKeyring()
	if err != nil {
		return nil, nil, err
	}
	return credentials, sessions, nil
}

func (a *AwsVault) rawKeyring() (keyring.Keyring, error) {
	if a.keyringImpl == nil {
		if a.KeyringBackend != "" {
			a.KeyringConfig.AllowedBackends = []keyring.BackendType{keyring.BackendType(a.KeyringBackend)}
		}
		var err error
		log.Println("Opening primary keyring")
		a.keyringImpl, err = keyring.Open(a.KeyringConfig)
		if err != nil {
			return nil, err
		}
	}

	return a.keyringImpl, nil
}

// keyringLockKey returns a key for the cross-process keyring lock that
// identifies the underlying store, so that processes using the same store
// share a lock however they specify it, and different stores don't contend.
func keyringLockKey(backend string, config keyring.Config) string {
	if backend == "" {
		backends := keyring.AvailableBackends()
		if len(backends) == 0 {
			return "aws-vault"
		}
		backend = string(backends[0])
	}

	switch keyring.BackendType(backend) {
	case keyring.KeychainBackend:
		if config.KeychainName != "" {
			return backend + ":" + config.KeychainName
		}
	case keyring.FileBackend:
		if config.FileDir != "" {
			return backend + ":" + canonicalStoreDir(config.FileDir, "", "")
		}
	case keyring.PassBackend:
		return backend + ":" + canonicalStoreDir(config.PassDir, "PASSWORD_STORE_DIR", ".password-store")
	case keyring.PassageBackend:
		return backend + ":" + canonicalStoreDir(config.PassDir, "PASSAGE_DIR", filepath.Join(".passage", "store"))
	case keyring.SecretServiceBackend:
		if config.LibSecretCollectionName != "" {
			return backend + ":" + config.LibSecretCollectionName
		}
	case keyring.KWalletBackend:
		if config.KWalletFolder != "" {
			return backend + ":" + config.KWalletFolder
		}
	case keyring.WinCredBackend:
		if config.WinCredPrefix != "" {
			return backend + ":" + config.WinCredPrefix
		}
	case keyring.OPBackend, keyring.OPConnectBackend, keyring.OPDesktopBackend:
		if config.OPVaultID != "" {
			return backend + ":" + config.OPVaultID
		}
	}
	return backend
}

// canonicalStoreDir resolves a store directory the way the keyring backends
// do: an empty dir falls back to envVar, then to homeRel under the home
// directory, and ~ is expanded. The result is absolute and clean.
func canonicalStoreDir(dir, envVar, homeRel string) string {
	if dir == "" && envVar != "" {
		dir = os.Getenv(envVar)
	}
	if dir == "" && homeRel != "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, homeRel)
		}
	}
	if expanded, err := keyring.ExpandTilde(dir); err == nil {
		dir = expanded
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return filepath.Clean(dir)
}

func (a *AwsVault) hasSeparateSessionKeyring() bool {
	return a.SessionKeyringBackend != "" || a.sessionKeyringOverrides.configured()
}

func (a *AwsVault) sessionKeyringBackend() string {
	if a.SessionKeyringBackend != "" {
		return a.SessionKeyringBackend
	}
	return a.KeyringBackend
}

// SessionKeyring opens the session keyring on first use, defaulting to the
// primary keyring, wrapped in a cross-process lock when --parallel-safe is set.
func (a *AwsVault) SessionKeyring() (keyring.Keyring, error) {
	if !a.hasSeparateSessionKeyring() {
		log.Println("Using primary keyring for sessions")
		return a.Keyring()
	}

	raw, err := a.rawSessionKeyring()
	if err != nil {
		return nil, err
	}
	if !a.ParallelSafe {
		return raw, nil
	}
	if a.lockedSessionKeyringImpl == nil {
		config := a.sessionKeyringOverrides.apply(a.KeyringConfig)
		a.lockedSessionKeyringImpl = vault.NewLockedKeyring(raw, keyringLockKey(a.sessionKeyringBackend(), config))
	}
	return a.lockedSessionKeyringImpl, nil
}

func (a *AwsVault) rawSessionKeyring() (keyring.Keyring, error) {
	if a.sessionKeyringImpl == nil {
		config := a.sessionKeyringOverrides.apply(a.KeyringConfig)
		if backend := a.sessionKeyringBackend(); backend != "" {
			config.AllowedBackends = []keyring.BackendType{keyring.BackendType(backend)}
		}

		var err error
		log.Println("Opening session keyring")
		a.sessionKeyringImpl, err = keyring.Open(config)
		if err != nil {
			return nil, err
		}
	}

	return a.sessionKeyringImpl, nil
}

// Keyrings returns the primary and session keyrings.
func (a *AwsVault) Keyrings() (keyring.Keyring, keyring.Keyring, error) {
	credentials, err := a.Keyring()
	if err != nil {
		return nil, nil, err
	}
	sessions, err := a.SessionKeyring()
	if err != nil {
		return nil, nil, err
	}
	return credentials, sessions, nil
}

// sessionKeyrings returns the keyrings that may hold cached sessions, the one in
// use first. A nil sessions means sessions share the primary keyring. Otherwise
// primary is included too, as it keeps sessions cached before a separate keyring
// was set up.
func sessionKeyrings(primary, sessions keyring.Keyring) []keyring.Keyring {
	if sessions == nil {
		return []keyring.Keyring{primary}
	}
	return []keyring.Keyring{sessions, primary}
}

// removeSessionsForProfile deletes the cached sessions for profileName from
// sessionKeyrings and returns how many it deleted.
func removeSessionsForProfile(profileName string, primary, sessions keyring.Keyring) (n int, err error) {
	for _, kr := range sessionKeyrings(primary, sessions) {
		var removed int
		removed, err = (&vault.SessionKeyring{Keyring: kr}).RemoveForProfile(profileName)
		n += removed
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// AwsConfigFile loads the AWS config file on first use and returns it.
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

// MustGetProfileNames returns the profile names in the AWS config file, exiting if it can't be loaded.
func (a *AwsVault) MustGetProfileNames() []string {
	config, err := a.AwsConfigFile()
	if err != nil {
		log.Fatalf("Error loading AWS config: %s", err.Error())
	}
	return config.ProfileNames()
}

// ConfigureGlobals registers the global flags and returns the state they populate.
func ConfigureGlobals(app *kingpin.Application) *AwsVault {
	a := &AwsVault{
		KeyringConfig: keyringConfigDefaults,
	}

	backends := keyring.AvailableBackends()
	backendsAvailable := make([]string, 0, len(backends))
	for _, backendType := range backends {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}

	promptsAvailable := prompt.Available()

	app.Flag("debug", "Show debugging output").
		BoolVar(&a.Debug)

	app.Flag("backend", fmt.Sprintf("Secret backend to use %v", backendsAvailable)).
		Default(backendsAvailable[0]).
		Envar("AWS_VAULT_BACKEND").
		EnumVar(&a.KeyringBackend, backendsAvailable...)

	app.Flag("session-backend", fmt.Sprintf("Secret backend to use for sessions %v", backendsAvailable)).
		Envar("AWS_VAULT_SESSION_BACKEND").
		EnumVar(&a.SessionKeyringBackend, backendsAvailable...)

	app.Flag("prompt", fmt.Sprintf("Prompt driver to use %v", promptsAvailable)).
		Envar("AWS_VAULT_PROMPT").
		StringVar(&a.promptDriver)

	app.Validate(func(_ *kingpin.Application) error {
		if a.promptDriver == "" {
			return nil
		}
		if a.promptDriver == "pass" {
			kingpin.Fatalf("--prompt=pass (or AWS_VAULT_PROMPT=pass) has been removed from aws-vault as using TOTPs without " +
				"a dedicated device goes against security best practices. If you wish to continue using pass, " +
				"add `mfa_process = pass otp <your mfa_serial>` to profiles in your ~/.aws/config file.")
		}
		for _, v := range promptsAvailable {
			if v == a.promptDriver {
				return nil
			}
		}
		return fmt.Errorf("--prompt value must be one of %s, got '%s'", strings.Join(promptsAvailable, ","), a.promptDriver)
	})

	app.Flag("keychain", "Name of macOS keychain to use, if it doesn't exist it will be created").
		Default("aws-vault").
		Envar("AWS_VAULT_KEYCHAIN_NAME").
		StringVar(&a.KeyringConfig.KeychainName)

	app.Flag("session-keychain", "Name of macOS keychain to use for sessions").
		Envar("AWS_VAULT_SESSION_KEYCHAIN_NAME").
		StringVar(&a.sessionKeyringOverrides.KeychainName)

	app.Flag("secret-service-collection", "Name of secret-service collection to use, if it doesn't exist it will be created").
		Default("awsvault").
		Envar("AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME").
		StringVar(&a.KeyringConfig.LibSecretCollectionName)

	app.Flag("session-secret-service-collection", "Name of secret-service collection to use for sessions").
		Envar("AWS_VAULT_SESSION_SECRET_SERVICE_COLLECTION_NAME").
		StringVar(&a.sessionKeyringOverrides.LibSecretCollectionName)

	app.Flag("pass-dir", "Pass password store directory").
		Envar("AWS_VAULT_PASS_PASSWORD_STORE_DIR").
		StringVar(&a.KeyringConfig.PassDir)

	app.Flag("session-pass-dir", "Pass password store directory to use for sessions").
		Envar("AWS_VAULT_SESSION_PASS_PASSWORD_STORE_DIR").
		StringVar(&a.sessionKeyringOverrides.PassDir)

	app.Flag("pass-cmd", "Name of the pass executable").
		Envar("AWS_VAULT_PASS_CMD").
		StringVar(&a.KeyringConfig.PassCmd)

	app.Flag("session-pass-cmd", "Name of the pass executable to use for sessions").
		Envar("AWS_VAULT_SESSION_PASS_CMD").
		StringVar(&a.sessionKeyringOverrides.PassCmd)

	app.Flag("pass-prefix", "Prefix to prepend to the item path stored in pass").
		Envar("AWS_VAULT_PASS_PREFIX").
		StringVar(&a.KeyringConfig.PassPrefix)

	app.Flag("session-pass-prefix", "Prefix to prepend to session item paths stored in pass").
		Envar("AWS_VAULT_SESSION_PASS_PREFIX").
		StringVar(&a.sessionKeyringOverrides.PassPrefix)

	app.Flag("passage-identities-file", "Passage identities file").
		Envar("AWS_VAULT_PASSAGE_IDENTITIES_FILE").
		StringVar(&a.KeyringConfig.PassageIdentitiesFile)

	app.Flag("session-passage-identities-file", "Passage identities file to use for sessions").
		Envar("AWS_VAULT_SESSION_PASSAGE_IDENTITIES_FILE").
		StringVar(&a.sessionKeyringOverrides.PassageIdentitiesFile)

	app.Flag("file-dir", "Directory for the \"file\" password store").
		Default("~/.awsvault/keys/").
		Envar("AWS_VAULT_FILE_DIR").
		StringVar(&a.KeyringConfig.FileDir)

	app.Flag("session-file-dir", "Directory for the session \"file\" password store").
		Envar("AWS_VAULT_SESSION_FILE_DIR").
		StringVar(&a.sessionKeyringOverrides.FileDir)

	app.Flag("op-timeout", "Timeout for 1Password API operations (1Password Service Accounts only)").
		Default("15s").
		Envar("AWS_VAULT_OP_TIMEOUT").
		DurationVar(&a.KeyringConfig.OPTimeout)

	app.Flag("op-vault-id", "UUID of the 1Password vault").
		Envar("AWS_VAULT_OP_VAULT_ID").
		StringVar(&a.KeyringConfig.OPVaultID)

	app.Flag("session-op-vault-id", "UUID of the 1Password vault to use for sessions").
		Envar("AWS_VAULT_SESSION_OP_VAULT_ID").
		StringVar(&a.sessionKeyringOverrides.OPVaultID)

	app.Flag("op-item-title-prefix", "Prefix to prepend to 1Password item titles").
		Default("aws-vault").
		Envar("AWS_VAULT_OP_ITEM_TITLE_PREFIX").
		StringVar(&a.KeyringConfig.OPItemTitlePrefix)

	app.Flag("session-op-item-title-prefix", "Prefix to prepend to 1Password session item titles").
		Envar("AWS_VAULT_SESSION_OP_ITEM_TITLE_PREFIX").
		StringVar(&a.sessionKeyringOverrides.OPItemTitlePrefix)

	app.Flag("op-item-tag", "Tag to apply to 1Password items").
		Default("aws-vault").
		Envar("AWS_VAULT_OP_ITEM_TAG").
		StringVar(&a.KeyringConfig.OPItemTag)

	app.Flag("session-op-item-tag", "Tag to apply to 1Password session items").
		Envar("AWS_VAULT_SESSION_OP_ITEM_TAG").
		StringVar(&a.sessionKeyringOverrides.OPItemTag)

	app.Flag("op-connect-host", "1Password Connect server HTTP(S) URI").
		Envar("AWS_VAULT_OP_CONNECT_HOST").
		StringVar(&a.KeyringConfig.OPConnectHost)

	app.Flag("op-desktop-account-id", "1Password Desktop App account name or account UUID").
		Envar("AWS_VAULT_OP_DESKTOP_ACCOUNT_ID").
		StringVar(&a.KeyringConfig.OPDesktopAccountID)

	app.Flag("proton-pass-share-id", "Share ID of the Proton Pass vault to use").
		Envar("AWS_VAULT_PROTON_PASS_SHARE_ID").
		StringVar(&a.KeyringConfig.ProtonPassShareID)

	app.Flag("session-proton-pass-share-id", "Share ID of the Proton Pass vault to use for sessions").
		Envar("AWS_VAULT_SESSION_PROTON_PASS_SHARE_ID").
		StringVar(&a.sessionKeyringOverrides.ProtonPassShareID)

	app.Flag("proton-pass-item-title-prefix", "Prefix to prepend to Proton Pass item titles (default inherited from keyring)").
		Envar("AWS_VAULT_PROTON_PASS_ITEM_TITLE_PREFIX").
		StringVar(&a.KeyringConfig.ProtonPassItemTitlePrefix)

	app.Flag("session-proton-pass-item-title-prefix", "Prefix to prepend to Proton Pass session item titles").
		Envar("AWS_VAULT_SESSION_PROTON_PASS_ITEM_TITLE_PREFIX").
		StringVar(&a.sessionKeyringOverrides.ProtonPassItemTitlePrefix)

	app.Flag("proton-pass-api-base", "Proton API base URL (default inherited from keyring)").
		Envar("AWS_VAULT_PROTON_PASS_API_BASE").
		StringVar(&a.KeyringConfig.ProtonPassAPIBase)

	app.Flag("proton-pass-timeout", "Timeout for Proton Pass API operations (default inherited from keyring)").
		Envar("AWS_VAULT_PROTON_PASS_TIMEOUT").
		DurationVar(&a.KeyringConfig.ProtonPassTimeout)

	app.Flag("biometrics", "Use biometric authentication if supported").
		Envar("AWS_VAULT_BIOMETRICS").
		BoolVar(&a.UseBiometrics)

	app.Flag("parallel-safe", "Enable cross-process locking for keyring operations, session caching, and SSO browser flows").
		Envar("AWS_VAULT_PARALLEL_SAFE").
		BoolVar(&a.ParallelSafe)

	app.PreAction(func(_ *kingpin.ParseContext) error {
		if !a.Debug {
			log.SetOutput(io.Discard)
		}
		keyring.Debug = a.Debug

		if a.UseBiometrics {
			configureTouchID(&a.KeyringConfig)
		}

		log.Printf("aws-vault %s", app.Model().Version)
		return nil
	})

	return a
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
	/*var countryQs = []*survey.Question{
	      {
	          Name: "profileName",
	          Prompt: &survey.Select{
	              Message: "Choose AWS profile:",
	              Options: f.ProfileNames(),
	          },
	          Validate: survey.Required,
	      },
	  }

	  answers := struct {
	      ProfileName string
	  }{}*/

	// ask the question
	err := survey.AskOne(prompt, &ProfileName)
	//err := survey.Ask(countryQs, &answers)

	return ProfileName, err
}

// TODO: evaluate github.com/charmbracelet/huh as a replacement for the survey picker;
// re-add huh and lipgloss to go.mod when restoring.
/*
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
*/

// profileResolvable reports whether profileName can be used as a target profile:
// either it has a section in the AWS config file, or long-term credentials are
// stored under that name in the keyring. It is used to reject a mistyped or
// non-existent profile before it silently inherits the [default] profile.
func profileResolvable(f *vault.ConfigFile, k keyring.Keyring, profileName string) bool {
	if _, ok := f.ProfileSection(profileName); ok {
		return true
	}
	hasCred, _ := (&vault.CredentialKeyring{Keyring: k}).Has(profileName)
	return hasCred
}
