package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// issue377Config mirrors the configuration from issue #377: a canonical
// [default] profile backed by SSO plus a second named SSO profile. The bug was
// that targeting a non-existent profile silently inherited [default]'s SSO
// account instead of erroring.
var issue377Config = []byte(`[sso-session login-session]
sso_start_url = https://example.awsapps.com/start#/
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[default]
region = us-east-1
sso_account_id = 222222222222
sso_session = login-session
sso_role_name = ReadOnly

[profile demo]
region = us-east-1
sso_account_id = 333333333333
sso_session = login-session
sso_role_name = ReadOnly
`)

func writeTempConfig(t *testing.T, b []byte) *vault.ConfigFile {
	t.Helper()
	// Write to a path rather than using os.CreateTemp: CreateTemp returns an
	// open file handle, and on Windows t.TempDir() cleanup cannot remove a file
	// that still has a live handle.
	path := filepath.Join(t.TempDir(), "aws-config")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	configFile, err := vault.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return configFile
}

func TestProfileResolvable(t *testing.T) {
	configFile := writeTempConfig(t, issue377Config)

	// "creds-only" exists only in the keyring (added via `aws-vault add`), with
	// no matching [profile] section. This is a supported case and must remain
	// resolvable.
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "creds-only", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})

	tests := []struct {
		name        string
		profileName string
		want        bool
	}{
		{"named profile with a config section", "demo", true},
		{"the default profile", "default", true},
		{"credentials-only profile present in keyring", "creds-only", true},
		{"non-existent profile (issue #377)", "invalid-profile", false},
		{"empty profile name", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := profileResolvable(configFile, kr, tc.profileName); got != tc.want {
				t.Errorf("profileResolvable(%q) = %v, want %v", tc.profileName, got, tc.want)
			}
		})
	}
}

func TestSessionKeyringDefaultsToPrimaryKeyring(t *testing.T) {
	primary := keyring.NewArrayKeyring(nil)
	a := &AwsVault{keyringImpl: primary}

	sessions, err := a.SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if sessions != primary {
		t.Fatal("expected sessions to use the primary keyring by default")
	}
}

func TestParallelSafeSessionKeyringSharesPrimaryLock(t *testing.T) {
	primary := keyring.NewArrayKeyring(nil)
	a := &AwsVault{keyringImpl: primary, ParallelSafe: true}

	credentials, sessions, err := a.Keyrings()
	if err != nil {
		t.Fatal(err)
	}
	if credentials == primary {
		t.Fatal("expected the primary keyring to be wrapped in a lock")
	}
	if sessions != credentials {
		t.Fatal("expected sessions to use the locked primary keyring by default")
	}
}

func TestParallelSafeSeparateSessionKeyringIsLocked(t *testing.T) {
	primary := keyring.NewArrayKeyring(nil)
	separate := keyring.NewArrayKeyring(nil)
	a := &AwsVault{
		keyringImpl:           primary,
		sessionKeyringImpl:    separate,
		SessionKeyringBackend: "file",
		ParallelSafe:          true,
	}

	credentials, sessions, err := a.Keyrings()
	if err != nil {
		t.Fatal(err)
	}
	if sessions == separate {
		t.Fatal("expected the session keyring to be wrapped in a lock")
	}
	if sessions == credentials {
		t.Fatal("expected sessions to use the separate session keyring")
	}

	again, err := a.SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if again != sessions {
		t.Fatal("expected the locked session keyring to be reused")
	}
}

func TestRawKeyringsSkipParallelSafeLock(t *testing.T) {
	primary := keyring.NewArrayKeyring(nil)
	separate := keyring.NewArrayKeyring(nil)
	a := &AwsVault{
		keyringImpl:           primary,
		sessionKeyringImpl:    separate,
		SessionKeyringBackend: "file",
		ParallelSafe:          true,
	}

	credentials, sessions, err := a.RawKeyrings()
	if err != nil {
		t.Fatal(err)
	}
	if credentials != primary || sessions != separate {
		t.Fatal("expected RawKeyrings to return the unwrapped keyrings")
	}

	a = &AwsVault{keyringImpl: primary, ParallelSafe: true}
	credentials, sessions, err = a.RawKeyrings()
	if err != nil {
		t.Fatal(err)
	}
	if credentials != primary || sessions != primary {
		t.Fatal("expected RawKeyrings to return the unwrapped primary keyring for sessions by default")
	}
}

func TestSessionKeyringOverridesConfigured(t *testing.T) {
	tests := []struct {
		name      string
		overrides keyringConfigOverrides
	}{
		{"1Password vault ID", keyringConfigOverrides{OPVaultID: "session-vault"}},
		{"1Password item title prefix", keyringConfigOverrides{OPItemTitlePrefix: "sessions"}},
		{"1Password item tag", keyringConfigOverrides{OPItemTag: "sessions"}},
		{"Proton Pass share ID", keyringConfigOverrides{ProtonPassShareID: "session-share"}},
		{"Proton Pass item title prefix", keyringConfigOverrides{ProtonPassItemTitlePrefix: "sessions"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.overrides.configured() {
				t.Fatal("session override was not detected")
			}
		})
	}
}

func TestKeyringLockKey(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		config  keyring.Config
		want    string
	}{
		// Keychain backend
		{
			name:    "keychain with keychain name",
			backend: "keychain",
			config:  keyring.Config{KeychainName: "my-keychain"},
			want:    "keychain:my-keychain",
		},
		{
			name:    "keychain with empty keychain name",
			backend: "keychain",
			config:  keyring.Config{},
			want:    "keychain",
		},

		// File backend
		{
			name:    "file with file dir",
			backend: "file",
			config:  keyring.Config{FileDir: "/tmp/keys"},
			want:    "file:/tmp/keys",
		},
		{
			name:    "file with empty file dir",
			backend: "file",
			config:  keyring.Config{},
			want:    "file",
		},

		// Pass backend: dir and prefix combinations
		{
			name:    "pass with dir and prefix",
			backend: "pass",
			config:  keyring.Config{PassDir: "/store", PassPrefix: "aws"},
			want:    "pass:/store:aws",
		},
		{
			name:    "pass with dir only",
			backend: "pass",
			config:  keyring.Config{PassDir: "/store"},
			want:    "pass:/store",
		},
		{
			name:    "pass with prefix only",
			backend: "pass",
			config:  keyring.Config{PassPrefix: "aws"},
			want:    "pass:aws",
		},
		{
			name:    "pass with neither dir nor prefix",
			backend: "pass",
			config:  keyring.Config{},
			want:    "pass",
		},

		// Secret-service backend
		{
			name:    "secret-service with collection name",
			backend: "secret-service",
			config:  keyring.Config{LibSecretCollectionName: "awsvault"},
			want:    "secret-service:awsvault",
		},
		{
			name:    "secret-service with empty collection name",
			backend: "secret-service",
			config:  keyring.Config{},
			want:    "secret-service",
		},

		// KWallet backend
		{
			name:    "kwallet with folder",
			backend: "kwallet",
			config:  keyring.Config{KWalletFolder: "aws-vault"},
			want:    "kwallet:aws-vault",
		},
		{
			name:    "kwallet with empty folder",
			backend: "kwallet",
			config:  keyring.Config{},
			want:    "kwallet",
		},

		// WinCred backend
		{
			name:    "wincred with prefix",
			backend: "wincred",
			config:  keyring.Config{WinCredPrefix: "aws-vault"},
			want:    "wincred:aws-vault",
		},
		{
			name:    "wincred with empty prefix",
			backend: "wincred",
			config:  keyring.Config{},
			want:    "wincred",
		},

		// 1Password backends (all share OPVaultID)
		{
			name:    "op with vault ID",
			backend: "op",
			config:  keyring.Config{OPVaultID: "vault-123"},
			want:    "op:vault-123",
		},
		{
			name:    "op with empty vault ID",
			backend: "op",
			config:  keyring.Config{},
			want:    "op",
		},
		{
			name:    "op-connect with vault ID",
			backend: "op-connect",
			config:  keyring.Config{OPVaultID: "vault-456"},
			want:    "op-connect:vault-456",
		},
		{
			name:    "op-connect with empty vault ID",
			backend: "op-connect",
			config:  keyring.Config{},
			want:    "op-connect",
		},
		{
			name:    "op-desktop with vault ID",
			backend: "op-desktop",
			config:  keyring.Config{OPVaultID: "vault-789"},
			want:    "op-desktop:vault-789",
		},
		{
			name:    "op-desktop with empty vault ID",
			backend: "op-desktop",
			config:  keyring.Config{},
			want:    "op-desktop",
		},

		// Fallback cases
		{
			name:    "unknown backend falls back to backend name",
			backend: "some-unknown-backend",
			config:  keyring.Config{},
			want:    "some-unknown-backend",
		},
		{
			name:    "empty backend falls back to aws-vault",
			backend: "",
			config:  keyring.Config{},
			want:    "aws-vault",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keyringLockKey(tt.backend, tt.config)
			if got != tt.want {
				t.Errorf("keyringLockKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSessionKeyringOverridesInheritPrimaryConfig(t *testing.T) {
	primary := keyring.Config{
		PassDir:                   "/primary/store",
		PassPrefix:                "credentials",
		PassageIdentitiesFile:     "/primary/identities",
		LibSecretCollectionName:   "primary",
		OPVaultID:                 "primary-vault",
		OPItemTitlePrefix:         "primary",
		OPItemTag:                 "primary",
		ProtonPassShareID:         "primary-share",
		ProtonPassItemTitlePrefix: "primary",
	}
	overrides := keyringConfigOverrides{
		PassPrefix:                "sessions",
		PassageIdentitiesFile:     "/session/identities",
		OPVaultID:                 "session-vault",
		OPItemTitlePrefix:         "sessions",
		OPItemTag:                 "sessions",
		ProtonPassShareID:         "session-share",
		ProtonPassItemTitlePrefix: "sessions",
	}

	sessions := overrides.apply(primary)
	if sessions.PassDir != primary.PassDir {
		t.Fatalf("PassDir = %q, want inherited value %q", sessions.PassDir, primary.PassDir)
	}
	if sessions.LibSecretCollectionName != primary.LibSecretCollectionName {
		t.Fatalf("LibSecretCollectionName = %q, want inherited value %q", sessions.LibSecretCollectionName, primary.LibSecretCollectionName)
	}
	if sessions.PassPrefix != overrides.PassPrefix {
		t.Fatalf("PassPrefix = %q, want override %q", sessions.PassPrefix, overrides.PassPrefix)
	}
	if sessions.PassageIdentitiesFile != overrides.PassageIdentitiesFile {
		t.Fatalf("PassageIdentitiesFile = %q, want override %q", sessions.PassageIdentitiesFile, overrides.PassageIdentitiesFile)
	}
	if sessions.OPVaultID != overrides.OPVaultID || sessions.OPItemTitlePrefix != overrides.OPItemTitlePrefix || sessions.OPItemTag != overrides.OPItemTag {
		t.Fatal("1Password session overrides were not applied")
	}
	if sessions.ProtonPassShareID != overrides.ProtonPassShareID || sessions.ProtonPassItemTitlePrefix != overrides.ProtonPassItemTitlePrefix {
		t.Fatal("Proton Pass session overrides were not applied")
	}
	if primary.PassPrefix != "credentials" ||
		primary.PassageIdentitiesFile != "/primary/identities" ||
		primary.OPVaultID != "primary-vault" ||
		primary.OPItemTitlePrefix != "primary" ||
		primary.OPItemTag != "primary" ||
		primary.ProtonPassShareID != "primary-share" ||
		primary.ProtonPassItemTitlePrefix != "primary" {
		t.Fatal("applying session overrides modified the primary config")
	}
}

func TestSessionKeyringEnvironmentConfiguration(t *testing.T) {
	backend := string(keyring.AvailableBackends()[0])
	t.Setenv("AWS_VAULT_BACKEND", backend)
	t.Setenv("AWS_VAULT_PASSAGE_IDENTITIES_FILE", "/primary/identities")
	t.Setenv("AWS_VAULT_SESSION_BACKEND", backend)
	t.Setenv("AWS_VAULT_SESSION_PASS_PREFIX", "sessions")
	t.Setenv("AWS_VAULT_SESSION_PASSAGE_IDENTITIES_FILE", "/session/identities")
	t.Setenv("AWS_VAULT_SESSION_OP_VAULT_ID", "session-vault")
	t.Setenv("AWS_VAULT_SESSION_OP_ITEM_TITLE_PREFIX", "sessions")
	t.Setenv("AWS_VAULT_SESSION_OP_ITEM_TAG", "sessions")
	t.Setenv("AWS_VAULT_SESSION_PROTON_PASS_SHARE_ID", "session-share")
	t.Setenv("AWS_VAULT_SESSION_PROTON_PASS_ITEM_TITLE_PREFIX", "sessions")

	app := kingpin.New("aws-vault", "")
	a := ConfigureGlobals(app)
	app.Command("noop", "")
	if _, err := app.Parse([]string{"noop"}); err != nil {
		t.Fatal(err)
	}

	if a.KeyringConfig.PassageIdentitiesFile != "/primary/identities" {
		t.Fatalf("primary PassageIdentitiesFile = %q", a.KeyringConfig.PassageIdentitiesFile)
	}
	if a.SessionKeyringBackend != backend {
		t.Fatalf("session backend = %q, want %q", a.SessionKeyringBackend, backend)
	}
	if a.sessionKeyringOverrides.PassPrefix != "sessions" {
		t.Fatalf("session PassPrefix = %q", a.sessionKeyringOverrides.PassPrefix)
	}
	if a.sessionKeyringOverrides.PassageIdentitiesFile != "/session/identities" {
		t.Fatalf("session PassageIdentitiesFile = %q", a.sessionKeyringOverrides.PassageIdentitiesFile)
	}
	if a.sessionKeyringOverrides.OPVaultID != "session-vault" ||
		a.sessionKeyringOverrides.OPItemTitlePrefix != "sessions" ||
		a.sessionKeyringOverrides.OPItemTag != "sessions" {
		t.Fatal("1Password session environment configuration was not applied")
	}
	if a.sessionKeyringOverrides.ProtonPassShareID != "session-share" ||
		a.sessionKeyringOverrides.ProtonPassItemTitlePrefix != "sessions" {
		t.Fatal("Proton Pass session environment configuration was not applied")
	}
}

// TestExecCommandRejectsMissingProfile is the regression test for issue #377:
// exec must error on a non-existent profile rather than silently inheriting
// [default]. The guard fires before any config load or execve, so calling
// execCommand directly is safe on every platform.
func TestExecCommandRejectsMissingProfile(t *testing.T) {
	t.Setenv("AWS_VAULT", "") // ensure we are not treated as an existing subshell
	configFile := writeTempConfig(t, issue377Config)
	kr := keyring.NewArrayKeyring([]keyring.Item{})

	_, err := execCommand(execCommandInput{ProfileName: "invalid-profile", NoSession: true}, configFile, kr, kr)
	if err == nil {
		t.Fatal("execCommand accepted a non-existent profile; expected an error (issue #377)")
	}
	if !strings.Contains(err.Error(), "invalid-profile") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestExportCommandRejectsMissingProfile covers the same guard on export, which
// also closes the `exec --json` path (it delegates to exportCommand).
func TestExportCommandRejectsMissingProfile(t *testing.T) {
	t.Setenv("AWS_VAULT", "")
	configFile := writeTempConfig(t, issue377Config)
	kr := keyring.NewArrayKeyring([]keyring.Item{})

	err := exportCommand(exportCommandInput{ProfileName: "invalid-profile", Format: formatTypeEnv, NoSession: true}, configFile, kr, kr)
	if err == nil {
		t.Fatal("exportCommand accepted a non-existent profile; expected an error (issue #377)")
	}
	if !strings.Contains(err.Error(), "invalid-profile") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestRotateCommandRejectsMissingProfile covers the same guard on rotate, so a
// typo'd profile can't rotate the keys of the inherited [default] profile.
func TestRotateCommandRejectsMissingProfile(t *testing.T) {
	configFile := writeTempConfig(t, issue377Config)
	kr := keyring.NewArrayKeyring([]keyring.Item{})

	err := rotateCommand(rotateCommandInput{ProfileName: "invalid-profile", NoSession: true}, configFile, kr, kr)
	if err == nil {
		t.Fatal("rotateCommand accepted a non-existent profile; expected an error (issue #377)")
	}
	if !strings.Contains(err.Error(), "invalid-profile") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestMissingProfileInheritsDefault documents the underlying loader behaviour
// that makes the guard necessary: GetProfileConfig does not error for a missing
// profile and silently fills it from [default]. If this ever fails, the loader
// behaviour changed and the CLI guard may no longer be the only thing between a
// typo and the wrong account.
func TestMissingProfileInheritsDefault(t *testing.T) {
	configFile := writeTempConfig(t, issue377Config)

	loader := &vault.ConfigLoader{File: configFile, ActiveProfile: "invalid-profile"}
	config, err := loader.GetProfileConfig("invalid-profile")
	if err != nil {
		t.Fatalf("loader unexpectedly errored: %v", err)
	}
	if config.SSOAccountID != "222222222222" {
		t.Fatalf("expected missing profile to inherit default SSO account %q, got %q",
			"222222222222", config.SSOAccountID)
	}
}

func setTestSession(t *testing.T, kr keyring.Keyring, profileName string) {
	t.Helper()
	expires := time.Now().Add(time.Hour)
	if err := (&vault.SessionKeyring{Keyring: kr}).Set(vault.SessionMetadata{
		Type:        "sts.GetSessionToken",
		ProfileName: profileName,
	}, &ststypes.Credentials{
		AccessKeyId:     aws.String("AKIAEXAMPLE"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
		Expiration:      &expires,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveSessionsForProfileRemovesFromBothKeyrings(t *testing.T) {
	primary := keyring.NewArrayKeyring(nil)
	sessions := keyring.NewArrayKeyring(nil)
	setTestSession(t, primary, "sso-profile")
	setTestSession(t, sessions, "sso-profile")
	setTestSession(t, sessions, "no-creds-profile")

	n, err := removeSessionsForProfile("sso-profile", primary, sessions)
	if err != nil || n != 2 {
		t.Fatalf("removeSessionsForProfile = %d, %v, want 2", n, err)
	}

	if keys, err := (&vault.SessionKeyring{Keyring: primary}).Keys(); err != nil || len(keys) != 0 {
		t.Errorf("primary keyring still contains sessions %v, err: %v", keys, err)
	}
	if keys, err := (&vault.SessionKeyring{Keyring: sessions}).Keys(); err != nil || len(keys) != 1 {
		t.Errorf("session keyring has sessions %v, err: %v, want only no-creds-profile", keys, err)
	}
}

func TestRemoveSessionsForProfileSharedKeyring(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	setTestSession(t, kr, "sso-profile")

	n, err := removeSessionsForProfile("sso-profile", kr, nil)
	if err != nil || n != 1 {
		t.Fatalf("removeSessionsForProfile = %d, %v, want 1", n, err)
	}
}
