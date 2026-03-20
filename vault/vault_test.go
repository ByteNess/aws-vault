package vault_test

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func TestWriteFileAtomic_NoPartialOnCrash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "token.json")

	// Seed with known-good content.
	if err := os.WriteFile(target, []byte(`{"ok":true}`), 0600); err != nil {
		t.Fatal(err)
	}

	// Write new content atomically.
	if err := vault.WriteFileAtomic(target, []byte(`{"ok":false,"new":true}`), 0600); err != nil {
		t.Fatal(err)
	}

	// No stray temp files left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(entries), entries)
	}

	// Perms are 0600.
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0600 {
		t.Errorf("perm = %o, want 0600", info.Mode().Perm())
	}
}

func TestUsageWebIdentityExample(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile role2]
role_arn = arn:aws:iam::33333333333:role/role2
web_identity_token_process = oidccli raw
`))
	defer os.Remove(f)
	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "role2"}
	config, err := configLoader.GetProfileConfig("role2")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	ckr := newSeededKeyring(t, "")
	p, err := vault.NewTempCredentialsProvider(config, ckr, true, true)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := p.(*vault.AssumeRoleWithWebIdentityProvider)
	if !ok {
		t.Fatalf("Expected AssumeRoleWithWebIdentityProvider, got %T", p)
	}
}

func TestIssue1176(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile my-shared-base-profile]
credential_process=aws-vault exec my-shared-base-profile -j
mfa_serial=arn:aws:iam::1234567890:mfa/danielholz
region=eu-west-1

[profile profile-with-role]
source_profile=my-shared-base-profile
include_profile=my-shared-base-profile
region=eu-west-1
role_arn=arn:aws:iam::12345678901:role/allow-view-only-access-from-other-accounts
`))
	defer os.Remove(f)
	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "my-shared-base-profile"}
	config, err := configLoader.GetProfileConfig("my-shared-base-profile")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	ckr := newSeededKeyring(t, "")
	p, err := vault.NewTempCredentialsProvider(config, ckr, true, true)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := p.(*vault.CredentialProcessProvider)
	if !ok {
		t.Fatalf("Expected CredentialProcessProvider, got %T", p)
	}
}

func TestIssue1195(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile test]
source_profile=dev
region=ap-northeast-2

[profile dev]
sso_session=common
sso_account_id=2160xxxx
sso_role_name=AdministratorAccess
region=ap-northeast-2
output=json

[default]
sso_session=common
sso_account_id=3701xxxx
sso_role_name=AdministratorAccess
region=ap-northeast-2
output=json

[sso-session common]
sso_start_url=https://xxxx.awsapps.com/start
sso_region=ap-northeast-2
sso_registration_scopes=sso:account:access
`))
	defer os.Remove(f)
	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "test"}
	config, err := configLoader.GetProfileConfig("test")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	ckr := newSeededKeyring(t, "")
	p, err := vault.NewTempCredentialsProvider(config, ckr, true, true)
	if err != nil {
		t.Fatal(err)
	}

	ssoProvider, ok := p.(*vault.SSORoleCredentialsProvider)
	if !ok {
		t.Fatalf("Expected SSORoleCredentialsProvider, got %T", p)
	}
	if ssoProvider.AccountID != "2160xxxx" {
		t.Fatalf("Expected AccountID to be 2160xxxx, got %s", ssoProvider.AccountID)
	}
}

// Ensures direct role login is not treated as chained MFA.
func TestDirectRoleLoginDoesNotUseGetSessionToken(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile target]
role_arn=arn:aws:iam::111111111111:role/target
mfa_serial=arn:aws:iam::111111111111:mfa/user
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "target"}
	config, err := configLoader.GetProfileConfig("target")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaToken = "123456"

	ckr := newSeededKeyring(t, "target")

	buf := captureLogs(t)

	_, err = vault.NewTempCredentialsProvider(config, ckr, false, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := buf.String()

	if strings.Contains(logs, "profile target: using GetSessionToken") {
		t.Fatalf("did not expect GetSessionToken for non-chained role profile, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "profile target: using AssumeRole") {
		t.Fatalf("expected AssumeRole with MFA, logs:\n%s", logs)
	}
}

// Ensures role->role chaining keeps MFA context by priming with GetSessionToken before chained AssumeRole calls.
func TestRoleChainingMfaUsesGetSessionTokenBeforeAssumeRole(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile source]
role_arn=arn:aws:iam::111111111111:role/source
mfa_serial=arn:aws:iam::111111111111:mfa/user

[profile target]
source_profile=source
role_arn=arn:aws:iam::222222222222:role/target
mfa_serial=arn:aws:iam::111111111111:mfa/user
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "target"}
	config, err := configLoader.GetProfileConfig("target")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaToken = "123456"
	config.SourceProfile.MfaToken = "123456"

	ckr := newSeededKeyring(t, "source")

	buf := captureLogs(t)

	_, err = vault.NewTempCredentialsProvider(config, ckr, false, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := buf.String()
	idxSession := strings.Index(logs, "profile source: using GetSessionToken")
	idxSourceAssume := strings.Index(logs, "profile source: using AssumeRole")
	idxTargetAssume := strings.Index(logs, "profile target: using AssumeRole")

	if idxSession == -1 || idxSourceAssume == -1 || idxTargetAssume == -1 {
		t.Fatalf("expected source GetSessionToken then source/target AssumeRole, logs:\n%s", logs)
	}
	if !(idxSession < idxSourceAssume && idxSourceAssume < idxTargetAssume) {
		t.Fatalf("unexpected flow order, logs:\n%s", logs)
	}
}

// Ensures flows that are not real role chaining do not go through the chained MFA path.
func TestNonRoleChainingFlowDoesNotUseChainedMfaPath(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile source]
role_arn=arn:aws:iam::111111111111:role/source
mfa_serial=arn:aws:iam::111111111111:mfa/user

[profile target]
source_profile=source
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "target"}
	config, err := configLoader.GetProfileConfig("target")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaPromptMethod = "terminal"
	config.SourceProfile.MfaToken = "123456"

	ckr := newSeededKeyring(t, "source")

	buf := captureLogs(t)

	_, err = vault.NewTempCredentialsProvider(config, ckr, false, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := buf.String()

	if strings.Contains(logs, "profile source: using GetSessionToken") {
		t.Fatalf("did not expect GetSessionToken for role source chained to non-role target, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "profile source: using AssumeRole") {
		t.Fatalf("expected source to AssumeRole with MFA, logs:\n%s", logs)
	}
}

// Ensures inherited default MFA only triggers GetSessionToken at the long-term source profile.
func TestDefaultMfaRoleChainDoesNotCallGetSessionTokenWithSessionCreds(t *testing.T) {
	f := newConfigFile(t, []byte(`
[default]
mfa_serial=arn:aws:iam::111111111111:mfa/user

[profile source]
region=eu-west-1
duration_seconds=7200

[profile admin]
role_arn=arn:aws:iam::222222222222:role/admin
source_profile=source
role_session_name=user
duration_seconds=7200

[profile target]
role_arn=arn:aws:iam::333333333333:role/target
role_session_name=user
source_profile=admin
duration_seconds=7200
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "target"}
	config, err := configLoader.GetProfileConfig("target")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaToken = "123456"
	config.SourceProfile.MfaToken = "123456"
	config.SourceProfile.SourceProfile.MfaToken = "123456"

	ckr := newSeededKeyring(t, "source")

	buf := captureLogs(t)

	_, err = vault.NewTempCredentialsProvider(config, ckr, false, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := buf.String()
	if !strings.Contains(logs, "profile source: using GetSessionToken") {
		t.Fatalf("expected source to use GetSessionToken, logs:\n%s", logs)
	}
	if strings.Contains(logs, "profile admin: using GetSessionToken") {
		t.Fatalf("did not expect admin to use GetSessionToken with session credentials, logs:\n%s", logs)
	}
	if strings.Contains(logs, "profile target: using GetSessionToken") {
		t.Fatalf("did not expect target to use GetSessionToken, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "profile admin: using AssumeRole (chained MFA)") {
		t.Fatalf("expected admin to use chained AssumeRole, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "profile target: using AssumeRole (chained MFA)") {
		t.Fatalf("expected target to use chained AssumeRole, logs:\n%s", logs)
	}
}

// Ensures the chained GetSessionToken keeps the requested duration while AssumeRole is capped.
func TestRoleChainingCapsAssumeRoleDurationToOneHour(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile source]
role_arn=arn:aws:iam::111111111111:role/source
mfa_serial=arn:aws:iam::111111111111:mfa/user

[profile target]
source_profile=source
role_arn=arn:aws:iam::222222222222:role/target
mfa_serial=arn:aws:iam::111111111111:mfa/user
`))
	defer os.Remove(f)

	base := vault.ProfileConfig{
		AssumeRoleDuration:             12 * time.Hour,
		ChainedGetSessionTokenDuration: 12 * time.Hour,
	}
	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := vault.NewConfigLoader(base, configFile, "target")
	config, err := configLoader.GetProfileConfig("target")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaToken = "123456"
	config.SourceProfile.MfaToken = "123456"

	ckr := newSeededKeyring(t, "source")

	buf := captureLogs(t)

	_, err = vault.NewTempCredentialsProvider(config, ckr, false, true)
	if err != nil {
		t.Fatal(err)
	}

	if config.SourceProfile.GetSessionTokenDuration() != base.ChainedGetSessionTokenDuration {
		t.Fatalf("expected source GetSessionToken duration to remain %s, got %s", base.ChainedGetSessionTokenDuration, config.SourceProfile.GetSessionTokenDuration())
	}
	if config.SourceProfile.AssumeRoleDuration != vault.RoleChainingMaximumDuration {
		t.Fatalf("expected source AssumeRole duration to be capped to %s, got %s", vault.RoleChainingMaximumDuration, config.SourceProfile.AssumeRoleDuration)
	}
	if config.AssumeRoleDuration != vault.RoleChainingMaximumDuration {
		t.Fatalf("expected target AssumeRole duration to be capped to %s, got %s", vault.RoleChainingMaximumDuration, config.AssumeRoleDuration)
	}

	logs := buf.String()
	if !strings.Contains(logs, "profile source: capping AssumeRole duration") {
		t.Fatalf("expected source AssumeRole capping log, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "profile target: capping AssumeRole duration") {
		t.Fatalf("expected target AssumeRole capping log, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "using AssumeRole") {
		t.Fatalf("expected chained AssumeRole flow after duration cap, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "using GetSessionToken") {
		t.Fatalf("expected source GetSessionToken flow after duration cap, logs:\n%s", logs)
	}
}

// newSeededKeyring returns a CredentialKeyring with a single set of stub
// credentials stored under the given profile name. Pass an empty name to get
// an empty keyring.
func newSeededKeyring(t *testing.T, profileName string) *vault.CredentialKeyring {
	t.Helper()

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	if profileName == "" {
		return ckr
	}
	if err := ckr.Set(profileName, aws.Credentials{AccessKeyID: "id", SecretAccessKey: "secret"}); err != nil {
		t.Fatal(err)
	}
	return ckr
}

// captureLogs redirects the standard log package output into a buffer for the
// duration of the test, restoring the previous writer, flags and prefix when
// the test ends. Returns the buffer the caller can read with buf.String().
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()

	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")

	t.Cleanup(func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	})

	return &buf
}
func TestTempCredentialsProviderParallelSafeGetSessionToken(t *testing.T) {
	config := &vault.ProfileConfig{
		ProfileName: "creds",
		Region:      "us-east-1",
		MfaToken:    "123456", // provide token to avoid interactive prompt
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{
		{Key: "creds", Data: []byte(`{"AccessKeyID":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"secret"}`)},
	})}
	provider, err := vault.NewTempCredentialsProviderWithOptions(
		config,
		ckr,
		false,
		false,
		vault.TempCredentialsOptions{ParallelSafe: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	cached, ok := provider.(*vault.CachedSessionProvider)
	if !ok {
		t.Fatalf("Expected CachedSessionProvider, got %T", provider)
	}
	if !cached.UseSessionLock {
		t.Fatalf("Expected UseSessionLock to be true")
	}
	_, ok = cached.SessionProvider.(*vault.SessionTokenProvider)
	if !ok {
		t.Fatalf("Expected SessionTokenProvider, got %T", cached.SessionProvider)
	}
}

func TestTempCredentialsProviderParallelSafeAssumeRole(t *testing.T) {
	config := &vault.ProfileConfig{
		ProfileName:       "role",
		Region:            "us-east-1",
		RoleARN:           "arn:aws:iam::222222222222:role/role",
		MfaSerial:         "arn:aws:iam::111111111111:mfa/user",
		MfaToken:          "123456", // provide token to avoid interactive prompt
		SourceProfileName: "source",
		SourceProfile: &vault.ProfileConfig{
			ProfileName: "source",
			Region:      "us-east-1",
		},
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{
		{Key: "source", Data: []byte(`{"AccessKeyID":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"secret"}`)},
	})}
	provider, err := vault.NewTempCredentialsProviderWithOptions(
		config,
		ckr,
		true, // disableSessions: skip GetSessionToken so AssumeRole gets the MFA
		false,
		vault.TempCredentialsOptions{ParallelSafe: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	cached, ok := provider.(*vault.CachedSessionProvider)
	if !ok {
		t.Fatalf("Expected CachedSessionProvider, got %T", provider)
	}
	if !cached.UseSessionLock {
		t.Fatalf("Expected UseSessionLock to be true")
	}
	_, ok = cached.SessionProvider.(*vault.AssumeRoleProvider)
	if !ok {
		t.Fatalf("Expected AssumeRoleProvider, got %T", cached.SessionProvider)
	}
}

func TestTempCredentialsProviderParallelSafeSSOLocks(t *testing.T) {
	config := &vault.ProfileConfig{
		ProfileName:  "sso-profile",
		SSOStartURL:  "https://sso.example/start",
		SSORegion:    "us-east-1",
		SSOAccountID: "123456789012",
		SSORoleName:  "Role",
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	provider, err := vault.NewTempCredentialsProviderWithOptions(
		config,
		ckr,
		false,
		false,
		vault.TempCredentialsOptions{ParallelSafe: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	cached, ok := provider.(*vault.CachedSessionProvider)
	if !ok {
		t.Fatalf("Expected CachedSessionProvider, got %T", provider)
	}
	if !cached.UseSessionLock {
		t.Fatalf("Expected UseSessionLock to be true")
	}
	ssoProvider, ok := cached.SessionProvider.(*vault.SSORoleCredentialsProvider)
	if !ok {
		t.Fatalf("Expected SSORoleCredentialsProvider, got %T", cached.SessionProvider)
	}
	if !ssoProvider.UseSSOTokenLock {
		t.Fatalf("Expected UseSSOTokenLock to be true")
	}
}
