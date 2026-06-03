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

	// Perms are 0600 on Unix. Windows has no Unix permission bits, so the
	// expected mode is provided per-platform by wantTokenPerm (see
	// perm_unix_test.go / perm_windows_test.go).
	info, _ := os.Stat(target)
	if got := info.Mode().Perm(); got != wantTokenPerm() {
		t.Errorf("perm = %o, want %o", got, wantTokenPerm())
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

// A leaf role (nothing chains off it) sourced from long-term IAM-user
// credentials and requesting more than the role-chaining maximum must be
// assumed directly with MFA (no GetSessionToken), so AWS honours the full
// requested duration instead of capping it to 1h.
func TestLeafRoleAboveOneHourIsAssumedDirectly(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile mgmt]
mfa_serial=arn:aws:iam::111111111111:mfa/user

[profile role]
source_profile=mgmt
mfa_serial=arn:aws:iam::111111111111:mfa/user
role_arn=arn:aws:iam::111111111111:role/admin
duration_seconds=43200
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
	configLoader := vault.NewConfigLoader(base, configFile, "role")
	config, err := configLoader.GetProfileConfig("role")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	config.MfaToken = "123456"
	if config.SourceProfile != nil {
		config.SourceProfile.MfaToken = "123456"
	}

	buf := captureLogs(t)
	if _, err = vault.NewTempCredentialsProvider(config, newSeededKeyring(t, "mgmt"), false, true); err != nil {
		t.Fatal(err)
	}

	if config.AssumeRoleDuration != 12*time.Hour {
		t.Fatalf("expected role AssumeRole duration to remain 12h0m0s, got %s", config.AssumeRoleDuration)
	}

	logs := buf.String()
	if strings.Contains(logs, "capping AssumeRole duration") {
		t.Fatalf("did not expect duration capping for a directly-assumed leaf role, logs:\n%s", logs)
	}
	if strings.Contains(logs, "using GetSessionToken") {
		t.Fatalf("expected GetSessionToken to be skipped so the role is assumed directly, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "profile role: using AssumeRole (with MFA)") {
		t.Fatalf("expected a direct AssumeRole with MFA, logs:\n%s", logs)
	}
}

// A role that sources from another role is genuine role chaining: AWS caps it
// to 1h regardless, so it must stay on the GetSessionToken path (one cached,
// MFA-backed session token shared across the chain) and be capped to 1h. This
// guards against the direct-assume path leaking into chains (which would lose
// the shared MFA session and push MFA onto a role-signed AssumeRole).
func TestChainedRoleAboveOneHourStillUsesGetSessionToken(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile mgmt]
mfa_serial=arn:aws:iam::111111111111:mfa/user

[profile mid]
source_profile=mgmt
mfa_serial=arn:aws:iam::111111111111:mfa/user
role_arn=arn:aws:iam::111111111111:role/mid
duration_seconds=43200

[profile leaf]
source_profile=mid
role_arn=arn:aws:iam::222222222222:role/leaf
duration_seconds=43200
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
	configLoader := vault.NewConfigLoader(base, configFile, "leaf")
	config, err := configLoader.GetProfileConfig("leaf")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	for c := config; c != nil; c = c.SourceProfile {
		c.MfaToken = "123456"
	}

	buf := captureLogs(t)
	if _, err = vault.NewTempCredentialsProvider(config, newSeededKeyring(t, "mgmt"), false, true); err != nil {
		t.Fatal(err)
	}

	if config.AssumeRoleDuration != vault.RoleChainingMaximumDuration {
		t.Fatalf("expected chained leaf AssumeRole duration capped to %s, got %s", vault.RoleChainingMaximumDuration, config.AssumeRoleDuration)
	}

	logs := buf.String()
	if !strings.Contains(logs, "profile mgmt: using GetSessionToken") {
		t.Fatalf("expected base profile to consolidate MFA via GetSessionToken, logs:\n%s", logs)
	}
	if !strings.Contains(logs, "profile leaf: capping AssumeRole duration") {
		t.Fatalf("expected chained leaf to be capped to 1h, logs:\n%s", logs)
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
