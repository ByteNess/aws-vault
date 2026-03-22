package vault_test

import (
	"os"
	"testing"
	"bytes"
	"log"
	"strings"
	"time"

	"github.com/byteness/keyring"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/aws/aws-sdk-go-v2/aws"
)

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

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
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

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
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

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
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

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	err = ckr.Set("target", aws.Credentials{AccessKeyID: "id", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	}()

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

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	err = ckr.Set("source", aws.Credentials{AccessKeyID: "id", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	}()

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

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	err = ckr.Set("source", aws.Credentials{AccessKeyID: "id", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	}()

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

// Ensures chained AssumeRole duration is capped to 1 hour when a higher duration is requested.
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

	base := vault.ProfileConfig{AssumeRoleDuration: 12 * time.Hour}
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

	ckr := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{})}
	err = ckr.Set("source", aws.Credentials{AccessKeyID: "id", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	}()

	_, err = vault.NewTempCredentialsProvider(config, ckr, false, true)
	if err != nil {
		t.Fatal(err)
	}

	if config.SourceProfile.AssumeRoleDuration != time.Hour {
		t.Fatalf("expected source AssumeRole duration to be capped to 1h, got %s", config.SourceProfile.AssumeRoleDuration)
	}
	if config.AssumeRoleDuration != time.Hour {
		t.Fatalf("expected target AssumeRole duration to be capped to 1h, got %s", config.AssumeRoleDuration)
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
