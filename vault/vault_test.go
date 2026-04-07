package vault_test

import (
	"os"
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
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
