package cli

import (
	"os"
	"strings"
	"testing"

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
	f, err := os.CreateTemp(t.TempDir(), "aws-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.Name(), b, 0600); err != nil {
		t.Fatal(err)
	}
	configFile, err := vault.LoadConfig(f.Name())
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

// TestExecCommandRejectsMissingProfile is the regression test for issue #377:
// exec must error on a non-existent profile rather than silently inheriting
// [default]. The guard fires before any config load or execve, so calling
// ExecCommand directly is safe on every platform.
func TestExecCommandRejectsMissingProfile(t *testing.T) {
	t.Setenv("AWS_VAULT", "") // ensure we are not treated as an existing subshell
	configFile := writeTempConfig(t, issue377Config)
	kr := keyring.NewArrayKeyring([]keyring.Item{})

	_, err := ExecCommand(ExecCommandInput{ProfileName: "invalid-profile", NoSession: true}, configFile, kr)
	if err == nil {
		t.Fatal("ExecCommand accepted a non-existent profile; expected an error (issue #377)")
	}
	if !strings.Contains(err.Error(), "invalid-profile") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestExportCommandRejectsMissingProfile covers the same guard on export, which
// also closes the `exec --json` path (it delegates to ExportCommand).
func TestExportCommandRejectsMissingProfile(t *testing.T) {
	t.Setenv("AWS_VAULT", "")
	configFile := writeTempConfig(t, issue377Config)
	kr := keyring.NewArrayKeyring([]keyring.Item{})

	err := ExportCommand(ExportCommandInput{ProfileName: "invalid-profile", Format: FormatTypeEnv, NoSession: true}, configFile, kr)
	if err == nil {
		t.Fatal("ExportCommand accepted a non-existent profile; expected an error (issue #377)")
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

	err := RotateCommand(RotateCommandInput{ProfileName: "invalid-profile", NoSession: true}, configFile, kr)
	if err == nil {
		t.Fatal("RotateCommand accepted a non-existent profile; expected an error (issue #377)")
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
