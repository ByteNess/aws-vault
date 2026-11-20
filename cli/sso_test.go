package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

const ssoExportTestConfig = `[profile sso-profile]
sso_start_url=https://sso.example/start
sso_region=eu-west-1
sso_account_id=123456789012
sso_role_name=Administrator

[profile plain]
region=eu-west-1
`

// ssoExportFixture returns the parsed test config and a keyring holding a
// valid cached token for sso-profile.
func ssoExportFixture(t *testing.T) (*vault.ConfigFile, keyring.Keyring) {
	t.Helper()
	configFile, removeConfig := exampleConfigFile(ssoExportTestConfig)
	t.Cleanup(removeConfig)
	f, err := vault.LoadConfig(configFile)
	if err != nil {
		t.Fatal(err)
	}

	kr := keyring.NewArrayKeyring(nil)
	err = (vault.OIDCTokenKeyring{Keyring: kr}).Set("https://sso.example/start", &vault.OIDCTokenData{
		Token: ssooidc.CreateTokenOutput{
			AccessToken:  aws.String("the-access-token"),
			RefreshToken: aws.String("the-refresh-token"),
			ExpiresIn:    3600,
		},
		ClientID:     "the-client-id",
		ClientSecret: "the-client-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, kr
}

func TestSSOExportCommand_Plain(t *testing.T) {
	f, kr := ssoExportFixture(t)

	var out bytes.Buffer
	err := ssoExportCommand(ssoExportCommandInput{ProfileName: "sso-profile", Format: formatTypeSSOPlain}, f, kr, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "the-access-token\n" {
		t.Errorf("output = %q, want the access token on one line", out.String())
	}
}

func TestSSOExportCommand_JSON(t *testing.T) {
	f, kr := ssoExportFixture(t)

	var out bytes.Buffer
	err := ssoExportCommand(ssoExportCommandInput{ProfileName: "sso-profile", Format: formatTypeSSOJSON}, f, kr, &out)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if got["accessToken"] != "the-access-token" {
		t.Errorf("accessToken = %q", got["accessToken"])
	}
	expiresAt, err := time.Parse(time.RFC3339, got["expiresAt"])
	if err != nil {
		t.Fatalf("expiresAt = %q: %v", got["expiresAt"], err)
	}
	if left := time.Until(expiresAt); left < 59*time.Minute || left > time.Hour {
		t.Errorf("expiresAt is %s away, want about 1h", left)
	}
	if len(got) != 2 {
		t.Errorf("output has fields beyond accessToken and expiresAt: %s", out.String())
	}
	for _, secret := range []string{"the-refresh-token", "the-client-secret", "the-client-id"} {
		if strings.Contains(out.String(), secret) {
			t.Errorf("output leaks %s", secret)
		}
	}
}

func TestSSOExportCommand_ProfileWithoutSSO(t *testing.T) {
	f, kr := ssoExportFixture(t)

	var out bytes.Buffer
	err := ssoExportCommand(ssoExportCommandInput{ProfileName: "plain", Format: formatTypeSSOPlain}, f, kr, &out)
	if err == nil || !strings.Contains(err.Error(), "not configured for SSO") {
		t.Errorf("err = %v, want a not configured for SSO error", err)
	}
	if out.Len() != 0 {
		t.Errorf("unexpected output %q", out.String())
	}
}

func TestSSOExportCommand_UnknownProfile(t *testing.T) {
	f, kr := ssoExportFixture(t)

	err := ssoExportCommand(ssoExportCommandInput{ProfileName: "missing", Format: formatTypeSSOPlain}, f, kr, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %v, want a profile not found error", err)
	}
}

// The token is useful to an AWS CLI call made from inside `aws-vault exec`,
// so unlike `export` the command runs in an aws-vault subshell.
func TestSSOExportCommand_RunsInSubshell(t *testing.T) {
	f, kr := ssoExportFixture(t)
	t.Setenv("AWS_VAULT", "sso-profile")

	var out bytes.Buffer
	if err := ssoExportCommand(ssoExportCommandInput{ProfileName: "sso-profile", Format: formatTypeSSOPlain}, f, kr, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "the-access-token\n" {
		t.Errorf("output = %q", out.String())
	}
}
