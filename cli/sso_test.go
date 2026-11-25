package cli

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// ssoSessionFixture returns a config with an [sso-session] section and no
// profile using it, a keyring holding a valid token for the session, and the
// URL of a fake SSO portal that lists one account and one role.
func ssoSessionFixture(t *testing.T) (f *vault.ConfigFile, kr keyring.Keyring, portalURL string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Amz-Sso_bearer_token") != "the-session-token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/assignment/accounts":
			_, _ = fmt.Fprint(w, `{"accountList":[{"accountId":"111111111111","accountName":"dev","emailAddress":"dev@example.com"}]}`)
		case "/assignment/roles":
			_, _ = fmt.Fprintf(w, `{"roleList":[{"accountId":%q,"roleName":"Administrator"}]}`, r.URL.Query().Get("account_id"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	configFile, removeConfig := exampleConfigFile(`[sso-session my-sso]
sso_start_url=https://session.example/start
sso_region=eu-west-1
sso_registration_scopes=sso:account:access

[profile plain]
region=eu-west-1
`)
	t.Cleanup(removeConfig)
	f, err := vault.LoadConfig(configFile)
	if err != nil {
		t.Fatal(err)
	}

	kr = keyring.NewArrayKeyring(nil)
	err = (vault.OIDCTokenKeyring{Keyring: kr}).Set("https://session.example/start", &vault.OIDCTokenData{
		Token: ssooidc.CreateTokenOutput{AccessToken: aws.String("the-session-token"), ExpiresIn: 3600},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, kr, srv.URL
}

func TestSSOProvider_FromSSOSession(t *testing.T) {
	f, kr, _ := ssoSessionFixture(t)

	p, err := ssoProvider(ssoCommandInput{SSOSession: "my-sso", Config: vault.ProfileConfig{SSOUseDeviceCode: true}}, f, kr)
	if err != nil {
		t.Fatal(err)
	}
	if p.StartURL != "https://session.example/start" || len(p.RegistrationScopes) != 1 || !p.UseDeviceCode {
		t.Errorf("provider not built from the sso-session section and flags: %+v", p)
	}
	if p.AccountID != "" || p.RoleName != "" {
		t.Errorf("a session has no account or role, got %q %q", p.AccountID, p.RoleName)
	}
}

func TestSSOProvider_SSOSessionErrors(t *testing.T) {
	f, kr, _ := ssoSessionFixture(t)

	_, err := ssoProvider(ssoCommandInput{SSOSession: "missing"}, f, kr)
	if err == nil || !strings.Contains(err.Error(), "sso-session 'missing' not found") {
		t.Errorf("unknown session: err = %v", err)
	}

	_, err = ssoProvider(ssoCommandInput{SSOSession: "my-sso", ProfileName: "plain"}, f, kr)
	if err == nil || !strings.Contains(err.Error(), "--sso-session") || !strings.Contains(err.Error(), "profile") {
		t.Errorf("session and profile together: err = %v, want an error naming both", err)
	}
}

func TestSSOExportCommand_SSOSession(t *testing.T) {
	f, kr, _ := ssoSessionFixture(t)

	var out bytes.Buffer
	err := ssoExportCommand(ssoExportCommandInput{
		ssoCommandInput: ssoCommandInput{SSOSession: "my-sso"},
		Format:          formatTypeSSOPlain,
	}, f, kr, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "the-session-token\n" {
		t.Errorf("output = %q, want the token of the session", out.String())
	}
}

func TestSSOListAccountsCommand_SSOSession(t *testing.T) {
	f, kr, portalURL := ssoSessionFixture(t)

	var out bytes.Buffer
	err := ssoListAccountsCommand(ssoListAccountsCommandInput{
		ssoCommandInput: ssoCommandInput{SSOSession: "my-sso", Config: vault.ProfileConfig{EndpointURL: portalURL}},
		Format:          formatTypeSSOText,
	}, f, kr, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "111111111111  dev") {
		t.Errorf("output:\n%s\nwant the account of the session", out.String())
	}
}

func TestSSOListAccountRolesCommand_SSOSession(t *testing.T) {
	f, kr, portalURL := ssoSessionFixture(t)
	input := ssoListAccountRolesCommandInput{
		ssoCommandInput: ssoCommandInput{SSOSession: "my-sso", Config: vault.ProfileConfig{EndpointURL: portalURL}},
		Format:          formatTypeSSOText,
	}

	err := ssoListAccountRolesCommand(input, f, kr, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--account-id") || strings.Contains(err.Error(), "profile") {
		t.Errorf("without an account: err = %v, want an error naming --account-id and no profile", err)
	}

	input.AccountID = "222222222222"
	var out bytes.Buffer
	if err := ssoListAccountRolesCommand(input, f, kr, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "222222222222  Administrator") {
		t.Errorf("output:\n%s\nwant the role of the account", out.String())
	}
}
