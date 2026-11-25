package cli

import (
	"bytes"
	"encoding/json"
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

// ssoListAccountRolesFixture serves two roles for whichever account is asked
// for from a fake SSO portal, and returns a config whose SSO profiles point at
// it, with a valid cached token.
func ssoListAccountRolesFixture(t *testing.T) (*vault.ConfigFile, keyring.Keyring) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		accountID := r.URL.Query().Get("account_id")
		if r.URL.Path != "/assignment/roles" || accountID == "" || r.Header.Get("X-Amz-Sso_bearer_token") != "the-access-token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, `{"roleList":[{"accountId":%q,"roleName":"Administrator"},{"accountId":%q,"roleName":"ReadOnly"}]}`, accountID, accountID)
	}))
	t.Cleanup(srv.Close)

	configFile, removeConfig := exampleConfigFile(fmt.Sprintf(`[profile sso-profile]
sso_start_url=https://sso.example/start
sso_region=eu-west-1
sso_account_id=123456789012
sso_role_name=Administrator
endpoint_url=%s

[profile sso-no-account]
sso_start_url=https://sso.example/start
sso_region=eu-west-1
endpoint_url=%s
`, srv.URL, srv.URL))
	t.Cleanup(removeConfig)
	f, err := vault.LoadConfig(configFile)
	if err != nil {
		t.Fatal(err)
	}

	kr := keyring.NewArrayKeyring(nil)
	err = (vault.OIDCTokenKeyring{Keyring: kr}).Set("https://sso.example/start", &vault.OIDCTokenData{
		Token: ssooidc.CreateTokenOutput{AccessToken: aws.String("the-access-token"), ExpiresIn: 3600},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, kr
}

func TestSSOListAccountRolesCommand_DefaultsToTheProfileAccount(t *testing.T) {
	f, kr := ssoListAccountRolesFixture(t)

	var out bytes.Buffer
	err := ssoListAccountRolesCommand(ssoListAccountRolesCommandInput{
		ssoCommandInput: ssoCommandInput{ProfileName: "sso-profile"},
		Format:          formatTypeSSOText,
	}, f, kr, &out)
	if err != nil {
		t.Fatal(err)
	}
	want := "Account ID    Role Name\n" +
		"==========    =========\n" +
		"123456789012  Administrator\n" +
		"123456789012  ReadOnly\n"
	if out.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestSSOListAccountRolesCommand_AccountIDFlagWins(t *testing.T) {
	f, kr := ssoListAccountRolesFixture(t)

	var out bytes.Buffer
	err := ssoListAccountRolesCommand(ssoListAccountRolesCommandInput{
		ssoCommandInput: ssoCommandInput{ProfileName: "sso-profile"},
		AccountID:       "999999999999",
		Format:          formatTypeSSOText,
	}, f, kr, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "999999999999  Administrator\n") || strings.Contains(out.String(), "123456789012") {
		t.Errorf("output lists the wrong account:\n%s", out.String())
	}
}

func TestSSOListAccountRolesCommand_JSON(t *testing.T) {
	f, kr := ssoListAccountRolesFixture(t)

	var out bytes.Buffer
	err := ssoListAccountRolesCommand(ssoListAccountRolesCommandInput{
		ssoCommandInput: ssoCommandInput{ProfileName: "sso-no-account"},
		AccountID:       "999999999999",
		Format:          formatTypeSSOJSON,
	}, f, kr, &out)
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		RoleList []map[string]string `json:"roleList"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if len(got.RoleList) != 2 {
		t.Fatalf("roleList = %v, want 2 roles", got.RoleList)
	}
	if got.RoleList[0]["roleName"] != "Administrator" || got.RoleList[0]["accountId"] != "999999999999" {
		t.Errorf("first role = %v", got.RoleList[0])
	}
}

func TestSSOListAccountRolesCommand_NeedsAnAccount(t *testing.T) {
	f, kr := ssoListAccountRolesFixture(t)

	var out bytes.Buffer
	err := ssoListAccountRolesCommand(ssoListAccountRolesCommandInput{
		ssoCommandInput: ssoCommandInput{ProfileName: "sso-no-account"},
		Format:          formatTypeSSOText,
	}, f, kr, &out)
	if err == nil || !strings.Contains(err.Error(), "--account-id") {
		t.Errorf("err = %v, want an error naming --account-id", err)
	}
	if out.Len() != 0 {
		t.Errorf("unexpected output %q", out.String())
	}
}
