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

// ssoListAccountsFixture serves accountList from a fake SSO portal and
// returns a config whose sso-profile points at it, with a valid cached token.
func ssoListAccountsFixture(t *testing.T, accountList string) (*vault.ConfigFile, keyring.Keyring) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/assignment/accounts" || r.Header.Get("X-Amz-Sso_bearer_token") != "the-access-token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, `{"accountList":[%s]}`, accountList)
	}))
	t.Cleanup(srv.Close)

	configFile, removeConfig := exampleConfigFile(fmt.Sprintf(`[profile sso-profile]
sso_start_url=https://sso.example/start
sso_region=eu-west-1
sso_account_id=123456789012
sso_role_name=Administrator
endpoint_url=%s

[profile plain]
region=eu-west-1
`, srv.URL))
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

const twoAccounts = `{"accountId":"111111111111","accountName":"dev","emailAddress":"dev@example.com"},` +
	`{"accountId":"222222222222","accountName":"production","emailAddress":"prod@example.com"}`

func TestSSOListAccountsCommand_Text(t *testing.T) {
	f, kr := ssoListAccountsFixture(t, twoAccounts)

	var out bytes.Buffer
	err := ssoListAccountsCommand(ssoListAccountsCommandInput{
		ssoCommandInput: ssoCommandInput{ProfileName: "sso-profile"},
		Format:          formatTypeSSOText,
	}, f, kr, &out)
	if err != nil {
		t.Fatal(err)
	}
	want := "Account ID    Account Name  Email\n" +
		"==========    ============  =====\n" +
		"111111111111  dev           dev@example.com\n" +
		"222222222222  production    prod@example.com\n"
	if out.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestSSOListAccountsCommand_JSON(t *testing.T) {
	f, kr := ssoListAccountsFixture(t, twoAccounts)

	var out bytes.Buffer
	err := ssoListAccountsCommand(ssoListAccountsCommandInput{
		ssoCommandInput: ssoCommandInput{ProfileName: "sso-profile"},
		Format:          formatTypeSSOJSON,
	}, f, kr, &out)
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		AccountList []map[string]string `json:"accountList"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if len(got.AccountList) != 2 {
		t.Fatalf("accountList = %v, want 2 accounts", got.AccountList)
	}
	first := got.AccountList[0]
	if first["accountId"] != "111111111111" || first["accountName"] != "dev" || first["emailAddress"] != "dev@example.com" {
		t.Errorf("first account = %v", first)
	}
	if strings.Contains(out.String(), "the-access-token") {
		t.Error("output leaks the access token")
	}
}

func TestSSOListAccountsCommand_JSONWithNoAccounts(t *testing.T) {
	f, kr := ssoListAccountsFixture(t, "")

	var out bytes.Buffer
	err := ssoListAccountsCommand(ssoListAccountsCommandInput{
		ssoCommandInput: ssoCommandInput{ProfileName: "sso-profile"},
		Format:          formatTypeSSOJSON,
	}, f, kr, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"accountList": []`) {
		t.Errorf("output = %s, want an empty accountList array", out.String())
	}
}

func TestSSOListAccountsCommand_ProfileWithoutSSO(t *testing.T) {
	f, kr := ssoListAccountsFixture(t, twoAccounts)

	err := ssoListAccountsCommand(ssoListAccountsCommandInput{
		ssoCommandInput: ssoCommandInput{ProfileName: "plain"},
		Format:          formatTypeSSOText,
	}, f, kr, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "not configured for SSO") {
		t.Errorf("err = %v, want a not configured for SSO error", err)
	}
}
