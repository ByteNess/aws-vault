package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func TestRotateCommandOnlyUsesOldCredentials(t *testing.T) {
	responses := map[string]string{
		"GetSessionToken": `<GetSessionTokenResponse><GetSessionTokenResult><Credentials><AccessKeyId>ASIASESSION</AccessKeyId><SecretAccessKey>session/secret+</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials></GetSessionTokenResult></GetSessionTokenResponse>`,
		"CreateAccessKey": `<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIANEW</AccessKeyId><SecretAccessKey>new/secret+</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`,
		"DeleteAccessKey": `<DeleteAccessKeyResponse></DeleteAccessKeyResponse>`,
	}
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, credential, _ := strings.Cut(r.Header.Get("Authorization"), "Credential=")
		accessKeyID, _, _ := strings.Cut(credential, "/")
		requests = append(requests, r.Form.Get("Action")+" "+accessKeyID)
		_, _ = io.WriteString(w, responses[r.Form.Get("Action")])
	}))
	defer srv.Close()

	configFile := writeTempConfig(t, []byte("[profile a]\nregion = us-east-1\nendpoint_url = "+srv.URL+"\n"))
	kr := keyring.NewArrayKeyring(nil)
	ckr := &vault.CredentialKeyring{Keyring: kr}
	if err := ckr.Set("a", aws.Credentials{AccessKeyID: "AKIAOLD", SecretAccessKey: "old/secret+"}); err != nil {
		t.Fatal(err)
	}

	input := rotateCommandInput{ProfileName: "a", Config: vault.ProfileConfig{MfaPromptMethod: "terminal"}}
	if err := rotateCommand(input, configFile, kr); err != nil {
		t.Fatal(err)
	}

	want := []string{"GetSessionToken AKIAOLD", "CreateAccessKey ASIASESSION", "DeleteAccessKey ASIASESSION"}
	if !slices.Equal(requests, want) {
		t.Fatalf("requests = %v, want %v", requests, want)
	}
	creds, err := ckr.Get("a")
	if err != nil || creds.AccessKeyID != "AKIANEW" {
		t.Fatalf("stored credentials = %v, %v, want AKIANEW", creds.AccessKeyID, err)
	}
}
