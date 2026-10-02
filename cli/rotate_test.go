package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

const invalidClientTokenIDResponse = `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error><RequestId>1</RequestId></ErrorResponse>`

// rotateTestServer records requests as "Action SigningKeyID [-> TargetKeyID]" and rejects the first
// newKeyRejections requests signed with the new key
func rotateTestServer(t *testing.T, newKeyRejections int) (*httptest.Server, *[]string) {
	t.Helper()
	responses := map[string]string{
		"GetSessionToken":   `<GetSessionTokenResponse><GetSessionTokenResult><Credentials><AccessKeyId>ASIASESSION</AccessKeyId><SecretAccessKey>session/secret+</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials></GetSessionTokenResult></GetSessionTokenResponse>`,
		"CreateAccessKey":   `<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIANEW</AccessKeyId><SecretAccessKey>new/secret+</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`,
		"GetCallerIdentity": `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::111111111111:user/a</Arn><UserId>AIDA</UserId><Account>111111111111</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`,
		"DeleteAccessKey":   `<DeleteAccessKeyResponse></DeleteAccessKeyResponse>`,
	}
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, credential, _ := strings.Cut(r.Header.Get("Authorization"), "Credential=")
		accessKeyID, _, _ := strings.Cut(credential, "/")
		request := r.Form.Get("Action") + " " + accessKeyID
		if target := r.Form.Get("AccessKeyId"); target != "" {
			request += " -> " + target
		}
		requests = append(requests, request)
		if accessKeyID == "AKIANEW" && newKeyRejections > 0 {
			newKeyRejections--
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, invalidClientTokenIDResponse)
			return
		}
		_, _ = io.WriteString(w, responses[r.Form.Get("Action")])
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func shortenAccessKeyWait(t *testing.T) {
	t.Helper()
	timeout, interval := accessKeyWaitTimeout, accessKeyWaitInterval
	accessKeyWaitTimeout, accessKeyWaitInterval = 100*time.Millisecond, time.Millisecond
	t.Cleanup(func() { accessKeyWaitTimeout, accessKeyWaitInterval = timeout, interval })
}

func runRotate(t *testing.T, srv *httptest.Server) (*vault.CredentialKeyring, error) {
	t.Helper()
	shortenAccessKeyWait(t)

	configFile := writeTempConfig(t, []byte("[profile a]\nregion = us-east-1\nendpoint_url = "+srv.URL+"\n"))
	kr := keyring.NewArrayKeyring(nil)
	ckr := &vault.CredentialKeyring{Keyring: kr}
	if err := ckr.Set("a", aws.Credentials{AccessKeyID: "AKIAOLD", SecretAccessKey: "old/secret+"}); err != nil {
		t.Fatal(err)
	}

	input := rotateCommandInput{ProfileName: "a", Config: vault.ProfileConfig{MfaPromptMethod: "terminal"}}
	return ckr, rotateCommand(input, configFile, kr)
}

func assertStoredKey(t *testing.T, ckr *vault.CredentialKeyring, want string) {
	t.Helper()
	creds, err := ckr.Get("a")
	if err != nil || creds.AccessKeyID != want {
		t.Fatalf("stored credentials = %v, %v, want %s", creds.AccessKeyID, err, want)
	}
}

func TestRotateCommandOnlyUsesOldCredentials(t *testing.T) {
	srv, requests := rotateTestServer(t, 0)
	ckr, err := runRotate(t, srv)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"GetSessionToken AKIAOLD", "CreateAccessKey ASIASESSION", "GetCallerIdentity AKIANEW", "DeleteAccessKey ASIASESSION -> AKIAOLD"}
	if !slices.Equal(*requests, want) {
		t.Fatalf("requests = %v, want %v", *requests, want)
	}
	assertStoredKey(t, ckr, "AKIANEW")
}

func TestRotateCommandWaitsForNewAccessKey(t *testing.T) {
	srv, requests := rotateTestServer(t, 2)
	ckr, err := runRotate(t, srv)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"GetSessionToken AKIAOLD", "CreateAccessKey ASIASESSION", "GetCallerIdentity AKIANEW", "GetCallerIdentity AKIANEW", "GetCallerIdentity AKIANEW", "DeleteAccessKey ASIASESSION -> AKIAOLD"}
	if !slices.Equal(*requests, want) {
		t.Fatalf("requests = %v, want %v", *requests, want)
	}
	assertStoredKey(t, ckr, "AKIANEW")
}

func TestRotateCommandKeepsOldAccessKeyWhenNewOneNeverWorks(t *testing.T) {
	srv, requests := rotateTestServer(t, 1<<30)
	ckr, err := runRotate(t, srv)
	if err == nil || !strings.Contains(err.Error(), "never became usable") {
		t.Fatalf("err = %v, want a 'never became usable' error", err)
	}

	var deletes []string
	for _, r := range *requests {
		if strings.HasPrefix(r, "DeleteAccessKey") {
			deletes = append(deletes, r)
		}
	}
	if want := []string{"DeleteAccessKey ASIASESSION -> AKIANEW"}; !slices.Equal(deletes, want) {
		t.Fatalf("deletes = %v, want %v", deletes, want)
	}
	assertStoredKey(t, ckr, "AKIAOLD")
}

func TestRotateCommandNoSessionUsesSourceProfileCredentials(t *testing.T) {
	srv, requests := rotateTestServer(t, 0)
	shortenAccessKeyWait(t)

	configFile := writeTempConfig(t, []byte("[profile base]\nregion = us-east-1\nendpoint_url = "+srv.URL+"\n\n[profile a]\nsource_profile = base\nregion = us-east-1\nendpoint_url = "+srv.URL+"\n"))
	kr := keyring.NewArrayKeyring(nil)
	ckr := &vault.CredentialKeyring{Keyring: kr}
	if err := ckr.Set("base", aws.Credentials{AccessKeyID: "AKIAOLD", SecretAccessKey: "old/secret+"}); err != nil {
		t.Fatal(err)
	}

	input := rotateCommandInput{NoSession: true, ProfileName: "a", Config: vault.ProfileConfig{MfaPromptMethod: "terminal"}}
	if err := rotateCommand(input, configFile, kr); err != nil {
		t.Fatal(err)
	}

	want := []string{"CreateAccessKey AKIAOLD", "GetCallerIdentity AKIANEW", "DeleteAccessKey AKIAOLD -> AKIAOLD"}
	if !slices.Equal(*requests, want) {
		t.Fatalf("requests = %v, want %v", *requests, want)
	}
	creds, err := ckr.Get("base")
	if err != nil || creds.AccessKeyID != "AKIANEW" {
		t.Fatalf("stored credentials = %v, %v, want AKIANEW", creds.AccessKeyID, err)
	}
}
