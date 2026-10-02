package cli

import (
	"errors"
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

const (
	invalidClientTokenIDResponse = `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error><RequestId>1</RequestId></ErrorResponse>`
	deleteConflictResponse       = `<ErrorResponse><Error><Type>Sender</Type><Code>DeleteConflict</Code><Message>Cannot delete the access key.</Message></Error><RequestId>1</RequestId></ErrorResponse>`
)

// rotateTestServer records requests as "Action SigningKeyID [-> TargetKeyID]", rejects the first
// newKeyRejections requests signed with the new key, and fails deletes of the keys in failDeletes
func rotateTestServer(t *testing.T, newKeyRejections int, failDeletes ...string) (*httptest.Server, *[]string) {
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
		if r.Form.Get("Action") == "DeleteAccessKey" && slices.Contains(failDeletes, r.Form.Get("AccessKeyId")) {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, deleteConflictResponse)
			return
		}
		_, _ = io.WriteString(w, responses[r.Form.Get("Action")])
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func shortenAccessKeyWait(t *testing.T) {
	t.Helper()
	timeout, deleteTimeout, interval := accessKeyWaitTimeout, accessKeyDeleteTimeout, accessKeyWaitInterval
	accessKeyWaitTimeout, accessKeyDeleteTimeout, accessKeyWaitInterval = 100*time.Millisecond, 100*time.Millisecond, time.Millisecond
	t.Cleanup(func() {
		accessKeyWaitTimeout, accessKeyDeleteTimeout, accessKeyWaitInterval = timeout, deleteTimeout, interval
	})
}

// failingSetKeyring is a keyring whose writes fail
type failingSetKeyring struct{ keyring.Keyring }

func (failingSetKeyring) Set(keyring.Item) error { return errors.New("keyring is locked") }

func runRotate(t *testing.T, srv *httptest.Server) (*vault.CredentialKeyring, error) {
	t.Helper()
	return runRotateWithKeyring(t, srv, nil)
}

// runRotateWithKeyring rotates profile a, passing rotate the keyring returned by wrap if it is set
func runRotateWithKeyring(t *testing.T, srv *httptest.Server, wrap func(keyring.Keyring) keyring.Keyring) (*vault.CredentialKeyring, error) {
	t.Helper()
	shortenAccessKeyWait(t)

	configFile := writeTempConfig(t, []byte("[profile a]\nregion = us-east-1\nendpoint_url = "+srv.URL+"\n"))
	kr := keyring.NewArrayKeyring(nil)
	ckr := &vault.CredentialKeyring{Keyring: kr}
	if err := ckr.Set("a", aws.Credentials{AccessKeyID: "AKIAOLD", SecretAccessKey: "old/secret+"}); err != nil {
		t.Fatal(err)
	}

	input := rotateCommandInput{ProfileName: "a", Config: vault.ProfileConfig{MfaPromptMethod: "terminal"}}
	var rotateKeyring keyring.Keyring = kr
	if wrap != nil {
		rotateKeyring = wrap(kr)
	}
	return ckr, rotateCommand(input, configFile, rotateKeyring)
}

func deleteRequests(requests []string) []string {
	var deletes []string
	for _, r := range requests {
		if strings.HasPrefix(r, "DeleteAccessKey") {
			deletes = append(deletes, r)
		}
	}
	return deletes
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

	if got, want := deleteRequests(*requests), []string{"DeleteAccessKey ASIASESSION -> AKIANEW"}; !slices.Equal(got, want) {
		t.Fatalf("deletes = %v, want %v", got, want)
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

func TestRotateCommandDeletesNewAccessKeyWhenStoringItFails(t *testing.T) {
	srv, requests := rotateTestServer(t, 0)
	ckr, err := runRotateWithKeyring(t, srv, func(kr keyring.Keyring) keyring.Keyring { return failingSetKeyring{kr} })
	if err == nil || !strings.Contains(err.Error(), "storing new access key") || !strings.Contains(err.Error(), "deleted new access key") {
		t.Fatalf("err = %v, want a storing error reporting the new access key was deleted", err)
	}

	if got, want := deleteRequests(*requests), []string{"DeleteAccessKey ASIASESSION -> AKIANEW"}; !slices.Equal(got, want) {
		t.Fatalf("deletes = %v, want %v", got, want)
	}
	assertStoredKey(t, ckr, "AKIAOLD")
}

func TestRotateCommandShowsCleanupCommandWhenDeletingOldAccessKeyFails(t *testing.T) {
	srv, _ := rotateTestServer(t, 0, "AKIAOLD")
	ckr, err := runRotate(t, srv)
	if err == nil || !strings.Contains(err.Error(), "aws-vault exec a -- aws iam delete-access-key --access-key-id AKIAOLD") {
		t.Fatalf("err = %v, want the command to delete the old access key", err)
	}
	assertStoredKey(t, ckr, "AKIANEW")
}

func TestRotateCommandShowsCleanupCommandWhenRollbackFails(t *testing.T) {
	srv, _ := rotateTestServer(t, 1<<30, "AKIANEW")
	ckr, err := runRotate(t, srv)
	if err == nil || !strings.Contains(err.Error(), "aws-vault exec a -- aws iam delete-access-key --access-key-id AKIANEW") {
		t.Fatalf("err = %v, want the command to delete the new access key", err)
	}
	assertStoredKey(t, ckr, "AKIAOLD")
}

func TestDeleteAccessKeyCommand(t *testing.T) {
	userName := "alice"
	cases := []struct {
		input    rotateCommandInput
		userName *string
		want     string
	}{
		{input: rotateCommandInput{ProfileName: "a"}, want: "aws-vault exec a -- aws iam delete-access-key --access-key-id AKIAOLD"},
		{input: rotateCommandInput{ProfileName: "a", NoSession: true}, want: "aws-vault exec --no-session a -- aws iam delete-access-key --access-key-id AKIAOLD"},
		{input: rotateCommandInput{ProfileName: "a"}, userName: &userName, want: "aws-vault exec a -- aws iam delete-access-key --access-key-id AKIAOLD --user-name alice"},
	}
	for _, tc := range cases {
		if got := deleteAccessKeyCommand(tc.input, "AKIAOLD", tc.userName); got != tc.want {
			t.Errorf("deleteAccessKeyCommand() = %q, want %q", got, tc.want)
		}
	}
}
