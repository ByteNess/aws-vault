//go:build windows
// +build windows

package vault_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// openTestWinCred opens the real Windows Credential Manager. It writes to the
// user's credential store, so it only runs in CI.
func openTestWinCred(t *testing.T) keyring.Keyring {
	t.Helper()
	if os.Getenv("CI") == "" {
		t.Skip("writes to the Windows Credential Manager; set CI=1 to run")
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{keyring.WinCredBackend},
		ServiceName:     "test-" + hex.EncodeToString(b),
		WinCredPrefix:   "aws-vault-test",
	})
	if err != nil {
		t.Fatalf("open wincred: %v", err)
	}
	t.Cleanup(func() {
		keys, _ := kr.Keys()
		for _, k := range keys {
			_ = kr.Remove(k)
		}
	})
	return kr
}

func TestWinCredBlobLimit(t *testing.T) {
	kr := openTestWinCred(t)

	if err := kr.Set(keyring.Item{Key: "at-limit", Data: []byte(strings.Repeat("x", 5*512))}); err != nil {
		t.Fatalf("Set of 2560 bytes: %v", err)
	}
	err := kr.Set(keyring.Item{Key: "over-limit", Data: []byte(strings.Repeat("x", 5*512+1))})
	var errno syscall.Errno
	if !errors.As(err, &errno) || errno != 1783 {
		t.Errorf("Set of 2561 bytes: err = %v, want RPC_X_BAD_STUB_DATA (1783)", err)
	}
}

func TestOIDCTokenKeyringOnWinCred(t *testing.T) {
	kr := openTestWinCred(t)
	tk := &vault.OIDCTokenKeyring{Keyring: kr}
	startURL := "https://example.awsapps.com/start"
	want := measuredTokenData()

	if err := tk.Set(startURL, want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := tk.Get(startURL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Expired() || aws.ToString(got.Token.AccessToken) != aws.ToString(want.Token.AccessToken) {
		t.Errorf("token not usable: %+v", got)
	}
	if got.Refreshable() {
		t.Error("the client secret cannot fit in a Windows credential, so the token cannot be refreshable")
	}
}
