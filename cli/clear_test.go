package cli

import (
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// TestClearCommandModernOIDC is a regression test for the bug where
// ClearCommand did not remove OIDC tokens for profiles that use a modern
// [sso-session] block (SSOStartURL is empty in the profile section; the URL
// lives in the referenced sso-session section).
func TestClearCommandModernOIDC(t *testing.T) {
	const startURL = "https://example.awsapps.com/start"

	configFile := writeTempConfig(t, listTestConfig)
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "oidc:" + startURL, Data: []byte(`{}`)},
	})

	oidcKeyring := &vault.OIDCTokenKeyring{Keyring: kr}

	has, err := oidcKeyring.Has(startURL)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("expected OIDC token in keyring before clear")
	}

	if err := ClearCommand(ClearCommandInput{ProfileName: "sso-profile"}, configFile, kr); err != nil {
		t.Fatalf("ClearCommand error: %v", err)
	}

	has, err = oidcKeyring.Has(startURL)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Error("ClearCommand did not remove OIDC token for modern sso-session profile")
	}
}
