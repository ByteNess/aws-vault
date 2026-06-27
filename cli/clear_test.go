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

// TestClearCommandBothSetPrefersSSOSession verifies that when a profile sets
// both an inline sso_start_url and an sso_session, ClearCommand removes the
// token keyed by the [sso-session] url (the one the login path creates).
// Inline-first precedence would look up the wrong url and leave it behind.
func TestClearCommandBothSetPrefersSSOSession(t *testing.T) {
	const sessionURL = "https://session.awsapps.com/start"
	configFile := writeTempConfig(t, listBothSetConfig)
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "oidc:" + sessionURL, Data: []byte(`{}`)},
	})
	oidcKeyring := &vault.OIDCTokenKeyring{Keyring: kr}

	if err := ClearCommand(ClearCommandInput{ProfileName: "both-profile"}, configFile, kr); err != nil {
		t.Fatalf("ClearCommand error: %v", err)
	}

	has, err := oidcKeyring.Has(sessionURL)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Error("ClearCommand left the sso-session token behind; it resolved the inline url instead")
	}
}
