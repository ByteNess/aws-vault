package vault_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// The cached OIDC token must trust aws-vault so that reading it back doesn't
// require a keychain authorization prompt (and, when the aws-vault keychain is
// unlocked with Touch ID, a fingerprint) on every invocation.
// See https://github.com/ByteNess/aws-vault/issues/421
func TestOIDCTokenKeyringSetTrustsApplication(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	tk := &vault.OIDCTokenKeyring{Keyring: kr}

	startURL := "https://example.awsapps.com/start"
	err := tk.Set(startURL, &vault.OIDCTokenData{Token: ssooidc.CreateTokenOutput{
		AccessToken: aws.String("token"),
		ExpiresIn:   3600,
	}})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	keys, err := kr.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 stored item, got %d", len(keys))
	}

	item, err := kr.Get(keys[0])
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if item.KeychainNotTrustApplication {
		t.Error("oidc token item was stored with KeychainNotTrustApplication, which prompts for keychain access on every read")
	}
}

func TestOIDCTokenKeyringGetRemovesExpiredTokenWithoutRefreshToken(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	tk := &vault.OIDCTokenKeyring{Keyring: kr}
	startURL := "https://example.awsapps.com/start"

	// ExpiresIn of -1 stores a token whose expiration is already in the past.
	if err := tk.Set(startURL, &vault.OIDCTokenData{Token: ssooidc.CreateTokenOutput{AccessToken: aws.String("token"), ExpiresIn: -1}}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, err := tk.Get(startURL); err != keyring.ErrKeyNotFound {
		t.Fatalf("Get: err = %v, want ErrKeyNotFound", err)
	}
	if has, _ := tk.Has(startURL); has {
		t.Error("expired token without a refresh token should have been removed")
	}
}

func TestOIDCTokenKeyringGetKeepsExpiredRefreshableToken(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	tk := &vault.OIDCTokenKeyring{Keyring: kr}
	startURL := "https://example.awsapps.com/start"

	err := tk.Set(startURL, &vault.OIDCTokenData{
		Token:                 ssooidc.CreateTokenOutput{AccessToken: aws.String("token"), RefreshToken: aws.String("refresh"), ExpiresIn: -1},
		ClientID:              "client",
		ClientSecret:          "secret",
		ClientSecretExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := tk.Get(startURL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Expired() {
		t.Error("token should report Expired()")
	}
	if !got.Refreshable() {
		t.Error("token should report Refreshable()")
	}
	if got.Token.ExpiresIn != 0 {
		t.Errorf("ExpiresIn = %d, want 0 for an expired token", got.Token.ExpiresIn)
	}
	if aws.ToString(got.Token.RefreshToken) != "refresh" || got.ClientID != "client" || got.ClientSecret != "secret" {
		t.Errorf("refresh material not round-tripped: %+v", got)
	}
	if has, _ := tk.Has(startURL); !has {
		t.Error("refreshable token must stay in the keyring until it is redeemed")
	}
}

// Entries written before refresh support only carried Token and Expiration.
// They must still load, and be treated as non-refreshable.
func TestOIDCTokenKeyringGetReadsLegacyEntry(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	tk := &vault.OIDCTokenKeyring{Keyring: kr}
	startURL := "https://example.awsapps.com/start"

	legacy := `{"Token":{"AccessToken":"token","ExpiresIn":3600,"RefreshToken":"refresh"},"Expiration":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
	if err := kr.Set(keyring.Item{Key: "oidc:" + startURL, Data: []byte(legacy)}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := tk.Get(startURL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Expired() || aws.ToString(got.Token.AccessToken) != "token" {
		t.Errorf("legacy entry not loaded correctly: %+v", got)
	}
	if got.Refreshable() {
		t.Error("legacy entry has no client registration and must not be refreshable")
	}
	if got.Token.ExpiresIn <= 0 || got.Token.ExpiresIn > 3600 {
		t.Errorf("ExpiresIn = %d, want remaining seconds", got.Token.ExpiresIn)
	}
}
