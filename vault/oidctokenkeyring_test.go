package vault_test

import (
	"errors"
	"strings"
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

func TestOIDCTokenKeyringPeekLeavesExpiredTokenWithoutRefreshToken(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	tk := &vault.OIDCTokenKeyring{Keyring: kr}
	startURL := "https://example.awsapps.com/start"

	if err := tk.Set(startURL, &vault.OIDCTokenData{Token: ssooidc.CreateTokenOutput{AccessToken: aws.String("token"), ExpiresIn: -1}}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, err := tk.Peek(startURL); err != keyring.ErrKeyNotFound {
		t.Fatalf("Peek: err = %v, want ErrKeyNotFound", err)
	}
	if has, _ := tk.Has(startURL); !has {
		t.Error("Peek must leave the expired token in the keyring")
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

// The pass and passage backends list "oidc:https://..." back as "oidc:https:/...".
func TestOIDCTokenKeyringFindsTokenWithCollapsedSchemeSeparator(t *testing.T) {
	kr := keyring.NewArrayKeyring([]keyring.Item{{Key: "oidc:https:/example.awsapps.com/start", Data: []byte(`{}`)}})
	tk := &vault.OIDCTokenKeyring{Keyring: kr}
	startURL := "https://example.awsapps.com/start"

	if has, err := tk.Has(startURL); err != nil || !has {
		t.Fatalf("Has: got %v, %v, want true", has, err)
	}

	keys, err := tk.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 1 || keys[0] != startURL {
		t.Errorf("Keys = %v, want [%s]", keys, startURL)
	}
}

// winCredKeyring rejects entries over 2560 bytes like the Windows Credential
// Manager, or every entry when failAll is set.
type winCredKeyring struct {
	keyring.Keyring
	failAll bool
	sets    int
}

func (w *winCredKeyring) Set(i keyring.Item) error {
	w.sets++
	if w.failAll || len(i.Data) > 5*512 {
		return errors.New("the stub received bad data")
	}
	return w.Keyring.Set(i)
}

// measuredTokenData has the sizes IAM Identity Center issues.
func measuredTokenData() *vault.OIDCTokenData {
	return &vault.OIDCTokenData{
		Token: ssooidc.CreateTokenOutput{
			AccessToken:  aws.String(strings.Repeat("a", 232)),
			RefreshToken: aws.String(strings.Repeat("r", 232)),
			TokenType:    aws.String("Bearer"),
			ExpiresIn:    3600,
		},
		ClientID:              strings.Repeat("c", 35),
		ClientSecret:          strings.Repeat("s", 2877),
		ClientSecretExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	}
}

func TestOIDCTokenKeyringSetStoresTokenWithoutRefreshWhenTooLarge(t *testing.T) {
	kr := &winCredKeyring{Keyring: keyring.NewArrayKeyring(nil)}
	tk := &vault.OIDCTokenKeyring{Keyring: kr}
	startURL := "https://example.awsapps.com/start"
	want := measuredTokenData()

	if err := tk.Set(startURL, want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if kr.sets != 2 {
		t.Errorf("Set calls = %d, want 2 (the full entry, then the token alone)", kr.sets)
	}

	got, err := tk.Get(startURL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Expired() || aws.ToString(got.Token.AccessToken) != aws.ToString(want.Token.AccessToken) {
		t.Errorf("token not usable after fallback: %+v", got)
	}
	if got.Refreshable() || got.Token.RefreshToken != nil || got.ClientID != "" || got.ClientSecret != "" {
		t.Errorf("fallback entry must not carry refresh material: %+v", got)
	}
}

func TestOIDCTokenKeyringSetKeepsRefreshMaterialWhenItFits(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	tk := &vault.OIDCTokenKeyring{Keyring: kr}
	startURL := "https://example.awsapps.com/start"

	if err := tk.Set(startURL, measuredTokenData()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := tk.Get(startURL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Refreshable() {
		t.Error("token should stay refreshable")
	}
}

func TestOIDCTokenKeyringSetDoesNotRetrySmallEntries(t *testing.T) {
	kr := &winCredKeyring{Keyring: keyring.NewArrayKeyring(nil), failAll: true}
	tk := &vault.OIDCTokenKeyring{Keyring: kr}
	data := measuredTokenData()
	data.ClientSecret = "secret"

	if err := tk.Set("https://example.awsapps.com/start", data); err == nil {
		t.Fatal("Set: want the keyring error")
	}
	if kr.sets != 1 {
		t.Errorf("Set calls = %d, want 1", kr.sets)
	}
}
