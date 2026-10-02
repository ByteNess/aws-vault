package vault_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// The synced file must carry the client registration, otherwise the AWS CLI
// and SDKs cannot refresh the 1-hour token and fall back to the browser.
func TestSyncOIDCTokenToStandardCacheWritesClientRegistration(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	kr := keyring.NewArrayKeyring(nil)
	startURL := "https://example.awsapps.com/start"
	registrationExpiry := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	err := (vault.OIDCTokenKeyring{Keyring: kr}).Set(startURL, &vault.OIDCTokenData{
		Token: ssooidc.CreateTokenOutput{
			AccessToken:  aws.String("access"),
			RefreshToken: aws.String("refresh"),
			ExpiresIn:    3600,
		},
		ClientID:              "client",
		ClientSecret:          "secret",
		ClientSecretExpiresAt: registrationExpiry,
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	config := &vault.ProfileConfig{SSOStartURL: startURL, SSOSession: "my-sso"}
	if err := vault.SyncOIDCTokenToStandardCache(config, kr); err != nil {
		t.Fatalf("SyncOIDCTokenToStandardCache: %v", err)
	}

	path, err := ssocreds.StandardCachedTokenFilepath("my-sso")
	if err != nil {
		t.Fatalf("StandardCachedTokenFilepath: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read synced file: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]string{
		"accessToken":           "access",
		"refreshToken":          "refresh",
		"clientId":              "client",
		"clientSecret":          "secret",
		"registrationExpiresAt": registrationExpiry.UTC().Format(time.RFC3339),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if got["expiresAt"] == "" {
		t.Error("expiresAt missing")
	}
}
