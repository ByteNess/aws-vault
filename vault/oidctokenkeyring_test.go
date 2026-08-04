package vault_test

import (
	"testing"

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
	err := tk.Set(startURL, &ssooidc.CreateTokenOutput{
		AccessToken: aws.String("token"),
		ExpiresIn:   3600,
	})
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
