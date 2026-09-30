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

func TestOIDCTokenKeyringKeepsRefreshableToken(t *testing.T) {
	startURL := "https://example.awsapps.com/start"
	expired := &ssooidc.CreateTokenOutput{AccessToken: aws.String("token"), RefreshToken: aws.String("refresh"), ExpiresIn: -60}
	client := &vault.OIDCClient{ID: "id", Secret: "secret", ExpiresAt: time.Now().Add(time.Hour)}

	for _, tc := range []struct {
		name   string
		client *vault.OIDCClient
		kept   bool
	}{
		{"refreshable", client, true},
		{"no client", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tk := vault.OIDCTokenKeyring{Keyring: keyring.NewArrayKeyring(nil)}
			if err := tk.SetData(startURL, expired, tc.client); err != nil {
				t.Fatal(err)
			}

			if _, err := tk.Get(startURL); err != keyring.ErrKeyNotFound {
				t.Errorf("Get of an expired token: err = %v, want ErrKeyNotFound", err)
			}
			d, err := tk.GetData(startURL)
			if tc.kept && (err != nil || d.Token.ExpiresIn != 0 || d.Client.ID != "id") {
				t.Errorf("GetData = %+v, %v, want the expired token with its client and ExpiresIn 0", d, err)
			}
			if !tc.kept && err != keyring.ErrKeyNotFound {
				t.Errorf("GetData: err = %v, want ErrKeyNotFound", err)
			}
			if has, _ := tk.Has(startURL); has != tc.kept {
				t.Errorf("token kept = %v, want %v", has, tc.kept)
			}
		})
	}
}

// Tokens stored before refresh support have no client and still load.
func TestOIDCTokenKeyringReadsTokenWithoutClient(t *testing.T) {
	startURL := "https://example.awsapps.com/start"
	kr := keyring.NewArrayKeyring([]keyring.Item{{
		Key:  "oidc:" + startURL,
		Data: []byte(`{"Token":{"AccessToken":"token","ExpiresIn":3600},"Expiration":"` + time.Now().Add(time.Hour).Format(time.RFC3339) + `"}`),
	}})
	tk := vault.OIDCTokenKeyring{Keyring: kr}

	d, err := tk.GetData(startURL)
	if err != nil || aws.ToString(d.Token.AccessToken) != "token" || d.Client != nil {
		t.Fatalf("GetData = %+v, %v, want the token without a client", d, err)
	}
}
