package vault_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func TestIsSessionKey(t *testing.T) {
	var testCases = []struct {
		Key       string
		IsSession bool
	}{
		{"blah", false},
		{"blah session (61633665646639303539)", true},
		{"blah-iam session (32383863333237616430)", true},
		{"session,c2Vzc2lvbg,,1572281751", true},
		{"session,c2Vzc2lvbg,YXJuOmF3czppYW06OjEyMzQ1Njc4OTA6bWZhL2pzdGV3bW9u,1572281751", true},
	}

	for _, tc := range testCases {
		if tc.IsSession && !vault.IsSessionKey(tc.Key) {
			t.Fatalf("%q is a session key, but wasn't detected as one", tc.Key)
		} else if !tc.IsSession && vault.IsSessionKey(tc.Key) {
			t.Fatalf("%q isn't a session key, but was detected as one", tc.Key)
		}
	}
}

// Cached sessions must trust aws-vault so that reading them back doesn't
// require a keychain authorization prompt (and, when the aws-vault keychain is
// unlocked with Touch ID, a fingerprint) on every invocation.
// See https://github.com/ByteNess/aws-vault/issues/421
func TestSessionKeyringSetTrustsApplication(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	sk := &vault.SessionKeyring{Keyring: kr}

	expiry := time.Now().Add(time.Hour)
	key := vault.SessionMetadata{Type: "sts.GetSessionToken", ProfileName: "llamas"}
	err := sk.Set(key, &ststypes.Credentials{
		AccessKeyId:     aws.String("AKID"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
		Expiration:      &expiry,
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
		t.Error("session item was stored with KeychainNotTrustApplication, which prompts for keychain access on every read")
	}
}
