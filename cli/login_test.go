package cli

import (
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func TestGetCredsProviderMissingCredentials(t *testing.T) {
	input := loginCommandInput{ProfileName: "a"}
	config := &vault.ProfileConfig{ProfileName: "a"}

	_, err := getCredsProvider(input, config, nil, keyring.NewArrayKeyring(nil))

	want := "getting temporary credentials: profile a: credentials missing"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}
