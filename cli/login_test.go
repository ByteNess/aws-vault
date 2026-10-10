package cli

import (
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func TestGetCredsProviderMissingCredentials(t *testing.T) {
	input := loginCommandInput{ProfileName: "a"}
	config := &vault.ProfileConfig{ProfileName: "a"}
	kr := keyring.NewArrayKeyring(nil)

	_, err := getCredsProvider(input, config, nil, kr, kr)

	want := "getting temporary credentials: profile a: credentials missing"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

// login writes the same session cache and OIDC token as exec and export, and
// can start the same SSO sign-in, so with --parallel-safe it takes the same
// locks. Without the flag it takes none.
func TestGetCredsProviderParallelSafeSSOLocks(t *testing.T) {
	for _, parallelSafe := range []bool{false, true} {
		input := loginCommandInput{ProfileName: "sso-profile", ParallelSafe: parallelSafe}
		config := &vault.ProfileConfig{
			ProfileName:  "sso-profile",
			SSOStartURL:  "https://sso.example/start",
			SSORegion:    "us-east-1",
			SSOAccountID: "123456789012",
			SSORoleName:  "Role",
		}

		kr := keyring.NewArrayKeyring(nil)
		provider, err := getCredsProvider(input, config, nil, kr, kr)
		if err != nil {
			t.Fatal(err)
		}
		cached, ok := provider.(*vault.CachedSessionProvider)
		if !ok {
			t.Fatalf("got %T, want *vault.CachedSessionProvider", provider)
		}
		if cached.UseSessionLock != parallelSafe {
			t.Errorf("parallelSafe=%t: UseSessionLock = %t", parallelSafe, cached.UseSessionLock)
		}
		sso, ok := cached.SessionProvider.(*vault.SSORoleCredentialsProvider)
		if !ok {
			t.Fatalf("got %T, want *vault.SSORoleCredentialsProvider", cached.SessionProvider)
		}
		if sso.UseSSOTokenLock != parallelSafe {
			t.Errorf("parallelSafe=%t: UseSSOTokenLock = %t", parallelSafe, sso.UseSSOTokenLock)
		}
	}
}
