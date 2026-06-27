package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func ExampleListCommand() {
	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureListCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"list", "--credentials",
	}))

	// Output:
	// llamas
}

var listTestConfig = []byte(`[sso-session my-sso]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile sso-profile]
sso_session = my-sso
sso_account_id = 111122223333
sso_role_name = ReadOnly
region = us-east-1

[profile no-creds-profile]
sso_session = my-sso
sso_account_id = 444455556666
sso_role_name = ReadOnly
region = us-east-1
`)

// TestListCommandCredentialShown verifies that a profile whose name exists as a
// credential key in the keyring is shown with its name in the Credentials column
// of the list output.
func TestListCommandCredentialShown(t *testing.T) {
	configFile := writeTempConfig(t, listTestConfig)
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "sso-profile", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})

	output := captureListOutput(t, ListCommandInput{}, configFile, kr)

	// sso-profile has a stored credential; its Credentials column must show the profile name.
	found := false
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "sso-profile" && fields[1] == "sso-profile" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sso-profile in Credentials column; got:\n%s", output)
	}

	// no-creds-profile has no credential; its Credentials column must show "-".
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "no-creds-profile" && fields[1] != "-" {
			t.Errorf("no-creds-profile should have '-' in Credentials column; got line: %q", line)
		}
	}
}

// TestListCommandOIDCTokenShown is a regression test for the bug where
// OIDCTokenKeyring.Has() compared the raw startURL against keychain keys that
// carry an "oidc:" prefix, so Has() always returned false and OIDC tokens were
// never displayed in `aws-vault list`.
//
// This test exercises the OIDCTokenKeyring abstraction layer: Has() must
// delegate to Keys() so both methods operate on stripped startURLs. The
// ListCommand display logic is covered by TestListCommandOutputModernOIDC.
func TestListCommandOIDCTokenShown(t *testing.T) {
	const startURL = "https://example.awsapps.com/start"

	kr := keyring.NewArrayKeyring([]keyring.Item{
		// OIDC tokens are stored under "oidc:<startURL>" — this is what the
		// real OIDCTokenKeyring.Set() writes, and what Keys() strips back.
		{Key: "oidc:" + startURL, Data: []byte(`{}`)},
	})

	oidcKeyring := &vault.OIDCTokenKeyring{Keyring: kr}

	// Keys() must return the stripped URL so that the in-loop set lookup works.
	keys, err := oidcKeyring.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != startURL {
		t.Fatalf("Keys() = %v, want [%q]", keys, startURL)
	}

	// Has() must return true now that it compares using fmtKey(startURL).
	has, err := oidcKeyring.Has(startURL)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Error("OIDCTokenKeyring.Has() returned false; prefix comparison is broken again")
	}

	// Verify Keys() returns stripped URLs — ListCommand builds oidcTokenLabels
	// from Keys(), so a broken Keys() would silently hide all OIDC tokens.
	tokenSet := make(map[string]bool, len(keys))
	for _, k := range keys {
		tokenSet[k] = true
	}
	if !tokenSet[startURL] {
		t.Errorf("tokenSet[%q] = false; Keys() is not stripping the oidc: prefix", startURL)
	}
}

// TestListCommandOIDCTokenNotShownWhenAbsent verifies that profiles whose
// sso_start_url has no token in the keyring are not shown with an oidc entry.
func TestListCommandOIDCTokenNotShownWhenAbsent(t *testing.T) {
	const startURL = "https://example.awsapps.com/start"

	kr := keyring.NewArrayKeyring(nil)
	oidcKeyring := &vault.OIDCTokenKeyring{Keyring: kr}

	keys, err := oidcKeyring.Keys()
	if err != nil {
		t.Fatal(err)
	}

	tokenSet := make(map[string]bool, len(keys))
	for _, k := range keys {
		tokenSet[k] = true
	}
	if tokenSet[startURL] {
		t.Errorf("tokenSet[%q] = true; empty keyring should not match any start URL", startURL)
	}
}

// TestListCommandCredentialSetBuildCorrectly verifies that the credentialsSet
// built from credentialKeyring.Keys() correctly matches stored credential names
// and does not match session keys or OIDC token keys that share the keyring.
func TestListCommandCredentialSetBuildCorrectly(t *testing.T) {
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "my-profile", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
		{Key: "oidc:https://example.com/start", Data: []byte(`{}`)},
		// session key format: "<type>,<profile>,<mfaSerial>,<expiration_unix>"
		{Key: "GetSessionToken,my-profile,,9999999999", Data: []byte(`{}`)},
	})

	credKeyring := &vault.CredentialKeyring{Keyring: kr}
	names, err := credKeyring.Keys()
	if err != nil {
		t.Fatal(err)
	}

	credSet := make(map[string]bool, len(names))
	for _, n := range names {
		credSet[n] = true
	}

	if !credSet["my-profile"] {
		t.Error("credSet should contain the credential profile name")
	}
	if credSet["oidc:https://example.com/start"] {
		t.Error("credSet must not contain OIDC token keys")
	}
	for k := range credSet {
		if vault.IsSessionKey(k) {
			t.Errorf("credSet must not contain session keys, got %q", k)
		}
	}
}

// listLegacyConfig uses inline sso_start_url in [profile] blocks, which
// populates profileSection.SSOStartURL directly and allows OIDC tokens to be
// matched in the oidcTokensSet lookup.
var listLegacyConfig = []byte(`[profile legacy-sso]
sso_start_url = https://example.awsapps.com/start
sso_account_id = 111122223333
sso_role_name = ReadOnly
region = us-east-1

[profile no-token-profile]
sso_start_url = https://other.awsapps.com/start
sso_account_id = 444455556666
sso_role_name = ReadOnly
region = us-east-1
`)

// captureListOutput calls ListCommand into a bytes.Buffer and returns the output.
func captureListOutput(t *testing.T, input ListCommandInput, configFile *vault.ConfigFile, kr keyring.Keyring) string {
	t.Helper()
	var buf bytes.Buffer
	if err := ListCommand(input, configFile, kr, &buf); err != nil {
		t.Fatalf("ListCommand error: %v", err)
	}
	return buf.String()
}

// TestListCommandOutputLegacyOIDC is an end-to-end test verifying that a
// profile using a legacy inline sso_start_url with a matching OIDC token in
// the keyring shows the token associated with that profile row in the output.
func TestListCommandOutputLegacyOIDC(t *testing.T) {
	const startURL = "https://example.awsapps.com/start"
	configFile := writeTempConfig(t, listLegacyConfig)
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "oidc:" + startURL, Data: []byte(`{}`)},
	})

	output := captureListOutput(t, ListCommandInput{}, configFile, kr)

	// Legacy config has no sso-session name, so the label uses the hostname:
	// "oidc:example.awsapps.com".
	const label = "oidc:example.awsapps.com"
	found := false
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, label) {
			if !strings.HasPrefix(strings.TrimSpace(line), "legacy-sso") {
				t.Errorf("OIDC token not associated with legacy-sso profile row; got line: %q", line)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("OIDC token label %q not found in list output; got:\n%s", label, output)
	}

	// no-token-profile has a different sso_start_url with no token; must show no oidc: label.
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "oidc:other.awsapps.com") {
			t.Errorf("unexpected OIDC token shown for no-token-profile; got line: %q", line)
		}
	}
}

// TestListCommandOutputModernOIDC verifies that profiles using a modern
// [sso-session] block correctly show the OIDC token in their Sessions column.
// ListCommand resolves the sso_start_url from the referenced [sso-session]
// section when the profile's own SSOStartURL field is empty.
func TestListCommandOutputModernOIDC(t *testing.T) {
	const startURL = "https://example.awsapps.com/start"
	configFile := writeTempConfig(t, listTestConfig)
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "oidc:" + startURL, Data: []byte(`{}`)},
	})

	output := captureListOutput(t, ListCommandInput{}, configFile, kr)

	// Modern config references [sso-session my-sso], so the label uses the session
	// name: "oidc:my-sso".
	const label = "oidc:my-sso"
	for _, profileName := range []string{"sso-profile", "no-creds-profile"} {
		found := false
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, label) {
				fields := strings.Fields(line)
				if len(fields) > 0 && fields[0] == profileName {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("OIDC token label %q not shown under profile %q; output:\n%s", label, profileName, output)
		}
	}

	// Token must not appear as an orphaned row.
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, label) {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == "-" {
				t.Errorf("OIDC token appeared as orphaned row; expected it under profile rows: %q", line)
			}
		}
	}
}

// TestListCommandOnlySessionsIncludesOIDC verifies that --sessions includes
// OIDC token labels in the output alongside regular session labels.
func TestListCommandOnlySessionsIncludesOIDC(t *testing.T) {
	const startURL = "https://example.awsapps.com/start"
	configFile := writeTempConfig(t, listTestConfig)
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "oidc:" + startURL, Data: []byte(`{}`)},
	})

	output := captureListOutput(t, ListCommandInput{OnlySessions: true}, configFile, kr)

	// The OIDC label (oidc:my-sso) must appear in the --sessions output.
	found := false
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "oidc:my-sso" {
			found = true
		}
	}
	if !found {
		t.Errorf("OIDC label not found in --sessions output; got:\n%s", output)
	}
}
