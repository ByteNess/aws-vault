package cli

import (
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
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

	if err := ClearCommand(ClearCommandInput{ProfileName: "sso-profile"}, configFile, kr, nil); err != nil {
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

	if err := ClearCommand(ClearCommandInput{ProfileName: "both-profile"}, configFile, kr, nil); err != nil {
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

func TestClearCommandClearsSessionsFromBothKeyrings(t *testing.T) {
	const startURL = "https://example.awsapps.com/start"
	configFile := writeTempConfig(t, listTestConfig)
	primary := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "oidc:" + startURL, Data: []byte(`{}`)},
	})
	sessions := keyring.NewArrayKeyring(nil)
	expires := time.Now().Add(time.Hour)
	for _, kr := range []keyring.Keyring{primary, sessions} {
		sessionKeyring := &vault.SessionKeyring{Keyring: kr}
		if err := sessionKeyring.Set(vault.SessionMetadata{
			Type:        "sts.GetSessionToken",
			ProfileName: "sso-profile",
		}, &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIAEXAMPLE"),
			SecretAccessKey: aws.String("secret"),
			SessionToken:    aws.String("token"),
			Expiration:      &expires,
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := ClearCommand(ClearCommandInput{ProfileName: "sso-profile"}, configFile, primary, sessions); err != nil {
		t.Fatalf("ClearCommand error: %v", err)
	}

	for _, kr := range []keyring.Keyring{primary, sessions} {
		keys, err := (&vault.SessionKeyring{Keyring: kr}).Keys()
		if err != nil || len(keys) != 0 {
			t.Fatalf("keyring still contains sessions %v, err: %v", keys, err)
		}
	}
	if has, err := (&vault.OIDCTokenKeyring{Keyring: primary}).Has(startURL); err != nil || has {
		t.Fatalf("OIDC token was not removed from primary keyring, has: %v, err: %v", has, err)
	}
}

// A slice field makes this value non-comparable, like OPConnectKeyring.
type nonComparableKeyring struct {
	keyring.Keyring
	_ []string
}

func TestClearCommandWithNonComparableKeyring(t *testing.T) {
	tests := []struct {
		name                  string
		sessionBackend        string
		overrides             keyringConfigOverrides
		wantRemainingSessions int
	}{
		{name: "shared", wantRemainingSessions: 1},
		{name: "separate backend", sessionBackend: "op-connect"},
		{name: "session overrides", overrides: keyringConfigOverrides{OPVaultID: "sessions"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			primary := nonComparableKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{
				{Key: "oidc:https://example.awsapps.com/start", Data: []byte(`{}`)},
				{Key: "sso-profile", Data: []byte(`{}`)},
			})}
			sessions := nonComparableKeyring{Keyring: keyring.NewArrayKeyring(nil)}
			expires := time.Now().Add(time.Hour)
			for _, kr := range []keyring.Keyring{primary, sessions} {
				if err := (&vault.SessionKeyring{Keyring: kr}).Set(vault.SessionMetadata{
					Type:        "sts.GetSessionToken",
					ProfileName: "sso-profile",
				}, &ststypes.Credentials{
					AccessKeyId:     aws.String("AKIAEXAMPLE"),
					SecretAccessKey: aws.String("secret"),
					SessionToken:    aws.String("token"),
					Expiration:      &expires,
				}); err != nil {
					t.Fatal(err)
				}
			}

			a := &AwsVault{
				KeyringBackend:          "op-connect",
				SessionKeyringBackend:   tc.sessionBackend,
				sessionKeyringOverrides: tc.overrides,
				keyringImpl:             primary,
				sessionKeyringImpl:      sessions,
				awsConfigFile:           writeTempConfig(t, listTestConfig),
			}
			app := kingpin.New("aws-vault", "")
			ConfigureClearCommand(app, a)
			if _, err := app.Parse([]string{"clear"}); err != nil {
				t.Fatal(err)
			}

			keys, err := primary.Keys()
			if err != nil {
				t.Fatal(err)
			}
			if len(keys) != 1 || keys[0] != "sso-profile" {
				t.Fatalf("expected only long-lived credentials in primary keyring, got %v", keys)
			}
			sessionKeys, err := (&vault.SessionKeyring{Keyring: sessions}).Keys()
			if err != nil {
				t.Fatal(err)
			}
			if len(sessionKeys) != tc.wantRemainingSessions {
				t.Fatalf("separate keyring contains %d sessions, want %d", len(sessionKeys), tc.wantRemainingSessions)
			}
		})
	}
}
