package cli

import (
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func TestValidateMigrateBackendInput(t *testing.T) {
	backends := keyring.AvailableBackends()
	if len(backends) == 0 {
		t.Fatal("expected at least one available keyring backend")
	}

	err := validateMigrateBackendInput(MigrateBackendCommandInput{
		FromBackend: string(backends[0]),
		ToBackend:   string(backends[0]),
	})
	if err == nil {
		t.Fatal("expected same backend validation error")
	}

	err = validateMigrateBackendInput(MigrateBackendCommandInput{
		FromBackend: "does-not-exist",
		ToBackend:   string(backends[0]),
	})
	if err == nil {
		t.Fatal("expected unavailable source backend validation error")
	}
}

func TestMigrationProfilesFiltersSessionsAndOIDCTokens(t *testing.T) {
	src := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring([]keyring.Item{
		{Key: "dev"},
		{Key: "prod"},
		{Key: "oidc:https://example.com/start"},
		{Key: "session,ZGV2,,9999999999"},
		{Key: "dev session (61633665646639303539)"},
	})}

	profiles, err := migrationProfiles(src, "")
	if err != nil {
		t.Fatal(err)
	}

	if want := []string{"dev", "prod"}; !slices.Equal(profiles, want) {
		t.Fatalf("profiles = %v, want %v", profiles, want)
	}
}

func TestMigrationProfilesExplicitMissingProfile(t *testing.T) {
	src := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring(nil)}

	_, err := migrationProfiles(src, "missing")
	if err == nil {
		t.Fatal("expected missing profile error")
	}
}

func TestMigrateOneCredentialSkipsExistingWithoutOverwrite(t *testing.T) {
	src := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring(nil)}
	dst := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring(nil)}
	mustSetDevCredential(t, src, aws.Credentials{AccessKeyID: "SRC", SecretAccessKey: "source"})
	mustSetDevCredential(t, dst, aws.Credentials{AccessKeyID: "DST", SecretAccessKey: "destination"})

	result, err := migrateOneCredential("dev", src, dst, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != migrateCredentialSkipped || result.Migrated {
		t.Fatalf("result = %#v, want skipped without migration", result)
	}

	got, err := dst.Get("dev")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessKeyID != "DST" {
		t.Fatalf("destination AccessKeyID = %q, want original DST", got.AccessKeyID)
	}
}

func TestMigrateBackendProfilesOverwritesAndDeletesSource(t *testing.T) {
	src := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring(nil)}
	dst := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring(nil)}
	want := aws.Credentials{AccessKeyID: "SRC", SecretAccessKey: "source"}
	mustSetDevCredential(t, src, want)
	mustSetDevCredential(t, dst, aws.Credentials{AccessKeyID: "DST", SecretAccessKey: "destination"})

	summary, err := migrateBackendProfiles(
		MigrateBackendCommandInput{Overwrite: true, DeleteSource: true},
		[]string{"dev"},
		src,
		dst,
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Overwritten != 1 || summary.Deleted != 1 || summary.Copied != 0 || summary.Skipped != 0 {
		t.Fatalf("summary = %#v, want one overwritten and deleted", summary)
	}

	if ok, err := src.Has("dev"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("source profile still exists after verified delete-source migration")
	}
	got, err := dst.Get("dev")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessKeyID != want.AccessKeyID || got.SecretAccessKey != want.SecretAccessKey {
		t.Fatalf("destination credentials = %#v, want %#v", got, want)
	}
}

func TestMigrateBackendProfilesVerificationFailureDoesNotDeleteSource(t *testing.T) {
	src := &vault.CredentialKeyring{Keyring: keyring.NewArrayKeyring(nil)}
	dst := &vault.CredentialKeyring{Keyring: corruptingGetKeyring{Keyring: keyring.NewArrayKeyring(nil)}}
	mustSetDevCredential(t, src, aws.Credentials{AccessKeyID: "SRC", SecretAccessKey: "source"})

	_, err := migrateBackendProfiles(
		MigrateBackendCommandInput{DeleteSource: true},
		[]string{"dev"},
		src,
		dst,
	)
	if err == nil {
		t.Fatal("expected verification failure")
	}

	if ok, err := src.Has("dev"); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("source profile was deleted after verification failure")
	}
}

type corruptingGetKeyring struct {
	keyring.Keyring
}

func (k corruptingGetKeyring) Get(key string) (keyring.Item, error) {
	item, err := k.Keyring.Get(key)
	if err != nil {
		return item, err
	}
	item.Data = []byte(`{"AccessKeyID":"CORRUPTED","SecretAccessKey":"corrupted"}`)
	return item, nil
}

func mustSetDevCredential(t *testing.T, ckr *vault.CredentialKeyring, creds aws.Credentials) {
	t.Helper()
	if err := ckr.Set("dev", creds); err != nil {
		t.Fatal(err)
	}
}
