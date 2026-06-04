package cli

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

type MigrateBackendCommandInput struct {
	FromBackend  string
	ToBackend    string
	ProfileName  string
	DryRun       bool
	Overwrite    bool
	DeleteSource bool
}

func ConfigureMigrateBackendCommand(app *kingpin.Application, a *AwsVault) {
	input := MigrateBackendCommandInput{}

	cmd := app.Command("migrate-backend", "Migrate stored credentials between keyring backends.")

	cmd.Flag("from", "Source keyring backend.").
		Required().
		StringVar(&input.FromBackend)

	cmd.Flag("to", "Destination keyring backend.").
		Required().
		StringVar(&input.ToBackend)

	cmd.Flag("profile", "Migrate only this profile.").
		StringVar(&input.ProfileName)

	cmd.Flag("dry-run", "Show what would be migrated without writing anything.").
		BoolVar(&input.DryRun)

	cmd.Flag("overwrite", "Overwrite destination credentials if they already exist.").
		BoolVar(&input.Overwrite)

	cmd.Flag("delete-source", "Delete source credentials after successful destination verification.").
		BoolVar(&input.DeleteSource)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := MigrateBackendCommand(input, a.KeyringConfig)
		app.FatalIfError(err, "migrate-backend")
		return nil
	})
}

func MigrateBackendCommand(input MigrateBackendCommandInput, cfg keyring.Config) error {
	if err := validateMigrateBackendInput(input); err != nil {
		return err
	}

	src, err := openSpecificBackend(cfg, input.FromBackend)
	if err != nil {
		return fmt.Errorf("open source backend %q: %w", input.FromBackend, err)
	}
	srcCreds := &vault.CredentialKeyring{Keyring: src}

	profiles, err := migrationProfiles(srcCreds, input.ProfileName)
	if err != nil {
		return err
	}

	if input.DryRun {
		printMigrateBackendDryRun(input, profiles)
		return nil
	}

	if len(profiles) == 0 {
		fmt.Printf("No credentials found in source backend %s.\n", input.FromBackend)
		return nil
	}

	dst, err := openSpecificBackend(cfg, input.ToBackend)
	if err != nil {
		return fmt.Errorf("open destination backend %q: %w", input.ToBackend, err)
	}
	dstCreds := &vault.CredentialKeyring{Keyring: dst}

	for _, profile := range profiles {
		fmt.Printf("Migrating %s... ", profile)
		result, err := migrateOneCredential(profile, srcCreds, dstCreds, input.Overwrite)
		if err != nil {
			fmt.Printf("failed: %v\n", err)
			return err
		}
		fmt.Println(result)
	}

	return nil
}

func printMigrateBackendDryRun(input MigrateBackendCommandInput, profiles []string) {
	if len(profiles) == 0 {
		fmt.Printf("No credentials found in source backend %s.\n", input.FromBackend)
		return
	}

	fmt.Printf("Would migrate %d credential profile(s) from %s to %s:\n", len(profiles), input.FromBackend, input.ToBackend)
	for _, profile := range profiles {
		fmt.Printf("  %s\n", profile)
	}
	fmt.Println()
	fmt.Println("No changes made.")
}

func migrateOneCredential(profile string, src *vault.CredentialKeyring, dst *vault.CredentialKeyring, overwrite bool) (string, error) {
	exists, err := dst.Has(profile)
	if err != nil {
		return "", fmt.Errorf("check destination profile %q: %w", profile, err)
	}
	if exists && !overwrite {
		return "skipped, already exists in destination", nil
	}

	creds, err := src.Get(profile)
	if err != nil {
		return "", fmt.Errorf("read source profile %q: %w", profile, err)
	}
	if err := dst.Set(profile, creds); err != nil {
		return "", fmt.Errorf("write destination profile %q: %w", profile, err)
	}
	got, err := dst.Get(profile)
	if err != nil {
		return "", fmt.Errorf("verify destination profile %q: %w", profile, err)
	}
	if got.AccessKeyID != creds.AccessKeyID ||
		got.SecretAccessKey != creds.SecretAccessKey ||
		got.SessionToken != creds.SessionToken {
		return "", fmt.Errorf("verify destination profile %q: credential mismatch", profile)
	}

	if exists {
		return "overwritten, verified", nil
	}
	return "copied, verified", nil
}

func migrationProfiles(src *vault.CredentialKeyring, profile string) ([]string, error) {
	if profile != "" {
		ok, err := src.Has(profile)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("profile %q not found in source backend", profile)
		}
		return []string{profile}, nil
	}

	profiles, err := src.Keys()
	if err != nil {
		return nil, err
	}
	return profiles, nil
}

func validateMigrateBackendInput(input MigrateBackendCommandInput) error {
	if !backendAvailable(input.FromBackend) {
		return fmt.Errorf("source backend %q is not available", input.FromBackend)
	}
	if !backendAvailable(input.ToBackend) {
		return fmt.Errorf("destination backend %q is not available", input.ToBackend)
	}
	if input.FromBackend == input.ToBackend {
		return fmt.Errorf("source and destination backends must differ")
	}
	return nil
}

func backendAvailable(name string) bool {
	for _, backend := range keyring.AvailableBackends() {
		if string(backend) == name {
			return true
		}
	}
	return false
}

func openSpecificBackend(cfg keyring.Config, backendName string) (keyring.Keyring, error) {
	cfg.AllowedBackends = []keyring.BackendType{keyring.BackendType(backendName)}
	return keyring.Open(cfg)
}
