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

	summary := migrateBackendSummary{}
	for _, profile := range profiles {
		fmt.Printf("Migrating %s... ", profile)
		result, err := migrateOneCredential(profile, srcCreds, dstCreds, input.Overwrite)
		if err != nil {
			fmt.Printf("failed: %v\n", err)
			fmt.Println("Migration stopped. Source credentials were not deleted for the failed profile.")
			return err
		}
		message := result.Message
		summary.Add(result)
		if input.DeleteSource && result.Migrated {
			if err := srcCreds.Remove(profile); err != nil {
				fmt.Printf("failed: %v\n", err)
				return fmt.Errorf("delete source profile %q: %w", profile, err)
			}
			message += ", deleted source"
			summary.Deleted++
		}
		fmt.Println(message)
	}
	printMigrateBackendSummary(summary)

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

type migrateCredentialResult struct {
	Message  string
	Migrated bool
	Outcome  migrateCredentialOutcome
}

type migrateCredentialOutcome string

const (
	migrateCredentialCopied      migrateCredentialOutcome = "copied"
	migrateCredentialOverwritten migrateCredentialOutcome = "overwritten"
	migrateCredentialSkipped     migrateCredentialOutcome = "skipped"
)

type migrateBackendSummary struct {
	Copied      int
	Overwritten int
	Skipped     int
	Deleted     int
}

func (s *migrateBackendSummary) Add(result migrateCredentialResult) {
	switch result.Outcome {
	case migrateCredentialCopied:
		s.Copied++
	case migrateCredentialOverwritten:
		s.Overwritten++
	case migrateCredentialSkipped:
		s.Skipped++
	}
}

func printMigrateBackendSummary(summary migrateBackendSummary) {
	fmt.Println()
	fmt.Println("Migration summary:")
	fmt.Printf("  copied: %d\n", summary.Copied)
	fmt.Printf("  overwritten: %d\n", summary.Overwritten)
	fmt.Printf("  skipped: %d\n", summary.Skipped)
	fmt.Printf("  deleted from source: %d\n", summary.Deleted)
}

func migrateOneCredential(profile string, src *vault.CredentialKeyring, dst *vault.CredentialKeyring, overwrite bool) (migrateCredentialResult, error) {
	exists, err := dst.Has(profile)
	if err != nil {
		return migrateCredentialResult{}, fmt.Errorf("check destination profile %q: %w", profile, err)
	}
	if exists && !overwrite {
		return migrateCredentialResult{Message: "skipped, already exists in destination", Outcome: migrateCredentialSkipped}, nil
	}

	creds, err := src.Get(profile)
	if err != nil {
		return migrateCredentialResult{}, fmt.Errorf("read source profile %q: %w", profile, err)
	}
	if err := dst.Set(profile, creds); err != nil {
		return migrateCredentialResult{}, fmt.Errorf("write destination profile %q: %w", profile, err)
	}
	got, err := dst.Get(profile)
	if err != nil {
		return migrateCredentialResult{}, fmt.Errorf("verify destination profile %q: %w", profile, err)
	}
	if got.AccessKeyID != creds.AccessKeyID ||
		got.SecretAccessKey != creds.SecretAccessKey ||
		got.SessionToken != creds.SessionToken {
		return migrateCredentialResult{}, fmt.Errorf("verify destination profile %q: credential mismatch", profile)
	}

	if exists {
		return migrateCredentialResult{Message: "overwritten, verified", Migrated: true, Outcome: migrateCredentialOverwritten}, nil
	}
	return migrateCredentialResult{Message: "copied, verified", Migrated: true, Outcome: migrateCredentialCopied}, nil
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
