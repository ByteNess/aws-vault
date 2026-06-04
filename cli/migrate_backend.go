package cli

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
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

	return fmt.Errorf("not implemented")
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
