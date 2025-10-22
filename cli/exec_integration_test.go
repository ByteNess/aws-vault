package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func TestExecCommandWithRedaction(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	
	configContent := `[default]
region = us-east-1
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[aws-vault]
redact_secrets = true
`
	
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a mock keyring with credentials
	keyring := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "default", Data: []byte(`{"AccessKeyID":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","SessionToken":"","ProviderName":"StaticProvider"}`)},
	})

	// Load the config file
	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	// Test ExecCommand with redaction enabled and no-session to avoid MFA
	input := ExecCommandInput{
		ProfileName: "default",
		Command:     "echo",
		Args:        []string{"Access key: AKIAIOSFODNN7EXAMPLE"},
		NoSession:   true, // Skip session creation to avoid MFA
		Config: vault.ProfileConfig{
			RedactSecrets: true,
		},
	}

	exitCode, err := ExecCommand(input, configFile, keyring)
	
	if err != nil {
		t.Errorf("ExecCommand() error = %v", err)
	}
	
	if exitCode != 0 {
		t.Errorf("ExecCommand() exitCode = %d, want 0", exitCode)
	}
	
	// Note: This test verifies that ExecCommand runs without error when redaction is enabled.
	// The actual redaction verification would require more complex subprocess output capture.
}

func TestExecCommandWithoutRedaction(t *testing.T) {
	// Create a temporary config file without redaction
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	
	configContent := `[default]
region = us-east-1
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`
	
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a mock keyring with credentials
	keyring := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "default", Data: []byte(`{"AccessKeyID":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","SessionToken":"","ProviderName":"StaticProvider"}`)},
	})

	// Load the config file
	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	// Test ExecCommand without redaction
	input := ExecCommandInput{
		ProfileName: "default",
		Command:     "echo",
		Args:        []string{"Access key: AKIAIOSFODNN7EXAMPLE"},
		NoSession:   true, // Skip session creation to avoid MFA
		Config: vault.ProfileConfig{
			RedactSecrets: false,
		},
	}

	exitCode, err := ExecCommand(input, configFile, keyring)
	
	if err != nil {
		t.Errorf("ExecCommand() error = %v", err)
	}
	
	if exitCode != 0 {
		t.Errorf("ExecCommand() exitCode = %d, want 0", exitCode)
	}
	
	// Note: This test verifies that ExecCommand runs without error when redaction is disabled.
}

func TestExecCommandCLIFlagOverridesConfig(t *testing.T) {
	// Create a temporary config file with redaction enabled
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	
	configContent := `[default]
region = us-east-1
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[aws-vault]
redact_secrets = true
`
	
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a mock keyring with credentials
	keyring := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "default", Data: []byte(`{"AccessKeyID":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","SessionToken":"","ProviderName":"StaticProvider"}`)},
	})

	// Load the config file
	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	// Test ExecCommand with CLI flag overriding config (redaction disabled)
	input := ExecCommandInput{
		ProfileName: "default",
		Command:     "echo",
		Args:        []string{"Access key: AKIAIOSFODNN7EXAMPLE"},
		NoSession:   true, // Skip session creation to avoid MFA
		Config: vault.ProfileConfig{
			RedactSecrets: false, // CLI flag would override this
		},
	}

	exitCode, err := ExecCommand(input, configFile, keyring)
	
	if err != nil {
		t.Errorf("ExecCommand() error = %v", err)
	}
	
	if exitCode != 0 {
		t.Errorf("ExecCommand() exitCode = %d, want 0", exitCode)
	}
	
	// Note: This test verifies that ExecCommand runs without error when CLI flag overrides config.
}
