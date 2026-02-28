package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
)

func TestAwsVaultSection(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	
	configContent := `[default]
region = us-east-1

[aws-vault]
redact_secrets = true

[profile test]
region = us-west-2
`
	
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load the config file
	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	// Test that the aws-vault section is parsed correctly
	awsVaultSection, ok := configFile.AwsVaultSection()
	if !ok {
		t.Fatal("Expected to find [aws-vault] section")
	}

	if !awsVaultSection.RedactSecrets {
		t.Error("Expected redact_secrets to be true")
	}

	if awsVaultSection.Name != "aws-vault" {
		t.Errorf("Expected section name to be 'aws-vault', got %q", awsVaultSection.Name)
	}
}

func TestAwsVaultSectionMissing(t *testing.T) {
	// Create a temporary config file without [aws-vault] section
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	
	configContent := `[default]
region = us-east-1

[profile test]
region = us-west-2
`
	
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load the config file
	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	// Test that the aws-vault section is not found
	awsVaultSection, ok := configFile.AwsVaultSection()
	if ok {
		t.Fatal("Expected not to find [aws-vault] section")
	}

	// Should return default values
	if awsVaultSection.RedactSecrets {
		t.Error("Expected redact_secrets to be false by default")
	}
}

func TestAwsVaultSectionRedactSecretsFalse(t *testing.T) {
	// Create a temporary config file with redact_secrets = false
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	
	configContent := `[default]
region = us-east-1

[aws-vault]
redact_secrets = false

[profile test]
region = us-west-2
`
	
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load the config file
	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	// Test that the aws-vault section is parsed correctly
	awsVaultSection, ok := configFile.AwsVaultSection()
	if !ok {
		t.Fatal("Expected to find [aws-vault] section")
	}

	if awsVaultSection.RedactSecrets {
		t.Error("Expected redact_secrets to be false")
	}
}
