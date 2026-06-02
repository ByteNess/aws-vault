package cli

import (
	"testing"

	"github.com/byteness/keyring"
)

func TestKeyringLockKey(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		config  keyring.Config
		want    string
	}{
		// Keychain backend
		{
			name:    "keychain with keychain name",
			backend: "keychain",
			config:  keyring.Config{KeychainName: "my-keychain"},
			want:    "keychain:my-keychain",
		},
		{
			name:    "keychain with empty keychain name",
			backend: "keychain",
			config:  keyring.Config{},
			want:    "keychain",
		},

		// File backend
		{
			name:    "file with file dir",
			backend: "file",
			config:  keyring.Config{FileDir: "/tmp/keys"},
			want:    "file:/tmp/keys",
		},
		{
			name:    "file with empty file dir",
			backend: "file",
			config:  keyring.Config{},
			want:    "file",
		},

		// Pass backend: dir and prefix combinations
		{
			name:    "pass with dir and prefix",
			backend: "pass",
			config:  keyring.Config{PassDir: "/store", PassPrefix: "aws"},
			want:    "pass:/store:aws",
		},
		{
			name:    "pass with dir only",
			backend: "pass",
			config:  keyring.Config{PassDir: "/store"},
			want:    "pass:/store",
		},
		{
			name:    "pass with prefix only",
			backend: "pass",
			config:  keyring.Config{PassPrefix: "aws"},
			want:    "pass:aws",
		},
		{
			name:    "pass with neither dir nor prefix",
			backend: "pass",
			config:  keyring.Config{},
			want:    "pass",
		},

		// Secret-service backend
		{
			name:    "secret-service with collection name",
			backend: "secret-service",
			config:  keyring.Config{LibSecretCollectionName: "awsvault"},
			want:    "secret-service:awsvault",
		},
		{
			name:    "secret-service with empty collection name",
			backend: "secret-service",
			config:  keyring.Config{},
			want:    "secret-service",
		},

		// KWallet backend
		{
			name:    "kwallet with folder",
			backend: "kwallet",
			config:  keyring.Config{KWalletFolder: "aws-vault"},
			want:    "kwallet:aws-vault",
		},
		{
			name:    "kwallet with empty folder",
			backend: "kwallet",
			config:  keyring.Config{},
			want:    "kwallet",
		},

		// WinCred backend
		{
			name:    "wincred with prefix",
			backend: "wincred",
			config:  keyring.Config{WinCredPrefix: "aws-vault"},
			want:    "wincred:aws-vault",
		},
		{
			name:    "wincred with empty prefix",
			backend: "wincred",
			config:  keyring.Config{},
			want:    "wincred",
		},

		// 1Password backends (all share OPVaultID)
		{
			name:    "op with vault ID",
			backend: "op",
			config:  keyring.Config{OPVaultID: "vault-123"},
			want:    "op:vault-123",
		},
		{
			name:    "op with empty vault ID",
			backend: "op",
			config:  keyring.Config{},
			want:    "op",
		},
		{
			name:    "op-connect with vault ID",
			backend: "op-connect",
			config:  keyring.Config{OPVaultID: "vault-456"},
			want:    "op-connect:vault-456",
		},
		{
			name:    "op-connect with empty vault ID",
			backend: "op-connect",
			config:  keyring.Config{},
			want:    "op-connect",
		},
		{
			name:    "op-desktop with vault ID",
			backend: "op-desktop",
			config:  keyring.Config{OPVaultID: "vault-789"},
			want:    "op-desktop:vault-789",
		},
		{
			name:    "op-desktop with empty vault ID",
			backend: "op-desktop",
			config:  keyring.Config{},
			want:    "op-desktop",
		},

		// Fallback cases
		{
			name:    "unknown backend falls back to backend name",
			backend: "some-unknown-backend",
			config:  keyring.Config{},
			want:    "some-unknown-backend",
		},
		{
			name:    "empty backend falls back to aws-vault",
			backend: "",
			config:  keyring.Config{},
			want:    "aws-vault",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AwsVault{
				KeyringBackend: tt.backend,
				KeyringConfig:  tt.config,
			}
			got := a.keyringLockKey()
			if got != tt.want {
				t.Errorf("keyringLockKey() = %q, want %q", got, tt.want)
			}
		})
	}
}
