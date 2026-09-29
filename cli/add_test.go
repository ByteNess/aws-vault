package cli

import (
	"log"
	"os"

	"github.com/alecthomas/kingpin/v2"
)

func Example_addCommand() {
	configFile, removeConfig := exampleConfigFile("")
	defer removeConfig()

	fileDir, err := os.MkdirTemp("", "aws-vault-file-backend")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(fileDir) }()

	defer setExampleEnv(
		"AWS_CONFIG_FILE", configFile,
		"AWS_ACCESS_KEY_ID", "llamas",
		"AWS_SECRET_ACCESS_KEY", "rock",
		"AWS_VAULT_BACKEND", "file",
		"AWS_VAULT_FILE_DIR", fileDir,
		"AWS_VAULT_FILE_PASSPHRASE", "password",
	)()

	app := kingpin.New(`aws-vault`, ``)
	ConfigureAddCommand(app, ConfigureGlobals(app))
	kingpin.MustParse(app.Parse([]string{"add", "--debug", "--env", "foo"}))

	// Output:
	// Added credentials to profile "foo" in vault
}
