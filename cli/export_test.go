package cli

import (
	"github.com/alecthomas/kingpin/v2"

	"github.com/byteness/keyring"
)

func Example_exportCommand() {
	configFile, removeConfig := exampleConfigFile("")
	defer removeConfig()
	defer setExampleEnv("AWS_CONFIG_FILE", configFile)()

	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.rawKeyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureExportCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"export", "--format=ini", "--no-session", "llamas",
	}))

	// Output:
	// [llamas]
	// aws_access_key_id=ABC
	// aws_secret_access_key=XYZ
}

func Example_exportCommandAccountID() {
	configFile, removeConfig := exampleConfigFile("[profile llamas]\naws_account_id=123456789012\n")
	defer removeConfig()
	defer setExampleEnv("AWS_CONFIG_FILE", configFile)()

	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureExportCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"export", "--format=env", "--no-session", "llamas",
	}))

	// Output:
	// AWS_ACCESS_KEY_ID=ABC
	// AWS_SECRET_ACCESS_KEY=XYZ
	// AWS_ACCOUNT_ID=123456789012
}
