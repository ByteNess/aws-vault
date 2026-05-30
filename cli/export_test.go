package cli

import (
	"log"
	"os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/byteness/keyring"
)

func ExampleExportCommand() {
	f, err := os.CreateTemp("", "aws-config")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name())

	if _, err = f.WriteString("[profile llamas]\nregion = us-east-1\n"); err != nil {
		log.Fatal(err)
	}
	f.Close()

	os.Setenv("AWS_CONFIG_FILE", f.Name())
	defer os.Unsetenv("AWS_CONFIG_FILE")

	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
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
