package cli

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
)

func ConfigureVersionCommand(app *kingpin.Application, versionInfo string) {
	cmd := app.Command("version", "Print the aws-vault version and build info.")
	cmd.Action(func(c *kingpin.ParseContext) error {
		fmt.Println(versionInfo)
		return nil
	})
}
