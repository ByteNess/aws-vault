package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/cli"
)

var (
	// Version is provided at compile time
	Version = "dev"
	// Commit is provided at compile time
	Commit = ""
	// Date is the build timestamp, provided at compile time (RFC3339)
	Date = ""
	// BuiltBy identifies the tool/pipeline that produced the binary
	BuiltBy = ""
)

func main() {
	app := kingpin.New("aws-vault", "A vault for securely storing and accessing AWS credentials in development environments.")
	versionInfo := fmt.Sprintf("%s", Version)
	//versionInfo := fmt.Sprintf("%s\ngo: %s", Version, runtime.Version())
	app.Version(versionInfo)
	app.VersionFlag.Short('v')

	a := cli.ConfigureGlobals(app)
	cli.ConfigureAddCommand(app, a)
	cli.ConfigureRemoveCommand(app, a)
	cli.ConfigureListCommand(app, a)
	cli.ConfigureRotateCommand(app, a)
	cli.ConfigureExecCommand(app, a)
	cli.ConfigureExportCommand(app, a)
	cli.ConfigureClearCommand(app, a)
	cli.ConfigureLoginCommand(app, a)
	cli.ConfigureProxyCommand(app)
	cli.ConfigureVersionCommand(app, versionInfo)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
