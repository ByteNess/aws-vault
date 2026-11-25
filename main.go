// aws-vault securely stores AWS credentials and provides temporary ones to
// commands and applications.
package main

import (
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
	versionInfo := Version
	//versionInfo := fmt.Sprintf("%s\ngo: %s", Version, runtime.Version())
	app.Version(versionInfo)
	app.VersionFlag.Short('v')

	cli.ConfigureCommands(app, cli.ConfigureGlobals(app), versionInfo)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
