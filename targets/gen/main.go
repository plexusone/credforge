// Command gen writes the targets file's JSON Schema into the targets
// package. Run it with go generate from the targets directory.
package main

import (
	"fmt"
	"os"

	oscfs "github.com/grokify/oscompat/fs"

	"github.com/plexusone/credforge/targets"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	s, err := targets.GenerateSchema("..")
	if err != nil {
		return err
	}
	return oscfs.WriteFile(targets.SchemaFile, s, oscfs.DefaultFilePerm)
}
