// Command gen writes the reviews file's JSON Schema into the review
// package. Run it with go generate from the review directory.
package main

import (
	"fmt"
	"os"

	oscfs "github.com/grokify/oscompat/fs"

	"github.com/plexusone/credforge/review"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	s, err := review.GenerateSchema("..")
	if err != nil {
		return err
	}
	return oscfs.WriteFile(review.SchemaFile, s, oscfs.DefaultFilePerm)
}
