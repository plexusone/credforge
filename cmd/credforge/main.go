// Command credforge compares a credential registry with the stores and
// workflows it names, without reading any value. It reads the registry,
// the event log and the targets file as JSON files.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/plexusone/credforge/cli"
)

func main() {
	err := cli.New(cli.Options{}).ExecuteContext(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "credforge:", err)
	}
	os.Exit(cli.Code(err))
}
