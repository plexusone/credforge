package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/plexusone/systemspec-credential/credspec"
	runbookcli "github.com/plexusone/systemspec-runbook/cli"
	rb "github.com/plexusone/systemspec-runbook/runbookspec"
	"github.com/spf13/cobra"

	"github.com/plexusone/credforge/runbook"
)

// Setup returns the setup command alone, with the same file flags as
// Check, for a host tool's own command tree. Use and Short are ignored.
func Setup(o Options) *cobra.Command {
	e := &env{opts: o.withDefaults()}
	cmd := e.setup()
	e.flags(cmd.PersistentFlags())
	return cmd
}

// tool is how the runbook's commands run credforge: the host's command,
// or credforge with the file flags this run was given.
func (e *env) tool() []string {
	if e.opts.Tool != nil {
		return e.opts.Tool()
	}
	out := []string{"credforge"}
	if e.opts.Registry == nil {
		out = append(out, "--registry", e.registry)
	}
	out = append(out, "--events", e.events)
	if e.opts.Targets == nil {
		out = append(out, "--targets", e.targets)
	}
	return out
}

func (e *env) setup() *cobra.Command {
	var system, environment, needs string
	parseNeeds := func() ([]credspec.Need, error) {
		var out []credspec.Need
		for _, n := range strings.Split(needs, ",") {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			need := credspec.Need(n)
			ok := false
			for _, v := range credspec.Needs() {
				ok = ok || v == need
			}
			if !ok || need == credspec.NeedRotation {
				return nil, fmt.Errorf("setup: --need %q is not launch, later or optional", n)
			}
			out = append(out, need)
		}
		return out, nil
	}
	build := func() (*rb.Runbook, error) {
		if system == "" {
			return nil, errors.New("setup: name the system with --system")
		}
		ns, err := parseNeeds()
		if err != nil {
			return nil, err
		}
		reg, err := e.loadRegistry()
		if err != nil {
			return nil, err
		}
		return runbook.Build(reg, runbook.Options{System: system, Environment: environment, Needs: ns, Tool: e.tool()})
	}
	cmd := runbookcli.New(runbookcli.Options{
		Use: "setup",
		Short: "Set up a system's credentials step by step: a runbook built from the registry, " +
			"run, checked and recorded with systemspec-runbook",
		Load:       build,
		EventsFlag: "progress",
	})
	cmd.Long = "setup builds a runbook from the registry for one system's credentials: what is set up at issuers\n" +
		"first, what tools make, and what a person gets from an issuer and installs, in setup order. Its\n" +
		"commands list, show, run and verify the steps; each step is checked with credforge check, which reads\n" +
		"names and never values. The steps' progress is kept in its own log beside the event log, named for\n" +
		"the system and environment, such as setup-example-app-prod.json, unless --progress names another."
	pf := cmd.PersistentFlags()
	pf.StringVar(&system, "system", "", "the system whose credentials to set up")
	pf.StringVar(&environment, "env", "", "the environment, such as prod; with the credentials that serve every environment")
	pf.StringVar(&needs, "need", "launch", "the needs to include: launch, later and optional, comma-separated")
	// The progress log's default is named for the system and environment,
	// beside the credential event log, once the flags are parsed.
	cmd.PersistentPreRunE = func(c *cobra.Command, args []string) error {
		// Cobra runs only the nearest hook, so a host's own runs first.
		for p := cmd.Parent(); p != nil; p = p.Parent() {
			if p.PersistentPreRunE != nil {
				if err := p.PersistentPreRunE(c, args); err != nil {
					return err
				}
				break
			}
		}
		fl := c.Flags().Lookup("progress")
		if fl == nil || fl.Changed {
			return nil
		}
		name := "setup-" + strings.Trim(strings.Join([]string{system, environment}, "-"), "-") + ".json"
		return fl.Value.Set(filepath.Join(filepath.Dir(e.events), name))
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "export",
		Short: "Write the runbook as JSON, for runbookspec or another tool",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			r, err := build()
			if err != nil {
				return err
			}
			b, err := json.MarshalIndent(r, "", "  ")
			if err != nil {
				return err
			}
			_, err = c.OutOrStdout().Write(append(b, '\n'))
			return err
		},
	})
	return cmd
}
