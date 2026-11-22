package cli

import (
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/plexusone/systemspec-credential/credspec"
	"github.com/spf13/cobra"

	"github.com/plexusone/credforge"
)

// Generate returns the generate command alone, with the same file flags as
// Check, for a host tool's own command tree. Use and Short are ignored.
func Generate(o Options) *cobra.Command {
	e := &env{opts: o.withDefaults()}
	cmd := e.generate()
	e.flags(cmd.Flags())
	return cmd
}

func (e *env) generate() *cobra.Command {
	var only, by string
	var includePlanned, dryRun, yes bool
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Make the random values and keys the registry describes, where no store holds one, and record them",
		Long: "generate makes each credential whose generation.format is set and whose provisioner is credforge\n" +
			"generate, or none: a random value (hex32, base64url32) or a private key (p256-pem, ed25519-pem,\n" +
			"rsa3072-pem), in memory with crypto/rand. It writes the value to every primary store, and records\n" +
			"a created event. It never prints a value.\n\n" +
			"It finds what is missing with a check, which reads names, never values. A credential is made only\n" +
			"when none of its primary stores holds a value, and a parameter store is written only if the\n" +
			"parameter still does not exist, so generate never replaces a value. A credential some of whose\n" +
			"stores hold a value is listed and left. It lists what it will make and asks first.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if _, err := path.Match(only, ""); err != nil {
				return &ExitCodeError{Code: ExitError, Err: fmt.Errorf("--only: %w", err)}
			}
			reg, log, tf, err := e.load()
			if err != nil {
				return err
			}
			// Only the stores of the credentials it makes are listed; the
			// extra repositories a check scans are not.
			g := &credforge.Generator{Checker: &credforge.Checker{Connector: e.opts.Connector(tf)}, Writer: e.opts.Writer(tf)}
			o := credforge.Options{IncludePlanned: includePlanned, Grace: credforge.DefaultGrace}
			if only != "" {
				o.Only = func(cr credspec.Credential) bool {
					ok, err := path.Match(only, cr.ID)
					return err == nil && ok
				}
			}
			plan, err := g.Plan(c.Context(), reg, log, o)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if err := writeGeneratePlan(out, plan); err != nil {
				return err
			}
			n := len(plan.Make())
			if dryRun || n == 0 {
				return nil
			}
			if !yes {
				ok, err := confirm(c.InOrStdin(), c.ErrOrStderr(), fmt.Sprintf("Make %d value(s)? [y/N] ", n))
				if err != nil {
					return err
				}
				if !ok {
					_, err := fmt.Fprintln(out, "nothing made")
					return err
				}
			}
			results, applyErr := g.Apply(c.Context(), reg, log, plan, by)
			recorded := 0
			for _, r := range results {
				if r.Event != nil {
					recorded++
				}
			}
			if recorded > 0 {
				if err := log.Save(e.events); err != nil {
					return errors.Join(applyErr, fmt.Errorf("generate: the values were written, but saving %s failed: %w", e.events, err))
				}
			}
			if err := writeGenerated(out, results, e.events); err != nil {
				return errors.Join(applyErr, err)
			}
			return applyErr
		},
	}
	f := cmd.Flags()
	f.StringVar(&only, "only", "", "make only credentials whose ID matches this pattern, such as 'app/prod/*'")
	f.BoolVar(&includePlanned, "include-planned", false, "also make planned credentials, for an environment being brought up")
	f.BoolVar(&dryRun, "dry-run", false, "list what would be made and stop")
	f.BoolVar(&yes, "yes", false, "make without asking")
	f.StringVar(&by, "by", "operator", "who generates, for the events")
	return cmd
}

func writeGeneratePlan(w io.Writer, p credforge.GeneratePlan) error {
	var lines []string
	for _, g := range p.Generations {
		if len(g.Writes) == 0 {
			lines = append(lines, fmt.Sprintf("leave  %s: %s", g.Credential, g.Skip))
			continue
		}
		stores := make([]string, len(g.Writes))
		for i, d := range g.Writes {
			stores[i] = d.Store.String()
		}
		lines = append(lines, fmt.Sprintf("make   %s (%s) in %s", g.Credential, g.Format, strings.Join(stores, ", ")))
	}
	if len(lines) == 0 {
		lines = append(lines, "no credential in the registry is made by generate")
	}
	_, err := fmt.Fprintln(w, strings.Join(lines, "\n"))
	return err
}

func writeGenerated(w io.Writer, results []credforge.GenerateResult, events string) error {
	var lines []string
	for _, r := range results {
		if r.Event == nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("made   %s; recorded created in %s", r.Credential, events))
	}
	if len(lines) == 0 {
		return nil
	}
	_, err := fmt.Fprintln(w, strings.Join(lines, "\n"))
	return err
}
