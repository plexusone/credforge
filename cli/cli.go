// Package cli is credforge's command line, as a Cobra command a host tool
// can mount over a registry it builds itself.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/awsssm"
	"github.com/plexusone/credforge/github"
	"github.com/plexusone/credforge/targets"
)

// Exit codes.
const (
	// ExitFindings is a check that found something in a --fail-on state.
	ExitFindings = 1
	// ExitError is a usage, file or connection error.
	ExitError = 2
)

// ExitCodeError carries the process exit code for an error.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string { return e.Err.Error() }
func (e *ExitCodeError) Unwrap() error { return e.Err }

// Code returns the exit code for err: 0 for nil, the code an ExitCodeError
// carries, and ExitError otherwise.
func Code(err error) int {
	if err == nil {
		return 0
	}
	var ec *ExitCodeError
	if errors.As(err, &ec) {
		return ec.Code
	}
	return ExitError
}

// Options configure the command.
type Options struct {
	// Use is the command's name, such as "credforge" or, when mounted,
	// "observe".
	Use string
	// Short is the one-line help.
	Short string
	// Registry builds the registry. When nil, the command reads the JSON
	// file named by --registry.
	Registry func() (*credspec.Registry, error)
	// RegistryPath is --registry's default when Registry is nil.
	RegistryPath string
	// EventsPath is --events's default.
	EventsPath string
	// Targets builds the targets file. When nil, the command reads the
	// file named by --targets.
	Targets func() (*targets.File, error)
	// TargetsPath is --targets's default when Targets is nil.
	TargetsPath string
	// Connector replaces the connections the targets file describes; tests
	// set it.
	Connector func(*targets.File) credforge.Connector
}

type env struct {
	opts     Options
	registry string
	events   string
	targets  string
}

// New returns the command tree: check and schema.
func New(o Options) *cobra.Command {
	if o.Use == "" {
		o.Use = "credforge"
	}
	if o.Short == "" {
		o.Short = "Compare a credential registry with the stores and workflows it names, without reading any value"
	}
	e := &env{opts: o.withDefaults()}
	cmd := &cobra.Command{Use: o.Use, Short: o.Short, SilenceUsage: true, SilenceErrors: true}
	e.flags(cmd.PersistentFlags())
	cmd.AddCommand(e.check(), e.schema())
	return cmd
}

// Check returns the check command alone, with its own --registry (when
// Options.Registry is nil), --events and --targets (when Options.Targets
// is nil) flags, for a host tool to add to a command tree of its own, such
// as beside systemspec-credential's commands. Its flags take precedence
// over a parent's flags of the same names. Use and Short are ignored.
func Check(o Options) *cobra.Command {
	e := &env{opts: o.withDefaults()}
	cmd := e.check()
	e.flags(cmd.Flags())
	return cmd
}

// withDefaults fills the empty paths and the connector.
func (o Options) withDefaults() Options {
	if o.RegistryPath == "" {
		o.RegistryPath = "credentials.json"
	}
	if o.EventsPath == "" {
		o.EventsPath = "events.json"
	}
	if o.TargetsPath == "" {
		o.TargetsPath = "targets.json"
	}
	if o.Connector == nil {
		o.Connector = func(f *targets.File) credforge.Connector { return NewConnector(f) }
	}
	return o
}

// flags defines the file flags on fs.
func (e *env) flags(fs *pflag.FlagSet) {
	if e.opts.Registry == nil {
		fs.StringVar(&e.registry, "registry", e.opts.RegistryPath, "the registry file (JSON)")
	}
	fs.StringVar(&e.events, "events", e.opts.EventsPath, "the event log file (JSON); missing means no events yet")
	if e.opts.Targets == nil {
		fs.StringVar(&e.targets, "targets", e.opts.TargetsPath, "the targets file (JSON): how each store is reached")
	}
}

func (e *env) load() (*credspec.Registry, *credspec.Log, *targets.File, error) {
	var reg *credspec.Registry
	var err error
	if e.opts.Registry != nil {
		if reg, err = e.opts.Registry(); err != nil {
			return nil, nil, nil, err
		}
		if err := reg.Validate(); err != nil {
			return nil, nil, nil, fmt.Errorf("registry: %w", err)
		}
	} else if reg, err = credspec.LoadRegistry(e.registry); err != nil {
		return nil, nil, nil, err
	}
	log, err := credspec.LoadLog(e.events, reg)
	if err != nil {
		return nil, nil, nil, err
	}
	var tf *targets.File
	if e.opts.Targets != nil {
		if tf, err = e.opts.Targets(); err == nil {
			err = tf.Validate()
		}
	} else {
		tf, err = targets.Load(e.targets)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	return reg, log, tf, nil
}

func (e *env) check() *cobra.Command {
	var record, includePlanned, all bool
	var failOn, only, format string
	var grace time.Duration
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Observe the stores the registry names and report where they disagree with it",
		Long: "check lists the names in every store the targets file reaches, never their values, and the secrets\n" +
			"the scanned repositories' workflows read, and compares them with the registry and the event log.\n\n" +
			"States, most urgent first:\n" +
			"  missing       a listed store does not hold the credential\n" +
			"  stale         a store was set before the current value was made\n" +
			"  unregistered  a workflow reads a secret the registry stores nowhere it can be read\n" +
			"  changed       a store was set after the log's latest event, and nothing was recorded\n" +
			"  unrecorded    a store holds a credential the log has no event for\n" +
			"  unlisted      a store holds a name no credential in use names\n" +
			"  unobserved    no binding reaches the store\n" +
			"  present       as recorded\n\n" +
			"--record logs unrecorded stores as created and changed ones as deployed. The exit status is 1\n" +
			"when a finding is in a --fail-on state, 2 on an error.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			states, err := credforge.ParseStates(failOn)
			if err != nil {
				return &ExitCodeError{Code: ExitError, Err: err}
			}
			if format != "text" && format != "json" {
				return &ExitCodeError{Code: ExitError, Err: fmt.Errorf("--format is text or json, not %q", format)}
			}
			if _, err := path.Match(only, ""); err != nil {
				return &ExitCodeError{Code: ExitError, Err: fmt.Errorf("--only: %w", err)}
			}
			reg, log, tf, err := e.load()
			if err != nil {
				return err
			}
			opts := credforge.Options{IncludePlanned: includePlanned, Grace: grace}
			if only != "" {
				opts.Only = func(cr credspec.Credential) bool {
					ok, err := path.Match(only, cr.ID)
					return err == nil && ok
				}
			}
			ch := &credforge.Checker{Connector: e.opts.Connector(tf)}
			if len(tf.Scan.GitHubRepositories) > 0 {
				ch.Extra = map[string][]string{github.StoreType: tf.Scan.GitHubRepositories}
			}
			rep, err := ch.Check(c.Context(), reg, log, opts)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if format == "json" {
				if err := writeJSON(out, rep); err != nil {
					return err
				}
			} else if err := writeText(out, rep, all); err != nil {
				return err
			}
			if record {
				added, err := credforge.Record(reg, log, rep, grace)
				if err != nil {
					return err
				}
				if len(added) > 0 {
					if e.events == "" {
						return errors.New("check: --record needs an --events file")
					}
					if err := log.Save(e.events); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprintf(c.ErrOrStderr(), "recorded %d event(s) in %s\n", len(added), e.events); err != nil {
					return err
				}
			}
			if failing := rep.In(states...); len(failing) > 0 {
				names := make([]string, len(states))
				for i, s := range states {
					names[i] = string(s)
				}
				return &ExitCodeError{Code: ExitFindings, Err: fmt.Errorf("check: %d finding(s) in %s", len(failing), strings.Join(names, ", "))}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&record, "record", false, "log unrecorded stores as created and changed ones as deployed")
	f.BoolVar(&includePlanned, "include-planned", false, "also compare planned credentials, for an environment being brought up")
	f.BoolVar(&all, "all", false, "list present and unobserved stores too, not only their counts")
	f.StringVar(&failOn, "fail-on", "missing,stale,unregistered", "states that make the exit status 1 (comma-separated; empty for none)")
	f.StringVar(&only, "only", "", "compare only credentials whose ID matches this pattern, such as 'app/prod/*'")
	f.StringVar(&format, "format", "text", "text or json")
	f.DurationVar(&grace, "grace", credforge.DefaultGrace, "how far a store's change and the log's event may differ")
	return cmd
}

func (e *env) schema() *cobra.Command {
	return &cobra.Command{
		Use:       "schema targets",
		Short:     "Write the targets file's JSON Schema",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{"targets"},
		RunE: func(c *cobra.Command, _ []string) error {
			_, err := c.OutOrStdout().Write(targets.Schema())
			return err
		},
	}
}

func writeJSON(w io.Writer, rep credforge.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// writeText writes a summary line, then one line per finding. Present and
// unobserved stores are only counted unless all is set.
func writeText(w io.Writer, rep credforge.Report, all bool) error {
	var counts []string
	for _, s := range credforge.States() {
		counts = append(counts, fmt.Sprintf("%d %s", rep.Count(s), s))
	}
	if _, err := fmt.Fprintf(w, "listed %d scope(s): %s\n", len(rep.Scopes), strings.Join(counts, ", ")); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range rep.Findings {
		if !all && (f.State == credforge.StatePresent || f.State == credforge.StateUnobserved) {
			continue
		}
		cred := f.Credential
		if cred == "" {
			cred = "-"
		}
		detail := f.Detail
		if f.Source != "" {
			detail += " (" + f.Source + ")"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.State, cred, f.Store, detail); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// Connector reaches stores as a targets file binds them, connecting once
// per binding.
type Connector struct {
	// HTTP sends GitHub's requests; http.DefaultClient when nil.
	HTTP   *http.Client
	file   *targets.File
	github map[string]*github.Client
	aws    map[string]*awsssm.Observer
	// newAWS connects to AWS; tests replace it.
	newAWS func(ctx context.Context, profile, region string) (*awsssm.Observer, error)
}

// NewConnector returns a Connector for f.
func NewConnector(f *targets.File) *Connector {
	return &Connector{file: f, github: map[string]*github.Client{}, aws: map[string]*awsssm.Observer{}, newAWS: awsssm.New}
}

// Observer returns the observer for a store, or nil when no binding
// reaches it or its type has no observer.
func (c *Connector) Observer(storeType, account string) (credforge.Observer, error) {
	b, ok := c.file.Match(storeType, account)
	if !ok {
		return nil, nil
	}
	switch {
	case storeType == github.StoreType && b.GitHub != nil:
		if !strings.Contains(account, "/") {
			// An organization's secrets are listed in a later release.
			return nil, nil
		}
		return c.githubClient(b.GitHub)
	case storeType == awsssm.StoreType && b.AWS != nil:
		key := b.AWS.Profile + "\x00" + b.AWS.Region
		if o, ok := c.aws[key]; ok {
			return o, nil
		}
		o, err := c.newAWS(context.Background(), b.AWS.Profile, b.AWS.Region)
		if err != nil {
			return nil, err
		}
		c.aws[key] = o
		return o, nil
	}
	return nil, nil
}

// References returns the reference finder for a store type and account:
// a repository's workflows, for GitHub Actions secrets.
func (c *Connector) References(storeType, account string) (credforge.ReferenceFinder, error) {
	if storeType != github.StoreType || !strings.Contains(account, "/") {
		return nil, nil
	}
	b, ok := c.file.Match(storeType, account)
	if !ok || b.GitHub == nil {
		return nil, nil
	}
	return c.githubClient(b.GitHub)
}

func (c *Connector) githubClient(g *targets.GitHub) (*github.Client, error) {
	key := g.TokenEnv + "\x00" + g.BaseURL
	if cl, ok := c.github[key]; ok {
		return cl, nil
	}
	token, err := github.TokenFromEnv(g.TokenEnv)
	if err != nil {
		return nil, err
	}
	cl := &github.Client{BaseURL: g.BaseURL, Token: token, HTTP: c.HTTP}
	c.github[key] = cl
	return cl, nil
}
