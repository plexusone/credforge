package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/awsssm"
	"github.com/plexusone/credforge/github"
	"github.com/plexusone/credforge/targets"
)

// Install returns the install command alone, with the same file flags as
// Check, for a host tool's own command tree. Use and Short are ignored.
func Install(o Options) *cobra.Command {
	e := &env{opts: o.withDefaults()}
	cmd := e.install()
	e.flags(cmd.Flags())
	return cmd
}

func (e *env) install() *cobra.Command {
	var expires, by string
	var dryRun, yes, fromStdin, noProbe bool
	cmd := &cobra.Command{
		Use:   "install <credential>",
		Short: "Write a credential's value to every store the registry lists, after checking it works, and record it",
		Long: "install sets one credential's value in each store the registry lists for it that the targets file\n" +
			"reaches: GitHub Actions secrets, sealed with the repository's key, and SSM SecureString parameters.\n" +
			"It lists the writes first and asks before reading the value.\n\n" +
			"The value is read once, hidden, from the terminal, or from standard input with --stdin and --yes.\n" +
			"It is never an argument, never written to disk, and never printed.\n\n" +
			"Before writing anything it checks the value: a GitHub token must read each repository its\n" +
			"entitlements name, which catches a missing repository, an organization's pending approval, or an\n" +
			"expired token. Then it records a created event (rotated when the log has one) with the expiry,\n" +
			"from --expires or as GitHub reports it, and a verified event for the checks that passed.\n\n" +
			"A credential whose provisioner stores it is refused; run its command instead. Stores no target\n" +
			"reaches are listed for you to set.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			var exp *time.Time
			if expires != "" {
				t, err := parseExpiry(expires)
				if err != nil {
					return &ExitCodeError{Code: ExitError, Err: err}
				}
				exp = &t
			}
			if fromStdin && !yes && !dryRun {
				return &ExitCodeError{Code: ExitError, Err: errors.New("install: --stdin needs --yes, since standard input holds the value, not the answer")}
			}
			reg, log, tf, err := e.load()
			if err != nil {
				return err
			}
			in := &credforge.Installer{Writer: e.opts.Writer(tf)}
			if !noProbe {
				in.Prober = e.opts.Prober
			}
			plan, err := in.Plan(reg, log, args[0])
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if err := writePlan(out, plan, in.Prober != nil); err != nil {
				return err
			}
			if dryRun {
				return nil
			}
			stdin := c.InOrStdin()
			tty, isTTY := terminal(stdin)
			if !fromStdin && !isTTY {
				return &ExitCodeError{Code: ExitError, Err: errors.New("install: the value is read from a terminal; pipe it with --stdin --yes")}
			}
			if !yes {
				ok, err := confirm(stdin, c.ErrOrStderr(), fmt.Sprintf("Write %d store(s)? [y/N] ", len(plan.Writes)))
				if err != nil {
					return err
				}
				if !ok {
					_, err := fmt.Fprintln(out, "nothing written")
					return err
				}
			}
			var value string
			if fromStdin {
				value, err = readValue(stdin)
			} else {
				value, err = readHidden(tty, c.ErrOrStderr(), fmt.Sprintf("Value of %s (hidden): ", plan.Credential))
			}
			if err != nil {
				return err
			}
			res, err := in.Apply(c.Context(), reg, log, plan, value, credforge.InstallOptions{Expires: exp, By: by})
			if err != nil {
				return err
			}
			if err := log.Save(e.events); err != nil {
				return fmt.Errorf("install: every store was written, but saving %s failed: %w", e.events, err)
			}
			return writeInstalled(out, res, e.events)
		},
	}
	f := cmd.Flags()
	f.StringVar(&expires, "expires", "", "the value's expiry, YYYY-MM-DD (UTC) or RFC 3339; default as the issuer reports it")
	f.StringVar(&by, "by", "operator", "who installs, for the events")
	f.BoolVar(&dryRun, "dry-run", false, "list the writes and stop")
	f.BoolVar(&yes, "yes", false, "write without asking")
	f.BoolVar(&fromStdin, "stdin", false, "read the value from standard input instead of the terminal")
	f.BoolVar(&noProbe, "no-probe", false, "write without checking the value first")
	return cmd
}

func parseExpiry(s string) (time.Time, error) {
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("install: --expires %q is not YYYY-MM-DD or RFC 3339", s)
	}
	return t.UTC(), nil
}

func writePlan(w io.Writer, p *credforge.InstallPlan, probes bool) error {
	head := fmt.Sprintf("install %s: a new value (%s)", p.Credential, p.Event)
	if p.Replaces != nil {
		head += ", replacing the one made " + p.Replaces.Format(time.DateOnly)
	}
	lines := []string{head}
	if probes {
		lines = append(lines, "  check  the value against its entitlements before writing")
	}
	for _, d := range p.Writes {
		lines = append(lines, "  write  "+d.Store.String())
	}
	for _, s := range p.Skipped {
		lines = append(lines, "  skip   "+s.Store.String()+": "+s.Reason)
	}
	_, err := fmt.Fprintln(w, strings.Join(lines, "\n"))
	return err
}

func writeInstalled(w io.Writer, res credforge.InstallResult, events string) error {
	var lines []string
	for _, ch := range res.Probe.Checked {
		lines = append(lines, "checked  "+ch)
	}
	for _, k := range res.Written {
		lines = append(lines, "wrote    "+k.String())
	}
	for _, e := range res.Events {
		l := fmt.Sprintf("recorded %s in %s", e.Type, events)
		if e.Expires != nil {
			l += ", expires " + e.Expires.Format(time.DateOnly)
		}
		lines = append(lines, l)
	}
	if res.ExpiryDiffers && res.Probe.Expires != nil {
		lines = append(lines, "note     GitHub reports the token expires "+res.Probe.Expires.Format(time.DateOnly)+"; the log has --expires")
	}
	_, err := fmt.Fprintln(w, strings.Join(lines, "\n"))
	return err
}

// terminal returns the file descriptor when r is a terminal.
func terminal(r io.Reader) (int, bool) {
	f, ok := r.(*os.File)
	if !ok {
		return 0, false
	}
	fd := int(f.Fd())
	return fd, term.IsTerminal(fd)
}

func confirm(r io.Reader, prompt io.Writer, question string) (bool, error) {
	if _, err := fmt.Fprint(prompt, question); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("install: reading the answer: %w", err)
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", nil
}

func readHidden(fd int, prompt io.Writer, question string) (string, error) {
	if _, err := fmt.Fprint(prompt, question); err != nil {
		return "", err
	}
	b, err := term.ReadPassword(fd)
	if _, perr := fmt.Fprintln(prompt); perr != nil {
		err = errors.Join(err, perr)
	}
	if err != nil {
		return "", fmt.Errorf("install: reading the value: %w", err)
	}
	return string(b), nil
}

// readValue reads standard input, dropping one trailing newline.
func readValue(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return "", fmt.Errorf("install: reading the value: %w", err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	return strings.TrimSuffix(s, "\r"), nil
}

// Writer returns the writer for a store the targets file binds, or nil
// when no binding reaches it or its type has no writer.
func (c *Connector) Writer(storeType, account string) (credforge.Writer, error) {
	b, ok := c.file.Match(storeType, account)
	if !ok {
		return nil, nil
	}
	switch {
	case storeType == github.StoreType && b.GitHub != nil:
		if !strings.Contains(account, "/") {
			// An organization's secrets are written in a later release.
			return nil, nil
		}
		cl, err := c.githubClient(b.GitHub)
		if err != nil {
			return nil, err
		}
		return cl, nil
	case storeType == awsssm.StoreType && b.AWS != nil:
		key := b.AWS.Profile + "\x00" + b.AWS.Region
		if w, ok := c.awsWriters[key]; ok {
			return w, nil
		}
		w, err := c.newAWSWriter(context.Background(), b.AWS.Profile, b.AWS.Region)
		if err != nil {
			return nil, err
		}
		c.awsWriters[key] = w
		return w, nil
	}
	return nil, nil
}

// defaultWriter is Options.Writer's default: the targets file's bindings.
func defaultWriter(f *targets.File) func(storeType, account string) (credforge.Writer, error) {
	return NewConnector(f).Writer
}
