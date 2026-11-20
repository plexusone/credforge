package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"
	"github.com/spf13/cobra"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/review"
)

// DefaultReviewAddr is the review page's default address.
const DefaultReviewAddr = "127.0.0.1:8484"

func (e *env) review() *cobra.Command {
	var addr, reviews, by string
	var grace time.Duration
	cmd := &cobra.Command{
		Use:   "review",
		Short: "Serve a local page to review every credential, record decisions and log events",
		Long: "review serves a page on a loopback address listing every credential in the registry with its\n" +
			"stores, consumers, entitlements, rotation and events, filtered by system, environment, status,\n" +
			"store, live state and review decision. A live check, run from the page, adds each store's state\n" +
			"and the stores no credential names. Decisions (approved, change, remove) are saved in the reviews\n" +
			"file and events in the event log; the registry itself is never written. No value is read or shown.\n\n" +
			"Without a targets file the page works without the live check.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return &ExitCodeError{Code: ExitError, Err: fmt.Errorf("--addr: %w", err)}
			}
			if !review.LoopbackHost(host) {
				return &ExitCodeError{Code: ExitError, Err: fmt.Errorf("--addr %s is not a loopback address; the review page is served only on this machine", addr)}
			}
			reg, err := e.loadRegistry()
			if err != nil {
				return err
			}
			if _, err := credspec.LoadLog(e.events, reg); err != nil {
				return err
			}
			if _, err := review.Load(reviews); err != nil {
				return err
			}
			srv := &review.Server{Title: e.opts.Title, Registry: reg, EventsPath: e.events, ReviewsPath: reviews, By: by}
			tf, err := e.loadTargets()
			switch {
			case err == nil:
				srv.Check = func(ctx context.Context) (credforge.Report, error) {
					log, err := credspec.LoadLog(e.events, reg)
					if err != nil {
						return credforge.Report{}, err
					}
					return e.checker(tf).Check(ctx, reg, log, credforge.Options{IncludePlanned: true, Grace: grace})
				}
			case e.opts.Targets == nil && errors.Is(err, fs.ErrNotExist):
				if _, err := fmt.Fprintf(c.ErrOrStderr(), "no targets file at %s: the page has no live check\n", e.targets); err != nil {
					return err
				}
			default:
				return err
			}

			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(c.OutOrStdout(), "reviewing at http://%s/ (Ctrl-C to stop)\n", ln.Addr()); err != nil {
				return errors.Join(err, ln.Close())
			}
			ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return serve(ctx, ln, srv.Handler())
		},
	}
	f := cmd.Flags()
	f.StringVar(&addr, "addr", DefaultReviewAddr, "the loopback address to serve on, such as 127.0.0.1:8484 or localhost:0")
	f.StringVar(&reviews, "reviews", e.opts.ReviewsPath, "the reviews file (JSON); missing means no decisions yet")
	f.StringVar(&by, "by", "operator", "who decisions and events are recorded as")
	f.DurationVar(&grace, "grace", credforge.DefaultGrace, "how far a store's change and the log's event may differ")
	return cmd
}

// serve serves h on ln until ctx is done, then shuts down, letting
// requests in flight finish for up to five seconds.
func serve(ctx context.Context, ln net.Listener, h http.Handler) error {
	hs := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
