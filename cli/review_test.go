package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/awsssm"
	"github.com/plexusone/credforge/review"
	"github.com/plexusone/credforge/targets"
)

func TestReviewRefusesANonLoopbackAddress(t *testing.T) {
	srv := githubServer(t)
	dir := fixture(t, srv.URL)
	_, _, err := run(t, srv, dir, "review", "--addr", "0.0.0.0:8484")
	if err == nil || Code(err) != ExitError || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("err = %v", err)
	}
}

// TestReviewServesAndChecks starts the review command on a free port, runs
// a live check through the page's API and stops it by cancelling.
func TestReviewServesAndChecks(t *testing.T) {
	srv := githubServer(t)
	dir := fixture(t, srv.URL)
	t.Setenv("TEST_GITHUB_TOKEN", "test-token")
	cmd := Review(Options{Title: "Example", Connector: func(f *targets.File) credforge.Connector {
		c := NewConnector(f)
		c.HTTP = srv.Client()
		c.newAWS = func(context.Context, string, string) (*awsssm.Observer, error) {
			return &awsssm.Observer{API: fakeSSM{}}, nil
		}
		return c
	}})
	pr, pw := io.Pipe()
	cmd.SetOut(pw)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--addr", "127.0.0.1:0",
		"--registry", filepath.Join(dir, "credentials.json"),
		"--events", filepath.Join(dir, "events.json"),
		"--targets", filepath.Join(dir, "targets.json"),
		"--reviews", filepath.Join(dir, "reviews.json")})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		err := cmd.ExecuteContext(ctx)
		if cerr := pw.Close(); cerr != nil {
			t.Error(cerr)
		}
		done <- err
	}()

	line, err := bufio.NewReader(pr).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		// Drain anything else the command writes, so it never blocks.
		if _, err := io.Copy(io.Discard, pr); err != nil {
			t.Error(err)
		}
	}()
	_, rest, ok := strings.Cut(line, "http://")
	if !ok {
		t.Fatalf("no URL in %q", line)
	}
	base := "http://" + strings.Fields(rest)[0]
	base = strings.TrimSuffix(base, "/")

	req, err := http.NewRequestWithContext(ctx, "POST", base+"/api/check", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var cr review.CheckResult
	if err := json.NewDecoder(res.Body).Decode(&cr); err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if cr.Error != "" || cr.Report == nil || cr.Report.Count(credforge.StateStale) != 1 || cr.Report.Count(credforge.StateUnregistered) != 1 {
		t.Fatalf("check = %+v", cr)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("review returned %v after cancelling", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("review did not stop")
	}
}
