package github_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/github"
)

const token = "test-token-value"

// server fakes the REST API for example-org/web: n secrets, and two
// workflow files. It fails the test on any request without the token, and
// on any path outside the listing endpoints.
func server(t *testing.T, n int) *httptest.Server {
	t.Helper()
	ci := "on: push\njobs:\n  test:\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }} ${{ secrets['NPM_TOKEN'] }}\n      # ${{ secrets.COMMENTED }}\n      - env: {T: \"${{ secrets.GITHUB_TOKEN }}\"}\n"
	release := "jobs:\n  r:\n    env:\n      A: ${{ secrets.DEPLOY_TOKEN }}\n      B: ${{secrets.RELEASE_KEY}}\n"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("%s without the token", r.URL.Path)
		}
		switch {
		case r.URL.Path == "/repos/example-org/web/actions/secrets":
			page := 1
			if _, err := fmt.Sscan(r.URL.Query().Get("page"), &page); err != nil {
				t.Errorf("page: %v", err)
			}
			type sec struct {
				Name      string    `json:"name"`
				UpdatedAt time.Time `json:"updated_at"`
			}
			var secrets []sec
			for i := (page - 1) * 100; i < min(page*100, n); i++ {
				secrets = append(secrets, sec{Name: fmt.Sprintf("S%03d", i), UpdatedAt: time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)})
			}
			writeJSON(t, w, map[string]any{"total_count": n, "secrets": secrets})
		case r.URL.Path == "/repos/example-org/web/contents/.github/workflows":
			writeJSON(t, w, []map[string]string{
				{"name": "ci.yaml", "path": ".github/workflows/ci.yaml", "type": "file"},
				{"name": "release.yml", "path": ".github/workflows/release.yml", "type": "file"},
				{"name": "README.md", "path": ".github/workflows/README.md", "type": "file"},
				{"name": "shared", "path": ".github/workflows/shared", "type": "dir"},
			})
		case r.URL.Path == "/repos/example-org/web/contents/.github/workflows/ci.yaml":
			if !strings.Contains(r.Header.Get("Accept"), "raw") {
				t.Errorf("workflow fetched without the raw media type")
			}
			fmt.Fprint(w, ci)
		case r.URL.Path == "/repos/example-org/web/contents/.github/workflows/release.yml":
			fmt.Fprint(w, release)
		case r.URL.Path == "/repos/example-org/empty/contents/.github/workflows":
			w.WriteHeader(http.StatusNotFound)
			writeJSON(t, w, map[string]string{"message": "Not Found"})
		case r.URL.Path == "/repos/example-org/locked/actions/secrets":
			w.WriteHeader(http.StatusForbidden)
			writeJSON(t, w, map[string]string{"message": "Resource not accessible by personal access token"})
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	}))
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error(err)
	}
}

func TestObservePages(t *testing.T) {
	srv := server(t, 230)
	defer srv.Close()
	c := &github.Client{BaseURL: srv.URL, Token: token}
	got, err := c.Observe(context.Background(), credforge.Scope{Type: github.StoreType, Account: "example-org/web"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 230 {
		t.Fatalf("observed %d secrets, want 230", len(got))
	}
	last := got[229]
	if last.Path != "S229" || last.Account != "example-org/web" || last.Type != github.StoreType ||
		!last.Modified.Equal(time.Date(2026, 1, 1, 0, 0, 229, 0, time.UTC)) {
		t.Errorf("last observation = %+v", last)
	}
}

func TestObserveErrors(t *testing.T) {
	srv := server(t, 0)
	defer srv.Close()
	c := &github.Client{BaseURL: srv.URL, Token: token}
	_, err := c.Observe(context.Background(), credforge.Scope{Type: github.StoreType, Account: "example-org/locked"})
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "not accessible") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("the error shows the token")
	}
	if _, err := c.Observe(context.Background(), credforge.Scope{Type: github.StoreType, Account: "example-org"}); err == nil {
		t.Fatal("an organization account was accepted as a repository")
	}
}

func TestReferences(t *testing.T) {
	srv := server(t, 0)
	defer srv.Close()
	c := &github.Client{BaseURL: srv.URL, Token: token}
	got, err := c.References(context.Background(), "example-org/web")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range got {
		lines = append(lines, r.Path+" "+r.Source)
	}
	want := []string{
		"DEPLOY_TOKEN .github/workflows/ci.yaml",
		"NPM_TOKEN .github/workflows/ci.yaml",
		"DEPLOY_TOKEN .github/workflows/release.yml",
		"RELEASE_KEY .github/workflows/release.yml",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("references:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}

	none, err := c.References(context.Background(), "example-org/empty")
	if err != nil || len(none) != 0 {
		t.Fatalf("a repository without workflows: %v, %v", none, err)
	}
}

func TestParseReferences(t *testing.T) {
	got := github.ParseReferences([]byte(`
env:
  A: ${{ secrets.A }}
  B: ${{ secrets . B }}
  C: ${{ secrets["C"] }}
  D: ${{ secrets.A }}
  # E: ${{ secrets.E }}
  F: ${{ github.token }} ${{ mysecrets.X }} ${{ secrets.GITHUB_TOKEN }}
`))
	if strings.Join(got, ",") != "A,B,C" {
		t.Fatalf("ParseReferences = %v", got)
	}
}

func TestTokenFromEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "from-gh")
	t.Setenv("CUSTOM", "from-custom")
	if v, err := github.TokenFromEnv(""); err != nil || v != "from-gh" {
		t.Fatalf("default = %q, %v", v, err)
	}
	if v, err := github.TokenFromEnv("CUSTOM"); err != nil || v != "from-custom" {
		t.Fatalf("CUSTOM = %q, %v", v, err)
	}
	if _, err := github.TokenFromEnv("UNSET_VARIABLE_FOR_TEST"); err == nil {
		t.Fatal("an unset variable gave a token")
	}
}

func TestTokenFallsBackToGH(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("CUSTOM", "")
	restore := github.SetGHAuthToken(func(context.Context) (string, error) { return "from-gh-cli", nil })
	defer restore()
	if v, err := github.Token(context.Background(), ""); err != nil || v != "from-gh-cli" {
		t.Fatalf("default = %q, %v; want the gh CLI's token", v, err)
	}
	if _, err := github.Token(context.Background(), "CUSTOM"); err == nil {
		t.Fatal("an unset named variable fell back to the gh CLI")
	}
	t.Setenv("GH_TOKEN", "from-env")
	if v, err := github.Token(context.Background(), ""); err != nil || v != "from-env" {
		t.Fatalf("with GH_TOKEN = %q, %v; want the variable first", v, err)
	}
	t.Setenv("GH_TOKEN", "")
	restore2 := github.SetGHAuthToken(func(context.Context) (string, error) { return "", errors.New("not signed in") })
	defer restore2()
	if _, err := github.Token(context.Background(), ""); err == nil {
		t.Fatal("gh not signed in gave a token")
	}
}
