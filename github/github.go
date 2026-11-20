// Package github observes GitHub Actions secrets and the secrets a
// repository's workflows read, through GitHub's REST API.
//
// It lists secret names and when each was last set, and reads workflow
// files for secrets.NAME. GitHub never returns an Actions secret's value,
// and this package asks for none.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/plexusone/credforge"
)

// DefaultBaseURL is GitHub's REST API.
const DefaultBaseURL = "https://api.github.com"

// StoreType is the registry's store type for Actions secrets.
const StoreType = credforge.StoreGitHubActions

// WorkflowsDir is where a repository's workflows are.
const WorkflowsDir = ".github/workflows"

// Client reads one GitHub instance with one token.
type Client struct {
	// BaseURL is the REST API's URL; DefaultBaseURL when empty.
	BaseURL string
	// Token authenticates each request. It needs read access to the
	// repositories' Actions secrets and contents.
	Token string
	// HTTP sends the requests; http.DefaultClient when nil.
	HTTP *http.Client
}

// TokenFromEnv returns the token in the named environment variable, or,
// when name is empty, in GITHUB_TOKEN, then GH_TOKEN.
func TokenFromEnv(name string) (string, error) {
	names := []string{"GITHUB_TOKEN", "GH_TOKEN"}
	if name != "" {
		names = []string{name}
	}
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("github: no token: set %s", strings.Join(names, " or "))
}

// Observe lists the Actions secrets of the repository s.Account
// (owner/repo): names and when each was last set.
func (c *Client) Observe(ctx context.Context, s credforge.Scope) ([]credforge.Observation, error) {
	owner, repo, err := splitRepo(s.Account)
	if err != nil {
		return nil, err
	}
	var out []credforge.Observation
	for page := 1; ; page++ {
		var body struct {
			TotalCount int `json:"total_count"`
			Secrets    []struct {
				Name      string    `json:"name"`
				UpdatedAt time.Time `json:"updated_at"`
			} `json:"secrets"`
		}
		p := fmt.Sprintf("/repos/%s/%s/actions/secrets?per_page=100&page=%d", url.PathEscape(owner), url.PathEscape(repo), page)
		if err := c.getJSON(ctx, p, &body); err != nil {
			return nil, err
		}
		for _, sec := range body.Secrets {
			out = append(out, credforge.Observation{
				Key:      credforge.Key{Type: StoreType, Account: s.Account, Path: sec.Name},
				Modified: sec.UpdatedAt,
			})
		}
		if len(body.Secrets) < 100 || len(out) >= body.TotalCount {
			return out, nil
		}
	}
}

// References lists the secrets the workflows of the repository account
// (owner/repo) read, from its default branch. A repository with no
// workflows has none.
func (c *Client) References(ctx context.Context, account string) ([]credforge.Reference, error) {
	owner, repo, err := splitRepo(account)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Name string `json:"name"`
		Path string `json:"path"`
		Type string `json:"type"`
	}
	dir := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), WorkflowsDir)
	if err := c.getJSON(ctx, dir, &entries); err != nil {
		if errors.Is(err, errNotFound) {
			return nil, nil
		}
		return nil, err
	}
	var out []credforge.Reference
	for _, e := range entries {
		if e.Type != "file" || (path.Ext(e.Name) != ".yml" && path.Ext(e.Name) != ".yaml") {
			continue
		}
		content, err := c.get(ctx, fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), escapePath(e.Path)), "application/vnd.github.raw+json")
		if err != nil {
			return nil, err
		}
		for _, name := range ParseReferences(content) {
			out = append(out, credforge.Reference{
				Key:    credforge.Key{Type: StoreType, Account: account, Path: name},
				Source: e.Path,
			})
		}
	}
	return out, nil
}

var reference = regexp.MustCompile(`\bsecrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\])`)

// ParseReferences returns the secret names a workflow file reads, as
// secrets.NAME or secrets['NAME'], sorted and without duplicates.
// GITHUB_TOKEN, which GitHub provides, is left out. Lines that are only a
// YAML comment are skipped.
func ParseReferences(workflow []byte) []string {
	var out []string
	for _, line := range strings.Split(string(workflow), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, m := range reference.FindAllStringSubmatch(line, -1) {
			name := m[1] + m[2]
			if name != "" && name != "GITHUB_TOKEN" {
				out = append(out, name)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

var errNotFound = errors.New("not found")

func (c *Client) getJSON(ctx context.Context, p string, v any) error {
	data, err := c.get(ctx, p, "application/vnd.github+json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("github: reading %s: %w", p, err)
	}
	return nil
}

// get requests p and returns the body. Errors name the path and status,
// never the request's headers.
func (c *Client) get(ctx context.Context, p, accept string) ([]byte, error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+p, nil)
	if err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: GET %s: %w", p, redact(err))
	}
	defer func() {
		// The body is fully read or discarded below; a close error leaves
		// nothing to recover.
		_ = resp.Body.Close()
	}()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("github: GET %s: %w", p, err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("github: GET %s: %w", p, errNotFound)
	case resp.StatusCode/100 != 2:
		var msg struct {
			Message string `json:"message"`
		}
		detail := ""
		if json.Unmarshal(data, &msg) == nil && msg.Message != "" {
			detail = ": " + msg.Message
		}
		return nil, fmt.Errorf("github: GET %s: %s%s", p, resp.Status, detail)
	}
	return data, nil
}

// redact drops a URL error's URL, which never holds the token here, but
// keeps the reported error to the cause alone.
func redact(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func splitRepo(account string) (owner, repo string, err error) {
	owner, repo, ok := strings.Cut(account, "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", fmt.Errorf("github: account %q is not owner/repo", account)
	}
	return owner, repo, nil
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}
