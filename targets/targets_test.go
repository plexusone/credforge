package targets_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexusone/credforge/targets"
)

const example = `{
  "formatVersion": "1",
  "bindings": [
    {"store": "github-actions", "account": "example-org/legacy", "github": {"tokenEnv": "LEGACY_TOKEN"}},
    {"store": "github-actions", "account": "example-org/*", "github": {}},
    {"store": "aws-ssm", "account": "hosting (us-west-2)", "aws": {"profile": "hosting", "region": "us-west-2"}},
    {"store": "aws-ssm", "account": "*", "aws": {}}
  ],
  "scan": {"githubRepositories": ["example-org/web", "example-org/api"]}
}`

func TestReadAndMatch(t *testing.T) {
	f, err := targets.Read([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		store, account string
		want           int // index of the binding, or -1
	}{
		{"github-actions", "example-org/legacy", 0},
		{"github-actions", "example-org/web", 1},
		{"github-actions", "other-org/web", -1},
		{"aws-ssm", "hosting (us-west-2)", 2},
		{"aws-ssm", "", 3},
		{"host-file", "", -1},
	} {
		b, ok := f.Match(tc.store, tc.account)
		if tc.want < 0 {
			if ok {
				t.Errorf("Match(%s, %s) = %+v, want none", tc.store, tc.account, b)
			}
			continue
		}
		want := f.Bindings[tc.want]
		if !ok || b.Store != want.Store || b.Account != want.Account {
			t.Errorf("Match(%s, %s) = %+v, %v; want binding %d", tc.store, tc.account, b, ok, tc.want)
		}
	}
	if got := f.Scan.GitHubRepositories; len(got) != 2 {
		t.Errorf("scan repositories = %v", got)
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct{ name, json, want string }{
		{"version", `{"formatVersion": "2", "bindings": []}`, "formatVersion"},
		{"store", `{"formatVersion": "1", "bindings": [{"account": "*", "aws": {}}]}`, "store is required"},
		{"account", `{"formatVersion": "1", "bindings": [{"store": "aws-ssm", "aws": {}}]}`, "account is required"},
		{"pattern", `{"formatVersion": "1", "bindings": [{"store": "aws-ssm", "account": "[", "aws": {}}]}`, "not a valid pattern"},
		{"neither", `{"formatVersion": "1", "bindings": [{"store": "aws-ssm", "account": "*"}]}`, "needs github or aws"},
		{"both", `{"formatVersion": "1", "bindings": [{"store": "aws-ssm", "account": "*", "aws": {}, "github": {}}]}`, "both"},
		{"env", `{"formatVersion": "1", "bindings": [{"store": "github-actions", "account": "*", "github": {"tokenEnv": "A-B"}}]}`, "tokenEnv"},
		{"url", `{"formatVersion": "1", "bindings": [{"store": "github-actions", "account": "*", "github": {"baseUrl": "http://x"}}]}`, "https"},
		{"repo", `{"formatVersion": "1", "bindings": [], "scan": {"githubRepositories": ["web"]}}`, "not owner/repo"},
		{"unknown field", `{"formatVersion": "1", "bindings": [], "token": "x"}`, "unknown field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := targets.Read([]byte(tc.json))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	name := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(name, []byte(example), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := targets.Load(name); err != nil {
		t.Fatal(err)
	}
	if _, err := targets.Load(filepath.Join(t.TempDir(), "none.json")); err == nil {
		t.Fatal("Load of a missing file succeeded")
	}
}

// TestSchemaIsCurrent fails when the types changed and the schema was not
// regenerated with go generate ./targets.
func TestSchemaIsCurrent(t *testing.T) {
	got, err := targets.GenerateSchema("..")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, targets.Schema()) {
		t.Fatal("targets.schema.json is stale: run go generate ./targets")
	}
}
