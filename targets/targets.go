// Package targets reads the targets file: how credforge reaches each store
// a credential registry names. It binds a store type and account, as the
// registry spells them, to a connection, such as a GitHub token's
// environment variable or an AWS profile and region. It holds no secrets.
package targets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
)

// FormatVersion is the targets file format this package reads and writes.
const FormatVersion = "1"

// File is a targets file.
type File struct {
	// Schema is the JSON Schema's URL, for editors.
	Schema string `json:"$schema,omitempty"`
	// FormatVersion is the file format's version: "1".
	FormatVersion string `json:"formatVersion"`
	// Bindings say how each store is reached. The first whose store type
	// and account match a registry store applies.
	Bindings []Binding `json:"bindings"`
	// Scan lists accounts to check beyond those the registry names.
	Scan Scan `json:"scan,omitzero"`
}

// Binding connects the stores of one type in matching accounts.
type Binding struct {
	// Store is the registry's store type, such as github-actions or aws-ssm.
	Store string `json:"store"`
	// Account matches the registry store's account exactly, or as a
	// path.Match pattern such as "example-org/*"; "*" matches any account,
	// including an empty one.
	Account string `json:"account"`
	// GitHub connects github-actions stores.
	GitHub *GitHub `json:"github,omitempty"`
	// AWS connects aws-ssm stores.
	AWS *AWS `json:"aws,omitempty"`
}

// GitHub is how GitHub is reached.
type GitHub struct {
	// TokenEnv is the environment variable holding the token. When empty,
	// GITHUB_TOKEN, then GH_TOKEN, then the GitHub CLI's (gh auth token).
	// The token is never written here.
	TokenEnv string `json:"tokenEnv,omitempty"`
	// BaseURL is the REST API's URL; https://api.github.com when empty.
	BaseURL string `json:"baseUrl,omitempty"`
}

// AWS is how an AWS account is reached. Credentials come from the SDK's
// default chain for the profile.
type AWS struct {
	// Profile is the shared configuration profile; the default chain's
	// when empty.
	Profile string `json:"profile,omitempty"`
	// Region is the region; the profile's when empty.
	Region string `json:"region,omitempty"`
}

// Scan lists accounts to check that the registry may not name.
type Scan struct {
	// GitHubRepositories are owner/repo names whose Actions secrets are
	// listed and whose workflows are read, so a secret a workflow reads and
	// the registry does not store is reported.
	GitHubRepositories []string `json:"githubRepositories,omitempty"`
}

// Match returns the first binding for a store type and account.
func (f *File) Match(store, account string) (Binding, bool) {
	for _, b := range f.Bindings {
		if b.Store != store {
			continue
		}
		if b.Account == "*" || b.Account == account {
			return b, true
		}
		if ok, err := path.Match(b.Account, account); err == nil && ok {
			return b, true
		}
	}
	return Binding{}, false
}

var (
	repoName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$`)
	envName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Validate checks the file.
func (f *File) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if f.FormatVersion != FormatVersion {
		add("formatVersion is %q; this credforge reads %q", f.FormatVersion, FormatVersion)
	}
	for i, b := range f.Bindings {
		where := fmt.Sprintf("bindings[%d]", i)
		if b.Store == "" {
			add("%s.store is required", where)
		}
		if b.Account == "" {
			add("%s.account is required; use \"*\" for any", where)
		} else if _, err := path.Match(b.Account, ""); err != nil {
			add("%s.account is not a valid pattern: %v", where, err)
		}
		if b.GitHub != nil && b.AWS != nil {
			add("%s has both github and aws", where)
		}
		if b.GitHub == nil && b.AWS == nil {
			add("%s needs github or aws", where)
		}
		if b.GitHub != nil {
			if b.GitHub.TokenEnv != "" && !envName.MatchString(b.GitHub.TokenEnv) {
				add("%s.github.tokenEnv %q is not an environment variable name", where, b.GitHub.TokenEnv)
			}
			if b.GitHub.BaseURL != "" && !strings.HasPrefix(b.GitHub.BaseURL, "https://") {
				add("%s.github.baseUrl must be an https URL", where)
			}
		}
	}
	for i, r := range f.Scan.GitHubRepositories {
		if !repoName.MatchString(r) {
			add("scan.githubRepositories[%d] %q is not owner/repo", i, r)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("targets: %w", err)
	}
	return nil
}

// Read parses and validates a targets file. Unknown fields are refused.
func Read(data []byte) (*File, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("targets: %w", err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Load reads and validates the targets file at name.
func Load(name string) (*File, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("targets: %w", err)
	}
	return Read(data)
}
