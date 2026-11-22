package github

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"
	"golang.org/x/crypto/nacl/box"

	"github.com/plexusone/credforge"
)

// Write sets the Actions secret k.Path in the repository k.Account
// (owner/repo), creating or replacing it. The value is sealed with the
// repository's public key, as GitHub requires, so only GitHub can open it.
// The client's token needs write access to the repository's secrets.
func (c *Client) Write(ctx context.Context, k credforge.Key, value string) error {
	if k.Type != StoreType {
		return fmt.Errorf("github: %s is not a %s store", k, StoreType)
	}
	owner, repo, err := splitRepo(k.Account)
	if err != nil {
		return err
	}
	if !secretName.MatchString(k.Path) || strings.HasPrefix(strings.ToUpper(k.Path), "GITHUB_") {
		return fmt.Errorf("github: %q is not an Actions secret name", k.Path)
	}
	base := fmt.Sprintf("/repos/%s/%s/actions/secrets", url.PathEscape(owner), url.PathEscape(repo))
	var pk struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if err := c.getJSON(ctx, base+"/public-key", &pk); err != nil {
		return err
	}
	sealed, err := seal(pk.Key, value)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"encrypted_value": sealed, "key_id": pk.KeyID})
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	if _, _, err := c.do(ctx, http.MethodPut, base+"/"+url.PathEscape(k.Path), "application/vnd.github+json", body); err != nil {
		return err
	}
	return nil
}

// secretName is an Actions secret's name; GitHub refuses one starting
// with GITHUB_.
var secretName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// seal encrypts value for the repository's public key with an anonymous
// NaCl box, which is what GitHub's secrets API takes.
func seal(publicKey, value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != 32 {
		return "", errors.New("github: the repository's public key is not a 32-byte base64 key")
	}
	var pk [32]byte
	copy(pk[:], raw)
	out, err := box.SealAnonymous(nil, []byte(value), &pk, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("github: sealing the secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

// ExpirationHeader is the response header in which GitHub reports a
// token's expiry.
const ExpirationHeader = "GitHub-Authentication-Token-Expiration"

// Prober tests a GitHub token against the repositories the registry
// grants it. It uses the value being installed as its token, and nothing
// else.
type Prober struct {
	// BaseURL is the REST API's URL; DefaultBaseURL when empty.
	BaseURL string
	// HTTP sends the requests; http.DefaultClient when nil.
	HTTP *http.Client
}

// Probe reads each github.com/<owner>/<repo> entitlement's repository with
// the value as the token, and its commits when the access names contents.
// It checks credentials GitHub issues and has nothing to check for others.
// The expiry GitHub reports for the token is returned.
func (p *Prober) Probe(ctx context.Context, cr credspec.Credential, value string) (credforge.Probe, error) {
	var out credforge.Probe
	if cr.Issuer.Type != credspec.IssuerGitHub {
		return out, nil
	}
	c := &Client{BaseURL: p.BaseURL, Token: value, HTTP: p.HTTP}
	for _, e := range cr.Entitlements {
		owner, repo, ok := repository(e.Resource)
		if !ok {
			continue
		}
		base := fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo))
		paths := []string{base}
		if strings.Contains(strings.ToLower(e.Access), "contents") {
			paths = append(paths, base+"/commits?per_page=1")
		}
		for _, pth := range paths {
			_, h, err := c.do(ctx, http.MethodGet, pth, "application/vnd.github+json", nil)
			if err := refused(err, e.Resource); err != nil {
				return out, err
			}
			if exp, err := expiration(h); err != nil {
				return out, err
			} else if exp != nil {
				out.Expires = exp
			}
		}
		out.Checked = append(out.Checked, fmt.Sprintf("the token reads %s (%s)", e.Resource, e.Access))
	}
	return out, nil
}

// refused explains a failed probe request, or returns nil when the request
// passed. An empty repository's commits (409) count as readable.
func refused(err error, resource string) error {
	if err == nil {
		return nil
	}
	var se *StatusError
	switch {
	case errors.Is(err, errNotFound):
		return fmt.Errorf("the token cannot read %s: check its repository access, and whether the organization has approved it", resource)
	case errors.As(err, &se) && se.Status == http.StatusConflict:
		return nil
	case errors.As(err, &se) && se.Status == http.StatusUnauthorized:
		return errors.New("GitHub refuses the token: it is mistyped, expired or revoked")
	case errors.As(err, &se) && se.Status == http.StatusForbidden:
		return fmt.Errorf("the token may not read %s: %s", resource, se.Text)
	}
	return err
}

// expiration reads the expiry GitHub reports, such as
// "2027-11-21 00:00:00 UTC"; nil when there is none.
func expiration(h http.Header) (*time.Time, error) {
	v := strings.TrimSpace(h.Get(ExpirationHeader))
	if v == "" {
		return nil, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700", time.RFC3339} {
		if t, err := time.Parse(layout, v); err == nil {
			t = t.UTC()
			return &t, nil
		}
	}
	return nil, fmt.Errorf("github: cannot read the token's expiry %q", v)
}

// repository reads github.com/<owner>/<repo>.
func repository(resource string) (owner, repo string, ok bool) {
	rest, ok := strings.CutPrefix(resource, "github.com/")
	if !ok {
		return "", "", false
	}
	owner, repo, err := splitRepo(rest)
	return owner, repo, err == nil
}
