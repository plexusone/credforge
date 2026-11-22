package github_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"
	"golang.org/x/crypto/nacl/box"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/github"
)

// Test values, not real secrets.
const (
	writeToken = "test-writer"
	probeValue = "test-value"
)

func TestWriteSealsTheSecret(t *testing.T) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var opened string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+writeToken {
			t.Errorf("%s %s without the writer's token", r.Method, r.URL.Path)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/example-org/web/actions/secrets/public-key":
			writeJSON(t, w, map[string]string{"key_id": "k1", "key": base64.StdEncoding.EncodeToString(pub[:])})
		case r.Method == http.MethodPut && r.URL.Path == "/repos/example-org/web/actions/secrets/DEPLOY_TOKEN":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), probeValue) {
				t.Error("the request holds the value unsealed")
			}
			var in struct {
				EncryptedValue string `json:"encrypted_value"`
				KeyID          string `json:"key_id"`
			}
			if err := json.Unmarshal(body, &in); err != nil {
				t.Fatal(err)
			}
			sealed, err := base64.StdEncoding.DecodeString(in.EncryptedValue)
			if err != nil {
				t.Fatal(err)
			}
			plain, ok := box.OpenAnonymous(nil, sealed, pub, priv)
			if !ok || in.KeyID != "k1" {
				t.Errorf("cannot open the sealed value with key %s", in.KeyID)
			}
			opened = string(plain)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer srv.Close()
	c := &github.Client{BaseURL: srv.URL, Token: writeToken, HTTP: srv.Client()}
	if err := c.Write(context.Background(), credforge.Key{Type: github.StoreType, Account: "example-org/web", Path: "DEPLOY_TOKEN"}, probeValue); err != nil {
		t.Fatal(err)
	}
	if opened != probeValue {
		t.Errorf("GitHub would hold %q", opened)
	}
	for _, k := range []credforge.Key{
		{Type: "aws-ssm", Account: "example-org/web", Path: "X"},
		{Type: github.StoreType, Account: "example-org", Path: "X"},
		{Type: github.StoreType, Account: "example-org/web", Path: "GITHUB_X"},
		{Type: github.StoreType, Account: "example-org/web", Path: "a-b"},
	} {
		if err := c.Write(context.Background(), k, probeValue); err == nil {
			t.Errorf("%s was written", k)
		}
	}
}

// probeServer answers as GitHub does for a token that reads lib, whose
// commits are empty, and not secret-repo.
func probeServer(t *testing.T, expiry string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+probeValue {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if expiry != "" {
			w.Header().Set(github.ExpirationHeader, expiry)
		}
		switch r.URL.Path {
		case "/repos/example-org/lib":
			writeJSON(t, w, map[string]string{"full_name": "example-org/lib"})
		case "/repos/example-org/lib/commits":
			w.WriteHeader(http.StatusConflict)
			writeJSON(t, w, map[string]string{"message": "Git Repository is empty."})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func tokenCred(resources ...string) credspec.Credential {
	c := credspec.Credential{ID: "ci/TOKEN", Issuer: credspec.Issuer{Type: credspec.IssuerGitHub, Account: "example-org"}}
	for _, r := range resources {
		c.Entitlements = append(c.Entitlements, credspec.Entitlement{Resource: r, Access: "contents: read"})
	}
	return c
}

func TestProbe(t *testing.T) {
	srv := probeServer(t, "2027-11-21 00:00:00 UTC")
	defer srv.Close()
	p := &github.Prober{BaseURL: srv.URL, HTTP: srv.Client()}
	ctx := context.Background()

	got, err := p.Probe(ctx, tokenCred("github.com/example-org/lib", "a policy"), probeValue)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2027, 11, 21, 0, 0, 0, 0, time.UTC)
	if len(got.Checked) != 1 || got.Expires == nil || !got.Expires.Equal(want) {
		t.Errorf("probe %+v; want one check and expiry %v", got, want)
	}

	_, err = p.Probe(ctx, tokenCred("github.com/example-org/lib", "github.com/example-org/secret-repo"), probeValue)
	if err == nil || !strings.Contains(err.Error(), "cannot read github.com/example-org/secret-repo") {
		t.Errorf("a repository the token cannot read: %v", err)
	}
	_, err = p.Probe(ctx, tokenCred("github.com/example-org/lib"), "test-wrong")
	if err == nil || !strings.Contains(err.Error(), "expired or revoked") {
		t.Errorf("a token GitHub refuses: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "test-wrong") {
		t.Error("the error holds the value")
	}

	self := tokenCred("github.com/example-org/lib")
	self.Issuer.Type = credspec.IssuerSelf
	if got, err := p.Probe(ctx, self, probeValue); err != nil || len(got.Checked) != 0 {
		t.Errorf("a credential GitHub does not issue: %+v, %v", got, err)
	}
}

func TestProbeExpiry(t *testing.T) {
	for header, ok := range map[string]bool{"": true, "2027-11-21 00:00:00 -0800": true, "soon": false} {
		srv := probeServer(t, header)
		p := &github.Prober{BaseURL: srv.URL, HTTP: srv.Client()}
		got, err := p.Probe(context.Background(), tokenCred("github.com/example-org/lib"), probeValue)
		srv.Close()
		if (err == nil) != ok {
			t.Errorf("expiry %q: %v", header, err)
		}
		if header == "" && got.Expires != nil {
			t.Errorf("no expiry header, but expires %v", got.Expires)
		}
	}
}
