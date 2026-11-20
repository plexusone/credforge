package review_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/review"
)

// dbID is a credential's ID in the registry, not a value.
const dbID = "app/prod/DB"

func registry() *credspec.Registry {
	return credspec.NewRegistry(credspec.Credential{
		ID: dbID, Name: "DB", System: "example-app", Environment: "prod", Kind: credspec.KindRandomSecret,
		Status: credspec.StatusActive, Owner: "ops", Issuer: credspec.Issuer{Type: credspec.IssuerSelf},
		Generation: credspec.Generation{Method: credspec.MethodRandom},
		Stores:     []credspec.Store{{Type: "aws-ssm", Role: credspec.RolePrimary, Account: "hosting", Path: "/app/prod/DB"}},
		Rotation:   credspec.Rotation{Policy: credspec.PolicyScheduled, IntervalDays: 90},
		Handling:   credspec.Handling{Generate: credspec.ActorSystem, Distribute: credspec.ActorSystem, Rotate: credspec.ActorHuman},
	})
}

func newServer(t *testing.T) (*review.Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	s := &review.Server{
		Title: "Example", Registry: registry(), By: "ops",
		EventsPath: filepath.Join(dir, "events.json"), ReviewsPath: filepath.Join(dir, "reviews.json"),
		Now: func() time.Time { return day0 },
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func do(t *testing.T, method, url, body string, header map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(b)
}

func TestPageAndData(t *testing.T) {
	_, ts := newServer(t)
	res, body := do(t, "GET", ts.URL+"/", "", nil)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "app.js") {
		t.Fatalf("page: %d %s", res.StatusCode, body)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("CSP = %q", csp)
	}
	res, body = do(t, "GET", ts.URL+"/api/data", "", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("data: %d %s", res.StatusCode, body)
	}
	var d review.Data
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Credentials) != 1 || d.Credentials[0].Assessment.State != credspec.StateUnrecorded || d.CanCheck {
		t.Fatalf("data = %+v", d)
	}
}

func TestReviewIsSavedAndCleared(t *testing.T) {
	s, ts := newServer(t)
	res, body := do(t, "PUT", ts.URL+"/api/reviews", `{"subject":"app/prod/DB","decision":"change","note":"rotate monthly"}`, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("put: %d %s", res.StatusCode, body)
	}
	f, err := review.Load(s.ReviewsPath)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := f.Find(dbID)
	if !ok || r.Note != "rotate monthly" || r.By != "ops" || !r.At.Equal(day0) {
		t.Fatalf("saved = %+v", f.Reviews)
	}
	if res, body := do(t, "PUT", ts.URL+"/api/reviews", `{"subject":"aws-ssm:hosting:/app/prod/OLD","decision":"remove"}`, nil); res.StatusCode != http.StatusOK {
		t.Fatalf("store key: %d %s", res.StatusCode, body)
	}
	if res, _ := do(t, "PUT", ts.URL+"/api/reviews", `{"subject":"nonsense","decision":"approved"}`, nil); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unknown subject was accepted: %d", res.StatusCode)
	}
	if res, _ := do(t, "PUT", ts.URL+"/api/reviews", `{"subject":"app/prod/DB","decision":""}`, nil); res.StatusCode != http.StatusOK {
		t.Fatalf("clear: %d", res.StatusCode)
	}
	if f, err = review.Load(s.ReviewsPath); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Find(dbID); ok {
		t.Fatal("the review was not cleared")
	}
}

func TestEventIsLogged(t *testing.T) {
	s, ts := newServer(t)
	res, body := do(t, "POST", ts.URL+"/api/events", `{"credential":"app/prod/DB","type":"created","note":"first value"}`, nil)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("post: %d %s", res.StatusCode, body)
	}
	log, err := credspec.LoadLog(s.EventsPath, s.Registry)
	if err != nil {
		t.Fatal(err)
	}
	if h := log.History(dbID); len(h) != 1 || h[0].By != "ops" || !h[0].At.Equal(day0) {
		t.Fatalf("history = %+v", h)
	}
	for name, b := range map[string]string{
		"unknown ID":        `{"credential":"app/prod/NOPE","type":"verified"}`,
		"future":            `{"credential":"app/prod/DB","type":"verified","at":"2030-01-01T00:00:00Z"}`,
		"expires on verify": `{"credential":"app/prod/DB","type":"verified","expires":"2027-01-01T00:00:00Z"}`,
		"unknown field":     `{"credential":"app/prod/DB","type":"verified","value":"x"}`,
	} {
		if res, _ := do(t, "POST", ts.URL+"/api/events", b, nil); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, res.StatusCode)
		}
	}
}

func TestGuardRefusesForeignHostsAndWrites(t *testing.T) {
	_, ts := newServer(t)
	if res, _ := do(t, "GET", ts.URL+"/api/data", "", map[string]string{"Host": "attacker.example:80"}); res.StatusCode != http.StatusForbidden {
		t.Errorf("foreign Host: %d", res.StatusCode)
	}
	if res, _ := do(t, "PUT", ts.URL+"/api/reviews", `{"subject":"app/prod/DB","decision":"approved"}`, map[string]string{"Origin": "https://attacker.example"}); res.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin write: %d", res.StatusCode)
	}
	req, err := http.NewRequestWithContext(context.Background(), "PUT", ts.URL+"/api/reviews", strings.NewReader(`{"subject":"app/prod/DB","decision":"approved"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("a form-style write: %d", res.StatusCode)
	}
	for host, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "0.0.0.0": false, "example.com": false} {
		if got := review.LoopbackHost(host); got != want {
			t.Errorf("LoopbackHost(%q) = %v", host, got)
		}
	}
}

func TestLiveCheckIsKept(t *testing.T) {
	s, ts := newServer(t)
	calls := 0
	s.Check = func(context.Context) (credforge.Report, error) {
		calls++
		if calls == 2 {
			return credforge.Report{}, errors.New("token expired")
		}
		return credforge.Report{Findings: []credforge.Finding{{State: credforge.StateMissing, Credential: dbID}}}, nil
	}
	if res, body := do(t, "POST", ts.URL+"/api/check", "{}", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("check: %d %s", res.StatusCode, body)
	}
	d, err := s.Data()
	if err != nil {
		t.Fatal(err)
	}
	if !d.CanCheck || d.Check == nil || d.Check.Report == nil || d.Check.Report.Count(credforge.StateMissing) != 1 {
		t.Fatalf("check = %+v", d.Check)
	}
	if _, body := do(t, "POST", ts.URL+"/api/check", "{}", nil); !strings.Contains(body, "token expired") {
		t.Fatalf("a failed check should say why: %s", body)
	}
}
