package credforge_test

import (
	"context"
	"errors"
	"testing"

	"github.com/plexusone/systemspec-credential/credspec"

	"github.com/plexusone/credforge"
)

// fakeObserver lists fixed observations, and records the scopes asked for.
type fakeObserver struct {
	items []credforge.Observation
	asked []credforge.Scope
	err   error
}

func (f *fakeObserver) Observe(_ context.Context, s credforge.Scope) ([]credforge.Observation, error) {
	f.asked = append(f.asked, s)
	if f.err != nil {
		return nil, f.err
	}
	var out []credforge.Observation
	for _, o := range f.items {
		if s.Contains(o.Key) {
			out = append(out, o)
		}
	}
	return out, nil
}

type dirObserver struct{ *fakeObserver }

func (d dirObserver) Scope(k credforge.Key) credforge.Scope {
	return credforge.Scope{Type: k.Type, Account: k.Account, Dir: dirOf(k.Path)}
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "."
}

type fakeRefs map[string][]credforge.Reference

func (f fakeRefs) References(_ context.Context, account string) ([]credforge.Reference, error) {
	return f[account], nil
}

type fakeConnector struct {
	observers map[string]credforge.Observer // by type
	refs      map[string]credforge.ReferenceFinder
	unbound   string // an account with no binding
}

func (f fakeConnector) Observer(typ, account string) (credforge.Observer, error) {
	if account == f.unbound {
		return nil, nil
	}
	return f.observers[typ], nil
}

func (f fakeConnector) References(typ, _ string) (credforge.ReferenceFinder, error) {
	return f.refs[typ], nil
}

func TestCheck(t *testing.T) {
	a := ssm("/app/prod/A")
	b := ssm("/app/prod/B")
	other := ssm("/app/other/C")
	gh := gha(repo, "TOKEN")
	off := gha("example-org/unbound", "TOKEN")
	reg := credspec.NewRegistry(
		cred("a", credspec.StatusActive, a),
		cred("b", credspec.StatusActive, b),
		cred("c", credspec.StatusActive, other),
		cred("t", credspec.StatusActive, gh),
		cred("u", credspec.StatusActive, off),
	)
	log := logOf(t, reg, ev("a", credspec.EventCreated, day0), ev("b", credspec.EventCreated, day0),
		ev("c", credspec.EventCreated, day0), ev("t", credspec.EventCreated, day0))
	ssmObs := &fakeObserver{items: []credforge.Observation{obs(a, day0), obs(b, day0), obs(other, day0)}}
	ghObs := &fakeObserver{items: []credforge.Observation{obs(gh, day0)}}
	conn := fakeConnector{
		observers: map[string]credforge.Observer{
			credspec.StoreAWSSSM:        dirObserver{ssmObs},
			credspec.StoreGitHubActions: ghObs,
		},
		refs: map[string]credforge.ReferenceFinder{credspec.StoreGitHubActions: fakeRefs{
			"example-org/extra": {{Key: credforge.Key{Type: credspec.StoreGitHubActions, Account: "example-org/extra", Path: "TOKEN"}, Source: "ci.yaml"}},
		}},
		unbound: "example-org/unbound",
	}
	ch := &credforge.Checker{Connector: conn, Extra: map[string][]string{credspec.StoreGitHubActions: {"example-org/extra"}}}
	rep, err := ch.Check(context.Background(), reg, log, credforge.Options{Grace: day})
	if err != nil {
		t.Fatal(err)
	}
	equal(t, states(rep), []string{
		"unregistered  TOKEN",
		"unobserved u TOKEN",
		"present a /app/prod/A",
		"present b /app/prod/B",
		"present c /app/other/C",
		"present t TOKEN",
	})
	// Two SSM directories, each listed once; the repository and the extra
	// one listed whole.
	if len(ssmObs.asked) != 2 || ssmObs.asked[0].Dir != "/app/prod" || ssmObs.asked[1].Dir != "/app/other" {
		t.Errorf("SSM scopes asked: %+v", ssmObs.asked)
	}
	if len(ghObs.asked) != 2 {
		t.Errorf("GitHub scopes asked: %+v", ghObs.asked)
	}
	if len(rep.Scopes) != 4 {
		t.Errorf("report scopes: %+v", rep.Scopes)
	}

	ssmObs.err = errors.New("throttled")
	if _, err := ch.Check(context.Background(), reg, log, credforge.Options{}); err == nil {
		t.Fatal("Check with a failing observer succeeded")
	}
}

func TestCheckExtraNeedsBinding(t *testing.T) {
	reg := credspec.NewRegistry(cred("a", credspec.StatusActive, ssm("/app/prod/A")))
	ch := &credforge.Checker{
		Connector: fakeConnector{unbound: "example-org/x"},
		Extra:     map[string][]string{credspec.StoreGitHubActions: {"example-org/x"}},
	}
	if _, err := ch.Check(context.Background(), reg, credspec.NewLog(), credforge.Options{}); err == nil {
		t.Fatal("Check scanned an unbound extra account")
	}
}
