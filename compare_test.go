package credforge_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"

	"github.com/plexusone/credforge"
)

const repo = "example-org/web"

var (
	day0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	day  = 24 * time.Hour
)

// cred is a valid credential stored as each of stores.
func cred(id string, status credspec.Status, stores ...credspec.Store) credspec.Credential {
	return credspec.Credential{
		ID: id, Name: id, System: "example-app", Environment: "prod", Kind: credspec.KindRandomSecret,
		Status: status, Owner: "ops", Issuer: credspec.Issuer{Type: credspec.IssuerSelf},
		Generation: credspec.Generation{Method: credspec.MethodRandom},
		Stores:     stores,
		Rotation:   credspec.Rotation{Policy: credspec.PolicyScheduled, IntervalDays: 90},
		Handling: credspec.Handling{Generate: credspec.ActorHuman, Distribute: credspec.ActorSystem,
			Rotate: credspec.ActorHuman},
	}
}

func ssm(path string) credspec.Store {
	return credspec.Store{Type: credspec.StoreAWSSSM, Role: credspec.RolePrimary, Account: "hosting", Path: path}
}

func gha(account, name string) credspec.Store {
	return credspec.Store{Type: credspec.StoreGitHubActions, Role: credspec.RolePrimary, Account: account, Path: name}
}

func obs(s credspec.Store, at time.Time) credforge.Observation {
	return credforge.Observation{Key: credforge.KeyOf(s), Modified: at}
}

func logOf(t *testing.T, reg *credspec.Registry, events ...credspec.Event) *credspec.Log {
	t.Helper()
	l := credspec.NewLog()
	for _, e := range events {
		if err := l.Append(reg, e); err != nil {
			t.Fatalf("append %v: %v", e, err)
		}
	}
	return l
}

func ev(id string, typ credspec.EventType, at time.Time) credspec.Event {
	return credspec.Event{Credential: id, Type: typ, At: at, By: "ops"}
}

// states maps each finding to "state credential store-path".
func states(rep credforge.Report) []string {
	out := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		out = append(out, fmt.Sprintf("%s %s %s", f.State, f.Credential, f.Store.Path))
	}
	return out
}

func equal(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("findings:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestCompareStoreStates(t *testing.T) {
	a := ssm("/app/prod/A")
	b := ssm("/app/prod/B")
	c := ssm("/app/prod/C")
	d := ssm("/app/prod/D")
	e := ssm("/app/prod/E")
	f := ssm("/elsewhere/F")
	reg := credspec.NewRegistry(
		cred("a", credspec.StatusActive, a), // present
		cred("b", credspec.StatusActive, b), // missing
		cred("c", credspec.StatusActive, c), // unrecorded
		cred("d", credspec.StatusActive, d), // stale
		cred("e", credspec.StatusActive, e), // changed
		cred("f", credspec.StatusActive, f), // unobserved
	)
	log := logOf(t, reg,
		ev("a", credspec.EventCreated, day0),
		ev("b", credspec.EventCreated, day0),
		ev("d", credspec.EventCreated, day0),
		ev("d", credspec.EventRotated, day0.Add(10*day)),
		ev("e", credspec.EventCreated, day0),
	)
	scopes := []credforge.Scope{{Type: credspec.StoreAWSSSM, Account: "hosting", Dir: "/app/prod"}}
	observed := []credforge.Observation{
		obs(a, day0.Add(time.Hour)),
		obs(c, day0),
		obs(d, day0),                  // made before the rotation: stale
		obs(e, day0.Add(5*day)),       // set after the last event: changed
		obs(ssm("/app/prod/Z"), day0), // nobody's: unlisted
	}
	rep := credforge.Compare(reg, log, scopes, observed, nil, credforge.Options{Grace: credforge.DefaultGrace})
	equal(t, states(rep), []string{
		"missing b /app/prod/B",
		"stale d /app/prod/D",
		"changed e /app/prod/E",
		"unrecorded c /app/prod/C",
		"unlisted  /app/prod/Z",
		"unobserved f /elsewhere/F",
		"present a /app/prod/A",
	})
	if got := rep.Count(credforge.StateMissing); got != 1 {
		t.Errorf("Count(missing) = %d", got)
	}
	if got := len(rep.In(credforge.StateStale, credforge.StateChanged)); got != 2 {
		t.Errorf("In(stale, changed) = %d", got)
	}
}

func TestCompareGrace(t *testing.T) {
	s := ssm("/app/prod/A")
	reg := credspec.NewRegistry(cred("a", credspec.StatusActive, s))
	// Installed, then recorded a few hours later: within the grace.
	log := logOf(t, reg, ev("a", credspec.EventRotated, day0))
	scopes := []credforge.Scope{{Type: credspec.StoreAWSSSM, Account: "hosting", Dir: "/app/prod"}}
	for _, tc := range []struct {
		name  string
		at    time.Time
		grace time.Duration
		want  credforge.State
	}{
		{"set before, within grace", day0.Add(-3 * time.Hour), day, credforge.StatePresent},
		{"set before, beyond grace", day0.Add(-2 * day), day, credforge.StateStale},
		{"set after, within grace", day0.Add(3 * time.Hour), day, credforge.StatePresent},
		{"set after, beyond grace", day0.Add(2 * day), day, credforge.StateChanged},
		{"exact, no grace", day0, 0, credforge.StatePresent},
		{"a second early, no grace", day0.Add(-time.Second), 0, credforge.StateStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := credforge.Compare(reg, log, scopes, []credforge.Observation{obs(s, tc.at)}, nil, credforge.Options{Grace: tc.grace})
			if got := rep.Findings[0].State; got != tc.want {
				t.Fatalf("got %s (%s), want %s", got, rep.Findings[0].Detail, tc.want)
			}
		})
	}
}

func TestCompareDeployedCountsAsRecorded(t *testing.T) {
	s := ssm("/app/prod/A")
	reg := credspec.NewRegistry(cred("a", credspec.StatusActive, s))
	log := logOf(t, reg, ev("a", credspec.EventCreated, day0), ev("a", credspec.EventDeployed, day0.Add(30*day)))
	scopes := []credforge.Scope{{Type: credspec.StoreAWSSSM, Account: "hosting", Dir: "/app/prod"}}
	rep := credforge.Compare(reg, log, scopes, []credforge.Observation{obs(s, day0.Add(30*day))}, nil, credforge.Options{Grace: day})
	equal(t, states(rep), []string{"present a /app/prod/A"})
}

func TestComparePlannedOptionalRetiredAndOnly(t *testing.T) {
	planned := ssm("/app/prod/P")
	optional := ssm("/app/prod/O")
	old := ssm("/app/prod/OLD")
	skipped := ssm("/app/prod/S")
	opt := cred("o", credspec.StatusActive, optional)
	opt.Tags = []string{"optional"}
	reg := credspec.NewRegistry(
		cred("p", credspec.StatusPlanned, planned),
		opt,
		cred("old", credspec.StatusRetired, old),
		cred("s", credspec.StatusActive, skipped),
	)
	log := credspec.NewLog()
	scopes := []credforge.Scope{{Type: credspec.StoreAWSSSM, Account: "hosting", Dir: "/app/prod"}}
	observed := []credforge.Observation{obs(old, day0), obs(skipped, day0)}
	only := func(c credspec.Credential) bool { return c.ID != "s" }

	rep := credforge.Compare(reg, log, scopes, observed, nil, credforge.Options{Only: only})
	// The planned credential is not compared, the optional one is never
	// missing, the retired one's leftover is unlisted, and the skipped one
	// is still known, so not unlisted.
	equal(t, states(rep), []string{"unlisted old /app/prod/OLD"})

	rep = credforge.Compare(reg, log, scopes, observed, nil, credforge.Options{Only: only, IncludePlanned: true})
	equal(t, states(rep), []string{"missing p /app/prod/P", "unlisted old /app/prod/OLD"})
}

func TestCompareBackupStoresAreNotCompared(t *testing.T) {
	backup := credspec.Store{Type: "password-manager", Role: credspec.RoleBackup, Path: "item"}
	reg := credspec.NewRegistry(cred("a", credspec.StatusActive, ssm("/app/prod/A"), backup))
	rep := credforge.Compare(reg, credspec.NewLog(), nil, nil, nil, credforge.Options{})
	equal(t, states(rep), []string{"unobserved a /app/prod/A"})
}

func TestCompareReferences(t *testing.T) {
	repoSecret := gha(repo, "DEPLOY_TOKEN")
	orgSecret := gha("example-org", "ORG_TOKEN")
	reg := credspec.NewRegistry(
		cred("deploy", credspec.StatusActive, repoSecret),
		cred("org", credspec.StatusActive, orgSecret),
	)
	ref := func(account, name, source string) credforge.Reference {
		return credforge.Reference{Key: credforge.Key{Type: credspec.StoreGitHubActions, Account: account, Path: name}, Source: source}
	}
	refs := []credforge.Reference{
		ref(repo, "DEPLOY_TOKEN", ".github/workflows/ci.yaml"),
		ref(repo, "ORG_TOKEN", ".github/workflows/ci.yaml"),                 // an organization secret
		ref(repo, "NEW_TOKEN", ".github/workflows/ci.yaml"),                 // unknown
		ref(repo, "NEW_TOKEN", ".github/workflows/release.yaml"),            // the same, elsewhere
		ref("example-org/api", "DEPLOY_TOKEN", ".github/workflows/ci.yaml"), // stored only in web
	}
	scopes := []credforge.Scope{{Type: credspec.StoreGitHubActions, Account: repo}}
	observed := []credforge.Observation{obs(repoSecret, day0)}
	log := logOf(t, reg, ev("deploy", credspec.EventCreated, day0))
	rep := credforge.Compare(reg, log, scopes, observed, refs, credforge.Options{Grace: day})
	equal(t, states(rep), []string{
		"unregistered  DEPLOY_TOKEN",
		"unregistered  NEW_TOKEN",
		"unobserved org ORG_TOKEN",
		"present deploy DEPLOY_TOKEN",
	})
	u := rep.In(credforge.StateUnregistered)
	if u[0].Store.Account != "example-org/api" {
		t.Errorf("first unregistered account = %q", u[0].Store.Account)
	}
	if want := ".github/workflows/ci.yaml, .github/workflows/release.yaml"; u[1].Source != want {
		t.Errorf("sources = %q, want %q", u[1].Source, want)
	}
}

func TestParseStates(t *testing.T) {
	got, err := credforge.ParseStates("missing, stale,,unregistered")
	if err != nil || len(got) != 3 || got[2] != credforge.StateUnregistered {
		t.Fatalf("ParseStates = %v, %v", got, err)
	}
	var unknown *credforge.UnknownStateError
	if _, err := credforge.ParseStates("missing,gone"); !errors.As(err, &unknown) || unknown.State != "gone" {
		t.Fatalf("ParseStates(gone) error = %v", err)
	}
}
