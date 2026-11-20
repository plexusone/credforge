package credforge_test

import (
	"testing"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"

	"github.com/plexusone/credforge"
)

func TestRecord(t *testing.T) {
	a1 := ssm("/app/prod/A1")
	a2 := gha(repo, "A")
	e := ssm("/app/prod/E")
	p := ssm("/app/prod/P")
	reg := credspec.NewRegistry(
		cred("a", credspec.StatusActive, a1, a2),
		cred("e", credspec.StatusActive, e),
		cred("p", credspec.StatusActive, p),
	)
	log := logOf(t, reg, ev("e", credspec.EventCreated, day0), ev("p", credspec.EventCreated, day0))
	scopes := []credforge.Scope{
		{Type: credspec.StoreAWSSSM, Account: "hosting", Dir: "/app/prod"},
		{Type: credspec.StoreGitHubActions, Account: repo},
	}
	observed := []credforge.Observation{
		obs(a1, day0.Add(2*day)),
		obs(a2, day0.Add(day)), // the earlier: the created event's time
		obs(e, day0.Add(9*day)),
		obs(p, day0),
	}
	rep := credforge.Compare(reg, log, scopes, observed, nil, credforge.Options{Grace: time.Hour})
	got, err := credforge.Record(reg, log, rep, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// a: made when first observed, then copied to the later store; e:
	// changed after its last event.
	want := []credspec.Event{
		{Credential: "a", Type: credspec.EventCreated, At: day0.Add(day)},
		{Credential: "a", Type: credspec.EventDeployed, At: day0.Add(2 * day)},
		{Credential: "e", Type: credspec.EventDeployed, At: day0.Add(9 * day)},
	}
	if len(got) != len(want) {
		t.Fatalf("recorded %d events: %+v", len(got), got)
	}
	for i, g := range got {
		w := want[i]
		if g.Credential != w.Credential || g.Type != w.Type || !g.At.Equal(w.At) || g.By != credforge.Recorder {
			t.Errorf("event %d: %+v, want %+v by %s", i, g, w, credforge.Recorder)
		}
	}
	if err := log.Validate(reg); err != nil {
		t.Fatalf("log after recording: %v", err)
	}
	// Recorded, the same observations compare as present.
	rep = credforge.Compare(reg, log, scopes, observed, nil, credforge.Options{Grace: time.Hour})
	if n := len(rep.In(credforge.StateUnrecorded, credforge.StateChanged)); n != 0 {
		t.Fatalf("after recording, %d still unrecorded or changed: %q", n, states(rep))
	}
}
