package credforge_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"

	"github.com/plexusone/credforge"
)

// value is a test value, not a real secret.
const value = "test-value"

// fakeWriter records writes and fails on the keys in fail.
type fakeWriter struct {
	wrote []credforge.Key
	got   []string
	fail  map[credforge.Key]bool
}

func (w *fakeWriter) Write(_ context.Context, k credforge.Key, v string) error {
	if w.fail[k] {
		return errors.New("refused")
	}
	w.wrote = append(w.wrote, k)
	w.got = append(w.got, v)
	return nil
}

type fakeProber struct {
	probe credforge.Probe
	err   error
	calls int
}

func (p *fakeProber) Probe(context.Context, credspec.Credential, string) (credforge.Probe, error) {
	p.calls++
	return p.probe, p.err
}

// installer reaches the given store types with w.
func installer(w *fakeWriter, p credforge.Prober, types ...string) *credforge.Installer {
	return &credforge.Installer{
		Writer: func(storeType, _ string) (credforge.Writer, error) {
			for _, t := range types {
				if t == storeType {
					return w, nil
				}
			}
			return nil, nil
		},
		Prober: p,
		Now:    func() time.Time { return day0 },
	}
}

func TestInstallPlan(t *testing.T) {
	web, api := gha(repo, "TOKEN"), gha("example-org/api", "TOKEN")
	vault := credspec.Store{Type: credspec.StorePasswordManager, Role: credspec.RoleBackup, Account: "ops", Path: "token"}
	host := credspec.Store{Type: credspec.StoreHostFile, Role: credspec.RoleRendered, Path: "/etc/app/token"}
	reg := credspec.NewRegistry(
		cred("tok", credspec.StatusActive, web, api, vault, host),
		cred("old", credspec.StatusActive, ssm("/app/prod/OLD")),
	)
	log := logOf(t, reg, ev("old", credspec.EventCreated, day0))
	in := installer(&fakeWriter{}, nil, credspec.StoreGitHubActions, credspec.StoreAWSSSM)

	p, err := in.Plan(reg, log, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if p.Event != credspec.EventCreated || p.Replaces != nil {
		t.Errorf("a credential with no events: %s, replaces %v; want created", p.Event, p.Replaces)
	}
	var writes, skipped []string
	for _, d := range p.Writes {
		writes = append(writes, d.Store.String())
	}
	for _, s := range p.Skipped {
		skipped = append(skipped, s.Store.Path)
	}
	equal(t, writes, []string{credforge.KeyOf(web).String(), credforge.KeyOf(api).String()})
	equal(t, skipped, []string{"token", "/etc/app/token"})

	p, err = in.Plan(reg, log, "old")
	if err != nil {
		t.Fatal(err)
	}
	if p.Event != credspec.EventRotated || p.Replaces == nil || !p.Replaces.Equal(day0) {
		t.Errorf("a credential made before: %s, replaces %v; want rotated, %v", p.Event, p.Replaces, day0)
	}
}

func TestInstallPlanRefuses(t *testing.T) {
	made := cred("made", credspec.StatusActive, ssm("/app/prod/DB"))
	made.Generation.Provisioner = &credspec.Provisioner{Tool: "db-tool", Command: "db-tool apply", RunBy: credspec.ActorHuman, Stores: true}
	retired := cred("retired", credspec.StatusRetired, ssm("/app/prod/R"))
	vaultOnly := cred("vault", credspec.StatusActive, credspec.Store{Type: credspec.StorePasswordManager, Role: credspec.RolePrimary, Path: "v"})
	reg := credspec.NewRegistry(made, retired, vaultOnly)
	log := credspec.NewLog()
	in := installer(&fakeWriter{}, nil, credspec.StoreAWSSSM)
	for id, want := range map[string]string{
		"made":    `run "db-tool apply"`,
		"retired": "retired",
		"vault":   "no store",
		"missing": "no credential",
	} {
		if _, err := in.Plan(reg, log, id); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error naming %q", id, err, want)
		}
	}
}

func TestInstallApply(t *testing.T) {
	web, api := gha(repo, "TOKEN"), gha("example-org/api", "TOKEN")
	reg := credspec.NewRegistry(cred("tok", credspec.StatusActive, web, api))
	log := credspec.NewLog()
	expires := day0.Add(365 * day)
	w := &fakeWriter{}
	pr := &fakeProber{probe: credforge.Probe{Checked: []string{"reads example-org/lib"}, Expires: &expires}}
	in := installer(w, pr, credspec.StoreGitHubActions)
	p, err := in.Plan(reg, log, "tok")
	if err != nil {
		t.Fatal(err)
	}
	res, err := in.Apply(context.Background(), reg, log, p, value, credforge.InstallOptions{By: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.wrote) != 2 || w.got[0] != value || w.got[1] != value {
		t.Fatalf("wrote %v", w.wrote)
	}
	if len(res.Events) != 2 || res.Events[0].Type != credspec.EventCreated || res.Events[1].Type != credspec.EventVerified {
		t.Fatalf("events %+v; want created, then verified", res.Events)
	}
	if e := res.Events[0]; e.Expires == nil || !e.Expires.Equal(expires) || !e.At.Equal(day0) || e.By != "ops" {
		t.Errorf("created %+v; want at %v, expiring %v as GitHub reported, by ops", e, day0, expires)
	}
	if err := log.Validate(reg); err != nil {
		t.Fatal(err)
	}
	// The stores, set as the install ran, compare as present.
	set := day0.Add(time.Second)
	rep := credforge.Compare(reg, log,
		[]credforge.Scope{{Type: credspec.StoreGitHubActions, Account: repo}, {Type: credspec.StoreGitHubActions, Account: "example-org/api"}},
		[]credforge.Observation{obs(web, set), obs(api, set)}, nil, credforge.Options{Grace: credforge.DefaultGrace})
	equal(t, states(rep), []string{"present tok TOKEN", "present tok TOKEN"})

	// The operator's expiry wins over the issuer's, and the difference is
	// reported.
	mine := day0.Add(30 * day)
	p, err = in.Plan(reg, log, "tok")
	if err != nil {
		t.Fatal(err)
	}
	res, err = in.Apply(context.Background(), reg, log, p, value, credforge.InstallOptions{Expires: &mine})
	if err != nil {
		t.Fatal(err)
	}
	if res.Events[0].Type != credspec.EventRotated || !res.Events[0].Expires.Equal(mine) || !res.ExpiryDiffers {
		t.Errorf("second install %+v, differs %v; want rotated, expiring %v, with the difference reported", res.Events[0], res.ExpiryDiffers, mine)
	}
}

func TestInstallApplyFailures(t *testing.T) {
	web, api := gha(repo, "TOKEN"), gha("example-org/api", "TOKEN")
	reg := credspec.NewRegistry(cred("tok", credspec.StatusActive, web, api))
	log := credspec.NewLog()
	ctx := context.Background()

	// A failed probe writes nothing.
	w := &fakeWriter{}
	in := installer(w, &fakeProber{err: errors.New("cannot read example-org/lib")}, credspec.StoreGitHubActions)
	p, err := in.Plan(reg, log, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Apply(ctx, reg, log, p, value, credforge.InstallOptions{}); err == nil || !strings.Contains(err.Error(), "nothing was written") {
		t.Errorf("failed probe: %v", err)
	}
	if len(w.wrote) != 0 {
		t.Errorf("a failed probe wrote %v", w.wrote)
	}

	// A failed write names what was written and records nothing.
	w = &fakeWriter{fail: map[credforge.Key]bool{credforge.KeyOf(api): true}}
	in = installer(w, nil, credspec.StoreGitHubActions)
	if p, err = in.Plan(reg, log, "tok"); err != nil {
		t.Fatal(err)
	}
	_, err = in.Apply(ctx, reg, log, p, value, credforge.InstallOptions{})
	if err == nil || !strings.Contains(err.Error(), "already written: "+credforge.KeyOf(web).String()) {
		t.Errorf("failed write: %v", err)
	}
	if len(log.Events) != 0 {
		t.Errorf("a failed write recorded %+v", log.Events)
	}

	for _, v := range []string{"", " " + value, value + "\n"} {
		if _, err := in.Apply(ctx, reg, log, p, v, credforge.InstallOptions{}); err == nil {
			t.Errorf("value %q was accepted", v)
		}
	}
}
