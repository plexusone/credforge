package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/awsssm"
	"github.com/plexusone/credforge/targets"
)

// installValue is a test value, not a real secret.
const installValue = "test-value"

type recordingWriter struct{ got map[string]string }

func (w *recordingWriter) Write(_ context.Context, k credforge.Key, v string) error {
	w.got[k.String()] = v
	return nil
}

type passingProber struct{}

func (passingProber) Probe(context.Context, credspec.Credential, string) (credforge.Probe, error) {
	return credforge.Probe{Checked: []string{"the token reads example-org/lib"}}, nil
}

// runInstall runs install over the fixture with stdin as standard input.
func runInstall(t *testing.T, dir, stdin string, args ...string) (*recordingWriter, string, error) {
	t.Helper()
	w := &recordingWriter{got: map[string]string{}}
	cmd := New(Options{
		Writer: func(*targets.File) func(string, string) (credforge.Writer, error) {
			return func(storeType, _ string) (credforge.Writer, error) {
				if storeType == "github-actions" {
					return w, nil
				}
				return nil, nil
			}
		},
		Prober: passingProber{},
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(append(append([]string{"install"}, args...),
		"--registry", filepath.Join(dir, "credentials.json"),
		"--events", filepath.Join(dir, "events.json"),
		"--targets", filepath.Join(dir, "targets.json")))
	err := cmd.ExecuteContext(context.Background())
	if strings.Contains(out.String(), installValue) {
		t.Errorf("the output holds the value:\n%s", out.String())
	}
	return w, out.String(), err
}

func events(t *testing.T, dir string) []credspec.Event {
	t.Helper()
	reg, err := credspec.LoadRegistry(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := credspec.LoadLog(filepath.Join(dir, "events.json"), reg)
	if err != nil {
		t.Fatal(err)
	}
	return log.History(deployID)
}

func TestInstall(t *testing.T) {
	dir := fixture(t, "https://github.example")
	before := len(events(t, dir))

	w, out, err := runInstall(t, dir, "", deployID, "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "write  github-actions:example-org/web:DEPLOY_TOKEN") || !strings.Contains(out, "(rotated), replacing the one made") {
		t.Errorf("dry run:\n%s", out)
	}
	if len(w.got) != 0 || len(events(t, dir)) != before {
		t.Errorf("a dry run wrote %v or recorded", w.got)
	}

	if _, _, err := runInstall(t, dir, installValue, deployID, "--stdin"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("--stdin without --yes: %v", err)
	}
	if _, _, err := runInstall(t, dir, installValue, deployID); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Errorf("no terminal and no --stdin: %v", err)
	}

	w, out, err = runInstall(t, dir, installValue+"\n", deployID, "--stdin", "--yes", "--expires", "2027-01-02", "--by", "ops")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := w.got["github-actions:example-org/web:DEPLOY_TOKEN"]; got != installValue {
		t.Errorf("wrote %q", got)
	}
	evs := events(t, dir)
	if len(evs) != before+2 {
		t.Fatalf("recorded %d event(s); want rotated and verified", len(evs)-before)
	}
	rot, ver := evs[len(evs)-2], evs[len(evs)-1]
	want := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	if rot.Type != credspec.EventRotated || rot.Expires == nil || !rot.Expires.Equal(want) || rot.By != "ops" || ver.Type != credspec.EventVerified {
		t.Errorf("events %+v, %+v", rot, ver)
	}
	if !strings.Contains(out, "checked  the token reads example-org/lib") || !strings.Contains(out, "expires 2027-01-02") {
		t.Errorf("output:\n%s", out)
	}
}

func TestInstallBadExpiry(t *testing.T) {
	dir := fixture(t, "https://github.example")
	if _, _, err := runInstall(t, dir, installValue, deployID, "--stdin", "--yes", "--expires", "next year"); Code(err) != ExitError {
		t.Errorf("a bad --expires: %v", err)
	}
}

func TestConnectorWriter(t *testing.T) {
	tf := &targets.File{FormatVersion: targets.FormatVersion, Bindings: []targets.Binding{
		{Store: "github-actions", Account: "example-org/*", GitHub: &targets.GitHub{TokenEnv: "TEST_WRITER_TOKEN"}},
	}}
	c := NewConnector(tf)
	if w, err := c.Writer("aws-ssm", "hosting"); w != nil || err != nil {
		t.Errorf("an unbound store: %v, %v", w, err)
	}
	if w, err := c.Writer("github-actions", "example-org"); w != nil || err != nil {
		t.Errorf("an organization's secrets: %v, %v", w, err)
	}
	t.Setenv("TEST_WRITER_TOKEN", "")
	if w, err := c.Writer("github-actions", "example-org/web"); w != nil || err == nil {
		t.Errorf("no token: %v, %v; want an error and no writer", w, err)
	}
	t.Setenv("TEST_WRITER_TOKEN", "test-token")
	if w, err := c.Writer("github-actions", "example-org/web"); w == nil || err != nil {
		t.Errorf("a bound repository: %v, %v", w, err)
	}
}

func TestGenerateCommand(t *testing.T) {
	dir := fixture(t, "https://github.example")
	reg, err := credspec.LoadRegistry(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := cred("app/prod/SESSION_KEY", credspec.Store{Type: "aws-ssm", Role: credspec.RolePrimary, Account: "hosting", Path: "/app/prod/SESSION_KEY"})
	c.Generation.Format = credspec.FormatHex32
	reg.Add(c)
	if err := reg.Save(filepath.Join(dir, "credentials.json")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_GITHUB_TOKEN", "test-token")
	w := &recordingWriter{got: map[string]string{}}
	newCmd := func(args ...string) (string, error) {
		cmd := New(Options{
			Connector: func(f *targets.File) credforge.Connector {
				cn := NewConnector(f)
				cn.newAWS = func(context.Context, string, string) (*awsssm.Observer, error) {
					return &awsssm.Observer{API: fakeSSM{}}, nil
				}
				return cn
			},
			Writer: func(*targets.File) func(string, string) (credforge.Writer, error) {
				return func(string, string) (credforge.Writer, error) { return w, nil }
			},
		})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetIn(strings.NewReader(""))
		cmd.SetArgs(append(append([]string{"generate"}, args...),
			"--only", "app/prod/*",
			"--registry", filepath.Join(dir, "credentials.json"),
			"--events", filepath.Join(dir, "events.json"),
			"--targets", filepath.Join(dir, "targets.json")))
		err := cmd.ExecuteContext(context.Background())
		return out.String(), err
	}
	out, err := newCmd("--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "make   app/prod/SESSION_KEY (hex32) in aws-ssm:hosting:/app/prod/SESSION_KEY") || len(w.got) != 0 {
		t.Errorf("dry run wrote %v:\n%s", w.got, out)
	}
	if out, err = newCmd(); err != nil || len(w.got) != 0 || !strings.Contains(out, "nothing made") {
		t.Errorf("unconfirmed: %v, wrote %v:\n%s", err, w.got, out)
	}
	if out, err = newCmd("--yes"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	v := w.got["aws-ssm:hosting:/app/prod/SESSION_KEY"]
	if len(v) != 64 || strings.Contains(out, v) {
		t.Errorf("wrote a %d-character value, or printed it:\n%s", len(v), out)
	}
	reg, err = credspec.LoadRegistry(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := credspec.LoadLog(filepath.Join(dir, "events.json"), reg)
	if err != nil {
		t.Fatal(err)
	}
	if h := log.History("app/prod/SESSION_KEY"); len(h) != 1 || h[0].Type != credspec.EventCreated {
		t.Errorf("history %+v", h)
	}
}

func TestSetupCommand(t *testing.T) {
	dir := fixture(t, "https://github.example")
	cmd := New(Options{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"setup", "--system", "example-app", "--env", "prod", "list",
		"--registry", filepath.Join(dir, "credentials.json"), "--events", filepath.Join(dir, "events.json")})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "1.3") {
		t.Errorf("list:\n%s", out.String())
	}
	// The progress log is named for the system and environment.
	cmd = New(Options{})
	out.Reset()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"setup", "--system", "example-app", "--env", "prod", "record", "1.1", "started",
		"--registry", filepath.Join(dir, "credentials.json"), "--events", filepath.Join(dir, "events.json")})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("record: %v\n%s", err, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "setup-example-app-prod.json")); err != nil {
		t.Errorf("progress log: %v", err)
	}
	cmd = New(Options{})
	out.Reset()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"setup", "--system", "example-app", "--env", "prod", "export",
		"--registry", filepath.Join(dir, "credentials.json"), "--events", filepath.Join(dir, "events.json")})
	if err := cmd.ExecuteContext(context.Background()); err != nil || !strings.Contains(out.String(), `"id": "credentials-example-app-prod"`) {
		t.Errorf("export: %v\n%s", err, out.String())
	}
}
