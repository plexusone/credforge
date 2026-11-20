package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/plexusone/systemspec-credential/credspec"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/awsssm"
	"github.com/plexusone/credforge/targets"
)

var day0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// deployID is a credential's ID in the registry, not a value.
const deployID = "app/ci/deploy"

func cred(id string, s credspec.Store) credspec.Credential {
	return credspec.Credential{
		ID: id, Name: id, System: "example-app", Environment: "prod", Kind: credspec.KindRandomSecret,
		Status: credspec.StatusActive, Owner: "ops", Issuer: credspec.Issuer{Type: credspec.IssuerSelf},
		Generation: credspec.Generation{Method: credspec.MethodRandom},
		Stores:     []credspec.Store{s},
		Rotation:   credspec.Rotation{Policy: credspec.PolicyScheduled, IntervalDays: 90},
		Handling: credspec.Handling{Generate: credspec.ActorHuman, Distribute: credspec.ActorSystem,
			Rotate: credspec.ActorHuman},
	}
}

// fixture writes a registry, an event log and a targets file, and returns
// the directory. The deploy token was rotated after its secret was last
// set (stale); the database password has no events (unrecorded); the api
// repository's workflow reads the deploy token, which is stored only in
// web (unregistered).
func fixture(t *testing.T, baseURL string) string {
	t.Helper()
	dir := t.TempDir()
	reg := credspec.NewRegistry(
		cred(deployID, credspec.Store{Type: "github-actions", Role: credspec.RolePrimary, Account: "example-org/web", Path: "DEPLOY_TOKEN"}),
		cred("app/prod/DB", credspec.Store{Type: "aws-ssm", Role: credspec.RolePrimary, Account: "hosting", Path: "/app/prod/DB"}),
		cred("app/prod/HOST_KEY", credspec.Store{Type: "host-file", Role: credspec.RolePrimary, Path: "/etc/app/key.pem"}),
	)
	if err := reg.Save(filepath.Join(dir, "credentials.json")); err != nil {
		t.Fatal(err)
	}
	log := credspec.NewLog()
	for _, e := range []credspec.Event{
		{Credential: deployID, Type: credspec.EventCreated, At: day0, By: "ops"},
		{Credential: deployID, Type: credspec.EventRotated, At: day0.Add(10 * 24 * time.Hour), By: "ops"},
	} {
		if err := log.Append(reg, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Save(filepath.Join(dir, "events.json")); err != nil {
		t.Fatal(err)
	}
	tf := fmt.Sprintf(`{
  "formatVersion": "1",
  "bindings": [
    {"store": "github-actions", "account": "example-org/*", "github": {"tokenEnv": "TEST_GITHUB_TOKEN", "baseUrl": %q}},
    {"store": "aws-ssm", "account": "hosting", "aws": {"profile": "hosting", "region": "us-west-2"}}
  ],
  "scan": {"githubRepositories": ["example-org/api"]}
}`, baseURL)
	if err := os.WriteFile(filepath.Join(dir, "targets.json"), []byte(tf), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func githubServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("%s without the token", r.URL.Path)
		}
		switch r.URL.Path {
		case "/repos/example-org/web/actions/secrets":
			fmt.Fprintf(w, `{"total_count": 1, "secrets": [{"name": "DEPLOY_TOKEN", "updated_at": %q}]}`, day0.Format(time.RFC3339))
		case "/repos/example-org/api/actions/secrets":
			fmt.Fprint(w, `{"total_count": 0, "secrets": []}`)
		case "/repos/example-org/web/contents/.github/workflows":
			w.WriteHeader(http.StatusNotFound)
		case "/repos/example-org/api/contents/.github/workflows":
			fmt.Fprint(w, `[{"name": "ci.yaml", "path": ".github/workflows/ci.yaml", "type": "file"}]`)
		case "/repos/example-org/api/contents/.github/workflows/ci.yaml":
			fmt.Fprint(w, "jobs:\n  t:\n    env:\n      T: ${{ secrets.DEPLOY_TOKEN }}\n")
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	}))
}

type fakeSSM struct{}

func (fakeSSM) DescribeParameters(_ context.Context, in *ssm.DescribeParametersInput, _ ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	return &ssm.DescribeParametersOutput{Parameters: []types.ParameterMetadata{
		{Name: aws.String("/app/prod/DB"), LastModifiedDate: aws.Time(day0)},
		{Name: aws.String("/app/prod/OLD"), LastModifiedDate: aws.Time(day0)},
	}}, nil
}

// run executes the command over the fixture in dir.
func run(t *testing.T, srv *httptest.Server, dir string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("TEST_GITHUB_TOKEN", "test-token")
	var awsProfiles []string
	cmd := New(Options{Connector: func(f *targets.File) credforge.Connector {
		c := NewConnector(f)
		c.HTTP = srv.Client()
		c.newAWS = func(_ context.Context, profile, region string) (*awsssm.Observer, error) {
			awsProfiles = append(awsProfiles, profile+"/"+region)
			return &awsssm.Observer{API: fakeSSM{}}, nil
		}
		return c
	}})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(append(args,
		"--registry", filepath.Join(dir, "credentials.json"),
		"--events", filepath.Join(dir, "events.json"),
		"--targets", filepath.Join(dir, "targets.json")))
	err = cmd.ExecuteContext(context.Background())
	if len(awsProfiles) > 1 {
		t.Errorf("connected to AWS %d times: %v", len(awsProfiles), awsProfiles)
	}
	return out.String(), errOut.String(), err
}

func TestCheckText(t *testing.T) {
	srv := githubServer(t)
	defer srv.Close()
	dir := fixture(t, srv.URL)
	out, _, err := run(t, srv, dir, "check")
	if Code(err) != ExitFindings {
		t.Fatalf("exit code %d (%v), want %d\n%s", Code(err), err, ExitFindings, out)
	}
	for _, want := range []string{
		"listed 3 scope(s): 0 missing, 1 stale, 1 unregistered, 0 changed, 1 unrecorded, 1 unlisted, 1 unobserved, 0 present",
		"stale         app/ci/deploy  github-actions:example-org/web:DEPLOY_TOKEN",
		"unregistered  -              github-actions:example-org/api:DEPLOY_TOKEN",
		"(.github/workflows/ci.yaml)",
		"unrecorded    app/prod/DB",
		"unlisted      -              aws-ssm:hosting:/app/prod/OLD",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "HOST_KEY") {
		t.Errorf("an unobserved store is listed without --all:\n%s", out)
	}
	if !strings.Contains(err.Error(), "2 finding(s) in missing, stale, unregistered") {
		t.Errorf("error = %v", err)
	}

	out, _, _ = run(t, srv, dir, "check", "--all")
	if !strings.Contains(out, "unobserved    app/prod/HOST_KEY") {
		t.Errorf("--all does not list the unobserved store:\n%s", out)
	}
}

func TestCheckJSONAndFailOn(t *testing.T) {
	srv := githubServer(t)
	defer srv.Close()
	dir := fixture(t, srv.URL)
	out, _, err := run(t, srv, dir, "check", "--format", "json", "--fail-on", "")
	if err != nil {
		t.Fatalf("--fail-on '' still failed: %v", err)
	}
	var rep credforge.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Count(credforge.StateStale) != 1 || len(rep.Scopes) != 3 {
		t.Fatalf("report = %+v", rep)
	}

	_, _, err = run(t, srv, dir, "check", "--fail-on", "unlisted", "--only", "app/prod/*")
	if Code(err) != ExitFindings {
		t.Fatalf("--fail-on unlisted: %v", err)
	}
	if _, _, err := run(t, srv, dir, "check", "--fail-on", "gone"); Code(err) != ExitError {
		t.Fatalf("an unknown state: %v", err)
	}
	if _, _, err := run(t, srv, dir, "check", "--format", "yaml"); Code(err) != ExitError {
		t.Fatalf("an unknown format: %v", err)
	}
}

func TestCheckRecord(t *testing.T) {
	srv := githubServer(t)
	defer srv.Close()
	dir := fixture(t, srv.URL)
	_, stderr, err := run(t, srv, dir, "check", "--record", "--fail-on", "unrecorded")
	if Code(err) != ExitFindings {
		t.Fatalf("exit code %d (%v)", Code(err), err)
	}
	if !strings.Contains(stderr, "recorded 1 event(s)") {
		t.Fatalf("stderr = %q", stderr)
	}
	reg, err := credspec.LoadRegistry(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := credspec.LoadLog(filepath.Join(dir, "events.json"), reg)
	if err != nil {
		t.Fatal(err)
	}
	rec := log.Record("app/prod/DB")
	if rec.Created == nil || !rec.Created.Equal(day0) {
		t.Fatalf("app/prod/DB record = %+v", rec)
	}
	// Recorded, it no longer fails.
	if _, _, err := run(t, srv, dir, "check", "--fail-on", "unrecorded"); err != nil {
		t.Fatalf("after recording: %v", err)
	}
}

func TestSchemaCommand(t *testing.T) {
	cmd := New(Options{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"schema", "targets"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), targets.Schema()) {
		t.Fatal("schema targets did not write the schema")
	}
	cmd.SetArgs([]string{"schema", "registry"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("schema registry succeeded")
	}
}

func TestGoBuiltRegistryAndTargets(t *testing.T) {
	reg := credspec.NewRegistry(cred("a", credspec.Store{Type: "host-file", Role: credspec.RolePrimary, Path: "/etc/a"}))
	cmd := New(Options{
		Use:      "observe",
		Registry: func() (*credspec.Registry, error) { return reg, nil },
		Targets: func() (*targets.File, error) {
			return &targets.File{FormatVersion: targets.FormatVersion}, nil
		},
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"check", "--events", filepath.Join(t.TempDir(), "none.json")})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "listed 0 scope(s)") || !strings.Contains(out.String(), "1 unobserved") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestCode(t *testing.T) {
	if Code(nil) != 0 || Code(fmt.Errorf("x")) != ExitError ||
		Code(fmt.Errorf("wrapped: %w", &ExitCodeError{Code: ExitFindings, Err: fmt.Errorf("y")})) != ExitFindings {
		t.Fatal("Code")
	}
}
