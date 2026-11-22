package runbook

import (
	"slices"
	"strings"
	"testing"

	"github.com/plexusone/systemspec-credential/credspec"
	rb "github.com/plexusone/systemspec-runbook/runbookspec"
)

func ssm(path string) credspec.Store {
	return credspec.Store{Type: credspec.StoreAWSSSM, Role: credspec.RolePrimary, Account: "hosting", Path: path}
}

func cred(id string, mutate func(*credspec.Credential)) credspec.Credential {
	parts := strings.Split(id, "/")
	c := credspec.Credential{
		ID: id, Name: parts[len(parts)-1], System: parts[0], Environment: parts[1], Kind: credspec.KindRandomSecret,
		Status: credspec.StatusPlanned, Owner: "ops", Issuer: credspec.Issuer{Type: credspec.IssuerSelf},
		Generation: credspec.Generation{Method: credspec.MethodRandom},
		Stores:     []credspec.Store{ssm("/example/" + strings.Join(parts[1:], "/"))},
		Rotation:   credspec.Rotation{Policy: credspec.PolicyOnDemand},
		Handling:   credspec.Handling{Generate: credspec.ActorHuman, Distribute: credspec.ActorSystem, Rotate: credspec.ActorHuman},
	}
	if mutate != nil {
		mutate(&c)
	}
	return c
}

func registry() *credspec.Registry {
	reg := credspec.NewRegistry(
		cred("example-app/prod/SESSION_KEY", func(c *credspec.Credential) { c.Generation.Format = credspec.FormatHex32 }),
		cred("example-app/prod/DB_DSN", func(c *credspec.Credential) {
			c.Generation.Provisioner = &credspec.Provisioner{Tool: "db-tool", Command: "db-tool apply example-app prod", RunBy: credspec.ActorHuman, Stores: true}
		}),
		cred("example-app/prod/API_TOKEN", func(c *credspec.Credential) {
			c.Kind, c.Generation.Method = credspec.KindAPIToken, credspec.MethodIssued
			c.Issuer = credspec.Issuer{Type: "example-issuer", Console: "https://console.example.com/tokens"}
			c.Generation.Steps = []string{"Create a token named example-app-prod."}
			c.Entitlements = []credspec.Entitlement{{Resource: "the example API", Access: "read"}}
			c.ConfigChanges = []string{"api_token: ${API_TOKEN}"}
			c.Requires = []string{"example-app/prod/api-project"}
			c.Stores = append(c.Stores, credspec.Store{Type: credspec.StoreHostFile, Role: credspec.RoleRendered, Path: "/etc/example-app/env"})
		}),
		cred("example-app/prod/OAUTH_CLIENT_SECRET", func(c *credspec.Credential) {
			c.Generation.Method = credspec.MethodIssued
			c.Stores = append(c.Stores, ssm("/example/prod/OAUTH_CLIENT_ID"))
		}),
		cred("example-app/prod/LATER_KEY", func(c *credspec.Credential) { c.Need = credspec.NeedLater }),
		cred("example-app/prod/NEXT_KEY", func(c *credspec.Credential) { c.Need = credspec.NeedRotation }),
		cred("example-app/staging/SESSION_KEY", func(c *credspec.Credential) { c.Generation.Format = credspec.FormatHex32 }),
		cred("other-app/prod/SESSION_KEY", nil),
	)
	reg.Prerequisites = []credspec.Prerequisite{{
		ID: "example-app/prod/api-project", Name: "The API project", System: "example-app", Environment: "prod",
		Status: credspec.StatusPlanned, Issuer: credspec.Issuer{Type: "example-issuer"},
		Steps: []string{"Create a project."}, Done: "The project exists.",
	}}
	return reg
}

func TestBuild(t *testing.T) {
	r, err := Build(registry(), Options{System: "example-app", Environment: "prod", Tool: []string{"ops", "credentials"}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range r.Steps() {
		got = append(got, s.ID+" "+s.Title)
	}
	want := []string{"1.1 The API project", "1.2 Generate the random values and keys", "1.3 Run db-tool", "1.4 API_TOKEN", "1.5 OAUTH_CLIENT_SECRET"}
	if !slices.Equal(got, want) {
		t.Fatalf("steps\n%v\nwant\n%v", got, want)
	}
	gen := r.Step("1.2")
	if len(gen.Actions) != 1 || !slices.Equal(gen.Actions[0].Exec[0].Args, []string{"ops", "credentials", "generate", "--only", "example-app/prod/SESSION_KEY", "--include-planned", "--yes"}) {
		t.Errorf("generate: %+v", gen.Actions)
	}
	if c := gen.Checks[0].Command; c == nil || !slices.Equal(c.Args[:5], []string{"ops", "credentials", "check", "--only", "example-app/prod/SESSION_KEY"}) {
		t.Errorf("check: %+v", gen.Checks)
	}
	tool := r.Step("1.3")
	if tool.Actions[0].Command != "db-tool apply example-app prod" || len(tool.Actions[0].Exec) != 0 || !slices.Equal(tool.Credentials, []string{"example-app/prod/DB_DSN"}) {
		t.Errorf("tool step: %+v", tool)
	}
	api := r.Step("1.4")
	if !slices.Equal(api.DependsOn, []string{"1.1"}) {
		t.Errorf("the token's step depends on %v, want the project's", api.DependsOn)
	}
	text := actionText(api)
	for _, want := range []string{"Open the issuer's console.", "Create a token named example-app-prod.", "- the example API: read", "Configuration: api_token", "Install it in aws-ssm hosting `/example/prod/API_TOKEN`"} {
		if !strings.Contains(text, want) {
			t.Errorf("the token's step lacks %q:\n%s", want, text)
		}
	}
	if last := api.Actions[len(api.Actions)-2]; !slices.Equal(last.Exec[0].Args, []string{"ops", "credentials", "install", "example-app/prod/API_TOKEN"}) {
		t.Errorf("install: %+v", last)
	}
	if len(api.Notes) != 1 || !strings.Contains(api.Notes[0], "/etc/example-app/env") {
		t.Errorf("notes %v", api.Notes)
	}
	oauth := r.Step("1.5")
	if strings.Contains(actionText(oauth), "Install it") || !strings.Contains(actionText(oauth), "Fix the registry first") {
		t.Errorf("a credential holding two values was offered an install:\n%s", actionText(oauth))
	}
	md, err := r.Markdown(rb.RenderOptions{})
	if err != nil || !strings.Contains(string(md), "example-app prod credentials") {
		t.Errorf("markdown: %v", err)
	}
}

func actionText(s *rb.Step) string {
	var b strings.Builder
	for _, a := range s.Actions {
		b.WriteString(a.Text + "\n")
	}
	return b.String()
}

func TestBuildNeedsDoneAndScope(t *testing.T) {
	reg := registry()
	r, err := Build(reg, Options{System: "example-app", Environment: "prod", Needs: []credspec.Need{credspec.NeedLater}})
	if err != nil || len(r.Steps()) != 1 || r.Steps()[0].Title != "LATER_KEY" {
		t.Fatalf("later only: %v", err)
	}
	r, err = Build(reg, Options{System: "example-app", Environment: "prod", Done: func(id string) bool { return id == "example-app/prod/API_TOKEN" }})
	if err != nil || r.Step("1.3").Title != "OAUTH_CLIENT_SECRET" || !strings.Contains(r.Summary, "`example-app/prod/API_TOKEN`") {
		t.Fatalf("done left out: %v, %s", err, r.Summary)
	}
	// The project is needed only by the token, which is done.
	for _, st := range r.Steps() {
		if st.Title == "The API project" {
			t.Error("a prerequisite nothing left needs was kept")
		}
	}
	if _, err := Build(reg, Options{System: "nobody"}); err == nil || !strings.Contains(err.Error(), "nothing left to set up") {
		t.Errorf("an empty system: %v", err)
	}
	if _, err := Build(reg, Options{}); err == nil {
		t.Error("no system was accepted")
	}
	all, err := Build(reg, Options{System: "example-app"})
	if err != nil || !slices.Contains(all.Step("1.2").Credentials, "example-app/staging/SESSION_KEY") {
		t.Errorf("every environment: %v", err)
	}
}

func TestPhasesFollowNeedsAndRequiresMayCrossKinds(t *testing.T) {
	reg := registry()
	// An optional prerequisite that requires an optional credential: the
	// webhook endpoint needs the key it is made with.
	reg.Credentials = append(reg.Credentials, cred("example-app/prod/PAY_KEY", func(c *credspec.Credential) {
		c.Need, c.Generation.Method = credspec.NeedOptional, credspec.MethodIssued
	}), cred("example-app/prod/PAY_WEBHOOK_SECRET", func(c *credspec.Credential) {
		c.Need, c.Generation.Method = credspec.NeedOptional, credspec.MethodIssued
		c.Requires = []string{"example-app/prod/pay-webhook"}
	}))
	reg.Prerequisites = append(reg.Prerequisites, credspec.Prerequisite{
		ID: "example-app/prod/pay-webhook", Name: "The payment webhook", System: "example-app", Environment: "prod",
		Status: credspec.StatusPlanned, Need: credspec.NeedOptional, Issuer: credspec.Issuer{Type: "example-pay"},
		Steps: []string{"Add the endpoint."}, Requires: []string{"example-app/prod/PAY_KEY"},
	})
	r, err := Build(reg, Options{System: "example-app", Environment: "prod", Needs: []credspec.Need{credspec.NeedLaunch, credspec.NeedOptional}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Phases) != 2 || r.Phases[1].Title != "Optional" {
		t.Fatalf("phases %+v", r.Phases)
	}
	var got []string
	for _, s := range r.Phases[1].Steps {
		got = append(got, s.ID+" "+s.Title+" "+strings.Join(s.DependsOn, ","))
	}
	want := []string{"2.1 PAY_KEY ", "2.2 The payment webhook 2.1", "2.3 PAY_WEBHOOK_SECRET 2.2"}
	if !slices.Equal(got, want) {
		t.Errorf("optional steps %v, want %v", got, want)
	}
}
