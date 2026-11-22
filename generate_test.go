package credforge_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/plexusone/systemspec-credential/credspec"

	"github.com/plexusone/credforge"
)

func TestNewValue(t *testing.T) {
	h, err := credforge.NewValue(credspec.FormatHex32)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
		t.Errorf("hex32: %d bytes, %v", len(b), err)
	}
	u, err := credforge.NewValue(credspec.FormatBase64URL32)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := base64.RawURLEncoding.DecodeString(u); err != nil || len(b) != 32 {
		t.Errorf("base64url32: %d bytes, %v", len(b), err)
	}
	for _, f := range []credspec.Format{credspec.FormatP256PEM, credspec.FormatEd25519PEM, credspec.FormatRSA3072PEM} {
		v, err := credforge.NewValue(f)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode([]byte(v))
		if block == nil || block.Type != "PRIVATE KEY" {
			t.Fatalf("%s: not a PKCS #8 PEM", f)
		}
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if _, err := credforge.NewValue("hex64"); err == nil {
		t.Error("an unknown format was made")
	}
}

// creatingWriter refuses to replace what it holds.
type creatingWriter struct{ held map[credforge.Key]string }

func (w *creatingWriter) Write(context.Context, credforge.Key, string) error {
	return fmt.Errorf("generate replaced a value")
}

func (w *creatingWriter) Create(_ context.Context, k credforge.Key, v string) error {
	if _, ok := w.held[k]; ok {
		return credforge.ErrExists
	}
	w.held[k] = v
	return nil
}

func generated(id string, f credspec.Format, stores ...credspec.Store) credspec.Credential {
	c := cred(id, credspec.StatusActive, stores...)
	c.Generation.Format = f
	if !f.Random() {
		c.Generation.Method = credspec.MethodKeypair
	}
	return c
}

func TestGenerate(t *testing.T) {
	newKey, signing := ssm("/app/prod/SESSION_KEY"), ssm("/app/prod/SIGNING_KEY")
	both1, both2 := ssm("/app/prod/BOTH"), gha(repo, "BOTH")
	half1, half2 := ssm("/app/prod/HALF"), gha(repo, "HALF")
	held, unbound := ssm("/app/prod/HELD"), gha("example-org/unbound", "X")
	byOther := generated("other-tool", credspec.FormatHex32, ssm("/app/prod/OTHER"))
	byOther.Generation.Provisioner = &credspec.Provisioner{Tool: "db-tool", Command: "db-tool apply", RunBy: credspec.ActorHuman, Stores: true}
	reg := credspec.NewRegistry(
		generated("session", credspec.FormatHex32, newKey),
		generated("signing", credspec.FormatP256PEM, signing),
		generated("both", credspec.FormatHex32, both1, both2),
		generated("half", credspec.FormatHex32, half1, half2),
		generated("held", credspec.FormatHex32, held),
		generated("unbound", credspec.FormatHex32, unbound),
		byOther,
		cred("typed", credspec.StatusActive, ssm("/app/prod/TYPED")),
	)
	log := credspec.NewLog()
	ssmObs := &fakeObserver{items: []credforge.Observation{obs(held, day0), obs(half1, day0)}}
	ghObs := &fakeObserver{}
	conn := fakeConnector{
		observers: map[string]credforge.Observer{credspec.StoreAWSSSM: dirObserver{ssmObs}, credspec.StoreGitHubActions: ghObs},
		unbound:   "example-org/unbound",
	}
	w := &creatingWriter{held: map[credforge.Key]string{}}
	g := &credforge.Generator{
		Checker: &credforge.Checker{Connector: conn},
		Writer:  func(string, string) (credforge.Writer, error) { return w, nil },
	}
	plan, err := g.Plan(context.Background(), reg, log, credforge.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, gen := range plan.Generations {
		line := gen.Credential + " " + fmt.Sprint(len(gen.Writes))
		if gen.Skip != "" {
			line += " " + strings.SplitN(gen.Skip, " ", 2)[0]
		}
		got = append(got, line)
	}
	// Only credentials generate makes, in registry order; held, half and
	// unbound are left, the first two because a store holds a value.
	equal(t, got, []string{"session 1", "signing 1", "both 2", "half 0 some", "held 0 every", "unbound 0 no"})

	results, err := g.Apply(context.Background(), reg, log, plan, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || len(w.held) != 4 {
		t.Fatalf("made %d, wrote %d stores", len(results), len(w.held))
	}
	if w.held[credforge.KeyOf(both1)] != w.held[credforge.KeyOf(both2)] {
		t.Error("one credential's stores hold different values")
	}
	if w.held[credforge.KeyOf(newKey)] == w.held[credforge.KeyOf(both1)] {
		t.Error("two credentials got the same value")
	}
	for _, r := range results {
		if r.Event == nil || r.Event.Type != credspec.EventCreated || r.Event.By != "ops" {
			t.Errorf("%s: event %+v", r.Credential, r.Event)
		}
		if strings.Contains(r.Event.Note, w.held[r.Written[0]]) {
			t.Errorf("%s: the event holds the value", r.Credential)
		}
	}
	if err := log.Validate(reg); err != nil {
		t.Fatal(err)
	}

	// A value set between the check and the write is never replaced: the
	// credential is left unrecorded, and the error says so.
	reg2 := credspec.NewRegistry(generated("late", credspec.FormatHex32, ssm("/app/prod/LATE")))
	log2 := credspec.NewLog()
	plan, err = g.Plan(context.Background(), reg2, log2, credforge.Options{})
	if err != nil {
		t.Fatal(err)
	}
	w.held[credforge.KeyOf(ssm("/app/prod/LATE"))] = "set meanwhile"
	if _, err := g.Apply(context.Background(), reg2, log2, plan, "ops"); err == nil || !strings.Contains(err.Error(), "already holds a value") {
		t.Errorf("a store set meanwhile: %v", err)
	}
	if len(log2.Events) != 0 {
		t.Errorf("recorded %+v", log2.Events)
	}
}
