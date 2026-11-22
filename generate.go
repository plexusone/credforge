package credforge

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"
)

// GeneratorTool is the provisioner tool name of a credential generate
// makes. A credential with a format and no provisioner is made too.
const GeneratorTool = "credforge generate"

// NewValue makes a value in format f with crypto/rand.
func NewValue(f credspec.Format) (string, error) {
	switch f {
	case credspec.FormatHex32, credspec.FormatBase64URL32:
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("credforge: %w", err)
		}
		if f == credspec.FormatHex32 {
			return hex.EncodeToString(b), nil
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	case credspec.FormatP256PEM:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", fmt.Errorf("credforge: %w", err)
		}
		return pkcs8(k)
	case credspec.FormatEd25519PEM:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("credforge: %w", err)
		}
		return pkcs8(k)
	case credspec.FormatRSA3072PEM:
		k, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return "", fmt.Errorf("credforge: %w", err)
		}
		return pkcs8(k)
	}
	return "", fmt.Errorf("credforge: cannot make format %q; use one of %v", f, credspec.Formats())
}

func pkcs8(key any) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("credforge: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ErrExists is a Creator finding the store already holds a value.
var ErrExists = errors.New("the store already holds a value")

// Creator is a Writer that can create a value without replacing one, such
// as a parameter store. Generate uses it when a writer has it, so a value
// set after the check is never replaced.
type Creator interface {
	Create(ctx context.Context, k Key, value string) error
}

// Generation is one credential generate makes, or leaves.
type Generation struct {
	Credential string          `json:"credential"`
	Format     credspec.Format `json:"format"`
	// Writes are the primary stores the value goes to; empty when the
	// credential is skipped.
	Writes []Destination `json:"writes,omitempty"`
	// Skip says why nothing is made, such as every store holding a value.
	Skip string `json:"skip,omitempty"`
}

// GeneratePlan is what generate makes.
type GeneratePlan struct {
	Generations []Generation `json:"generations"`
}

// Make returns the generations that write.
func (p GeneratePlan) Make() []Generation {
	var out []Generation
	for _, g := range p.Generations {
		if len(g.Writes) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// Generator makes the values of credentials it can generate, in their
// primary stores, only where no store holds one. It finds what is missing
// with a check, which reads names and never values.
type Generator struct {
	Checker *Checker
	// Writer returns the writer for a store type and account, or nil when
	// none reaches it.
	Writer func(storeType, account string) (Writer, error)
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// Generates reports whether generate makes c: it has a format, and either
// no provisioner or credforge generate as its provisioner.
func Generates(c credspec.Credential) bool {
	if c.Generation.Format == "" || c.Status == credspec.StatusRetired {
		return false
	}
	p := c.Generation.Provisioner
	return p == nil || p.Tool == GeneratorTool
}

// Plan checks the stores of each credential generate makes, among those o
// compares, and lists what it would write. A credential is made only when
// every primary store is checked and missing: one that holds a value in
// any store is left, since generate never reads a value to copy it.
func (g *Generator) Plan(ctx context.Context, reg *credspec.Registry, log *credspec.Log, o Options) (GeneratePlan, error) {
	only := o.Only
	o.Only = func(c credspec.Credential) bool { return Generates(c) && (only == nil || only(c)) }
	rep, err := g.Checker.Check(ctx, reg, log, o)
	if err != nil {
		return GeneratePlan{}, err
	}
	states := map[string]map[Key]State{}
	for _, f := range rep.Findings {
		if f.Credential == "" {
			continue
		}
		if states[f.Credential] == nil {
			states[f.Credential] = map[Key]State{}
		}
		states[f.Credential][f.Store] = f.State
	}
	var plan GeneratePlan
	for _, c := range reg.Credentials {
		st, ok := states[c.ID]
		if !ok {
			continue
		}
		gen := Generation{Credential: c.ID, Format: c.Generation.Format}
		var missing, held, unseen []Key
		for _, s := range c.Primary() {
			k := KeyOf(s)
			switch st[k] {
			case StateMissing:
				missing = append(missing, k)
			case StateUnobserved, "":
				unseen = append(unseen, k)
			default:
				held = append(held, k)
			}
		}
		switch {
		case len(held) > 0 && len(missing) == 0:
			gen.Skip = "every store holds a value"
		case len(held) > 0:
			gen.Skip = "some stores hold a value and " + keys(missing) + " does not; copy it with install, or replace it everywhere"
		case len(unseen) > 0:
			gen.Skip = "no binding reaches " + keys(unseen) + ", so it cannot be checked"
		case len(missing) == 0:
			gen.Skip = "it has no primary store"
		}
		if gen.Skip == "" {
			for _, k := range missing {
				w, err := g.Writer(k.Type, k.Account)
				if err != nil {
					return plan, fmt.Errorf("generate: reaching %s: %w", k, err)
				}
				if w == nil {
					gen.Skip = "no destination writes " + k.String()
					gen.Writes = nil
					break
				}
				gen.Writes = append(gen.Writes, Destination{Store: k, Writer: w})
			}
		}
		plan.Generations = append(plan.Generations, gen)
	}
	return plan, nil
}

// GenerateResult is what Apply made.
type GenerateResult struct {
	Credential string          `json:"credential"`
	Written    []Key           `json:"written"`
	Event      *credspec.Event `json:"event,omitempty"`
}

// Apply makes each planned value in memory, creates it in every store, and
// appends a created event; the caller saves the log. A store that holds a
// value by the time it is written stops that credential, and Apply goes on
// to the next. It returns every result and the errors joined.
func (g *Generator) Apply(ctx context.Context, reg *credspec.Registry, log *credspec.Log, p GeneratePlan, by string) ([]GenerateResult, error) {
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	var out []GenerateResult
	var errs []error
	for _, gen := range p.Make() {
		res := GenerateResult{Credential: gen.Credential}
		value, err := NewValue(gen.Format)
		if err != nil {
			errs = append(errs, fmt.Errorf("generate %s: %w", gen.Credential, err))
			continue
		}
		at := now().UTC()
		failed := false
		for _, d := range gen.Writes {
			if err := create(ctx, d, value); err != nil {
				errs = append(errs, fmt.Errorf("generate %s: writing %s: %w%s", gen.Credential, d.Store, err, written(res.Written)))
				failed = true
				break
			}
			res.Written = append(res.Written, d.Store)
		}
		if !failed {
			e := credspec.Event{Credential: gen.Credential, Type: credspec.EventCreated, At: at, By: by,
				Note: fmt.Sprintf("generated (%s) by %s in %s", gen.Format, GeneratorTool, keys(res.Written))}
			if err := log.Append(reg, e); err != nil {
				errs = append(errs, fmt.Errorf("generate %s: written, but recording failed: %w", gen.Credential, err))
			} else {
				res.Event = &e
			}
		}
		out = append(out, res)
	}
	return out, errors.Join(errs...)
}

// create writes value without replacing one when the writer can.
func create(ctx context.Context, d Destination, value string) error {
	if c, ok := d.Writer.(Creator); ok {
		return c.Create(ctx, d.Store, value)
	}
	return d.Writer.Write(ctx, d.Store, value)
}

func keys(ks []Key) string {
	names := make([]string, len(ks))
	for i, k := range ks {
		names[i] = k.String()
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}
