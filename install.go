package credforge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"
)

// Writer writes a value to one store. A value passes through it and is
// never kept.
type Writer interface {
	Write(ctx context.Context, k Key, value string) error
}

// Prober tests a value against what the registry says it should reach,
// such as a token reading each repository its entitlements name, before
// anything is written.
type Prober interface {
	// Probe returns what it checked. It returns an error when the value
	// fails a check, and a Probe with nothing checked when it has no check
	// for the credential.
	Probe(ctx context.Context, c credspec.Credential, value string) (Probe, error)
}

// Probe is what a Prober found.
type Probe struct {
	// Checked are the checks that passed, each a sentence.
	Checked []string `json:"checked,omitempty"`
	// Expires is the expiry the issuer reported, if any.
	Expires *time.Time `json:"expires,omitempty"`
}

// Destination is a store Install writes.
type Destination struct {
	Store  Key    `json:"store"`
	Writer Writer `json:"-"`
}

// Skipped is a store Install leaves to the operator.
type Skipped struct {
	Store  Key    `json:"store"`
	Reason string `json:"reason"`
}

// InstallPlan is every write Install makes, for the operator to confirm
// before a value is asked for.
type InstallPlan struct {
	Credential string `json:"credential"`
	// Event is created for a credential the log has no value for, and
	// rotated otherwise.
	Event credspec.EventType `json:"event"`
	// Replaces is when the value being replaced was made, for rotated.
	Replaces *time.Time `json:"replaces,omitempty"`
	// Writes are the stores written, in the registry's order.
	Writes []Destination `json:"writes"`
	// Skipped are the stores Install cannot reach, for the operator to set.
	Skipped []Skipped `json:"skipped,omitempty"`
}

// Installer writes one credential's value to every store the registry
// lists for it, and records it.
type Installer struct {
	// Writer returns the writer for a store type and account, or nil when
	// none reaches it.
	Writer func(storeType, account string) (Writer, error)
	// Prober tests the value first; nil skips the test.
	Prober Prober
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// Plan lists the writes for credential id. A credential a provisioner
// makes and stores is refused: the tool writes its stores, so a value set
// by hand would disagree with what the tool set at the issuer. A retired credential
// and one whose stores no writer reaches are refused too.
func (in *Installer) Plan(reg *credspec.Registry, log *credspec.Log, id string) (*InstallPlan, error) {
	c, ok := reg.Find(id)
	if !ok {
		return nil, fmt.Errorf("install: no credential %q in the registry", id)
	}
	if c.Status == credspec.StatusRetired {
		return nil, fmt.Errorf("install: %s is retired", id)
	}
	if p := c.Generation.Provisioner; p != nil && p.Stores {
		return nil, fmt.Errorf("install: %s is made and stored by %s; run %q instead", id, p.Tool, p.Command)
	}
	plan := &InstallPlan{Credential: id, Event: credspec.EventCreated}
	if rec := log.Record(id); rec.Rotated != nil || rec.Created != nil {
		plan.Event = credspec.EventRotated
		plan.Replaces = rec.Rotated
		if plan.Replaces == nil {
			plan.Replaces = rec.Created
		}
	}
	for _, s := range c.Stores {
		k := KeyOf(s)
		switch {
		case s.Role == credspec.RoleRendered:
			plan.Skipped = append(plan.Skipped, Skipped{Store: k, Reason: "rendered at deploy time from the primary store"})
			continue
		case s.Type == credspec.StoreNone:
			continue
		case s.Path == "":
			plan.Skipped = append(plan.Skipped, Skipped{Store: k, Reason: "the registry names no path"})
			continue
		}
		w, err := in.Writer(s.Type, s.Account)
		if err != nil {
			return nil, fmt.Errorf("install: reaching %s: %w", k, err)
		}
		if w == nil {
			plan.Skipped = append(plan.Skipped, Skipped{Store: k, Reason: "no destination reaches it; set it yourself"})
			continue
		}
		plan.Writes = append(plan.Writes, Destination{Store: k, Writer: w})
	}
	if len(plan.Writes) == 0 {
		return nil, fmt.Errorf("install: no store of %s is reachable; check the targets file", id)
	}
	return plan, nil
}

// InstallOptions are an install's choices.
type InstallOptions struct {
	// Expires is the value's expiry when the operator knows it. It wins
	// over the issuer's, which is used when this is nil.
	Expires *time.Time
	// By is who installs, for the events.
	By string
}

// InstallResult is what Apply did.
type InstallResult struct {
	Probe   Probe            `json:"probe"`
	Written []Key            `json:"written"`
	Events  []credspec.Event `json:"events"`
	// ExpiryDiffers is set when the operator's expiry is not the issuer's.
	ExpiryDiffers bool `json:"expiryDiffers,omitempty"`
}

// Apply probes value, writes it to every destination, and appends the
// events to log; the caller saves the log. A failed probe writes nothing.
// A failed write stops the install, records nothing, and its error names
// what was written, so the install can be run again.
func (in *Installer) Apply(ctx context.Context, reg *credspec.Registry, log *credspec.Log, p *InstallPlan, value string, o InstallOptions) (InstallResult, error) {
	var res InstallResult
	if value == "" {
		return res, errors.New("install: the value is empty")
	}
	if strings.TrimSpace(value) != value {
		return res, errors.New("install: the value starts or ends with white space; paste it again")
	}
	c, ok := reg.Find(p.Credential)
	if !ok {
		return res, fmt.Errorf("install: no credential %q in the registry", p.Credential)
	}
	if in.Prober != nil {
		pr, err := in.Prober.Probe(ctx, c, value)
		if err != nil {
			return res, fmt.Errorf("install: the value failed its check, so nothing was written: %w", err)
		}
		res.Probe = pr
	}
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	// The event is the time the first store is set, so every store is
	// within the check's grace of it.
	at := now().UTC()
	for _, d := range p.Writes {
		if err := d.Writer.Write(ctx, d.Store, value); err != nil {
			return res, fmt.Errorf("install: writing %s: %w%s", d.Store, err, written(res.Written))
		}
		res.Written = append(res.Written, d.Store)
	}

	expires := o.Expires
	if expires == nil {
		expires = res.Probe.Expires
	} else if pe := res.Probe.Expires; pe != nil && !pe.Equal(*expires) {
		res.ExpiryDiffers = true
	}
	var stores []string
	for _, k := range res.Written {
		stores = append(stores, k.String())
	}
	events := []credspec.Event{{
		Credential: p.Credential, Type: p.Event, At: at, Expires: expires, By: o.By,
		Note: "installed in " + strings.Join(stores, ", "),
	}}
	if len(res.Probe.Checked) > 0 {
		events = append(events, credspec.Event{
			Credential: p.Credential, Type: credspec.EventVerified, At: at, By: o.By,
			Note: strings.Join(res.Probe.Checked, "; "),
		})
	}
	for _, e := range events {
		if err := log.Append(reg, e); err != nil {
			return res, fmt.Errorf("install: every store was written, but recording %s failed: %w", e.Type, err)
		}
		res.Events = append(res.Events, e)
	}
	return res, nil
}

// written names the stores already written, for an error mid-install.
func written(keys []Key) string {
	if len(keys) == 0 {
		return "; nothing was written"
	}
	names := make([]string, len(keys))
	for i, k := range keys {
		names[i] = k.String()
	}
	return "; already written: " + strings.Join(names, ", ") + "; nothing was recorded, so run the install again"
}
