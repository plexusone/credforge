package credforge

import (
	"fmt"
	"slices"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"
)

// Recorder is the By of the events Record appends.
const Recorder = "credforge"

// Record appends to log what rep observed and the log lacks, and returns
// the events appended; the caller saves the log. It never edits the
// registry.
//
// A credential with unrecorded stores gets a created event at the earliest
// such store's change, and, when another was set more than grace later, a
// deployed event at the latest: the value was made, then copied. A
// credential with changed stores gets a deployed event at the latest such
// store's change. Pass the grace the report was compared with.
func Record(reg *credspec.Registry, log *credspec.Log, rep Report, grace time.Duration) ([]credspec.Event, error) {
	created := map[string]*pick{}
	copied := map[string]*pick{} // the latest unrecorded store
	deployed := map[string]*pick{}
	var order []string
	for _, f := range rep.Findings {
		if f.Credential == "" || f.Modified == nil {
			continue
		}
		var m map[string]*pick
		var better func(a, b Finding) bool
		switch f.State {
		case StateUnrecorded:
			m, better = created, func(a, b Finding) bool { return a.Modified.Before(*b.Modified) }
		case StateChanged:
			m, better = deployed, func(a, b Finding) bool { return a.Modified.After(*b.Modified) }
		default:
			continue
		}
		keep(m, f, better)
		if f.State == StateUnrecorded {
			keep(copied, f, func(a, b Finding) bool { return a.Modified.After(*b.Modified) })
		}
		order = append(order, f.Credential)
	}

	slices.Sort(order)
	order = slices.Compact(order)
	var out []credspec.Event
	add := func(id string, p *pick, t credspec.EventType, what string) error {
		if p == nil {
			return nil
		}
		e := credspec.Event{
			Credential: id, Type: t, At: p.f.Modified.UTC(), By: Recorder,
			Note: fmt.Sprintf("%s %s; the time is when the store last set it", what, p.f.Store),
		}
		if err := log.Append(reg, e); err != nil {
			return fmt.Errorf("credforge: recording %s %s: %w", id, t, err)
		}
		out = append(out, e)
		return nil
	}
	for _, id := range order {
		if err := add(id, created[id], credspec.EventCreated, "observed in"); err != nil {
			return out, err
		}
		if c, l := created[id], copied[id]; c != nil && l.f.Modified.After(c.f.Modified.Add(grace)) {
			if err := add(id, l, credspec.EventDeployed, "copied to"); err != nil {
				return out, err
			}
		}
		if err := add(id, deployed[id], credspec.EventDeployed, "changed in"); err != nil {
			return out, err
		}
	}
	return out, nil
}

// pick is the finding chosen for one credential.
type pick struct{ f Finding }

// keep records f in m for its credential when better than the one kept.
func keep(m map[string]*pick, f Finding, better func(a, b Finding) bool) {
	p, ok := m[f.Credential]
	if !ok {
		m[f.Credential] = &pick{f: f}
		return
	}
	if better(f, p.f) {
		p.f = f
	}
}
