package credforge

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"
)

// DefaultGrace is the usual Options.Grace: a day, the time operators take
// between changing a value and recording it.
const DefaultGrace = 24 * time.Hour

// StoreGitHubActions is credspec's store type for GitHub Actions secrets.
const StoreGitHubActions = credspec.StoreGitHubActions

// Options adjust a comparison.
type Options struct {
	// IncludePlanned compares planned credentials too, as for an
	// environment being brought up. Otherwise only active ones are.
	IncludePlanned bool
	// Grace is how far a store's change and the log's event may differ
	// before the store is stale or changed. Zero compares exactly; most
	// callers use DefaultGrace.
	Grace time.Duration
	// Only, when set, limits the credentials compared. Names the registry
	// stores are still known, so they are never reported as unlisted.
	Only func(credspec.Credential) bool
}

// Compare compares reg and log with what was observed: scopes are the
// listings made, observations what they returned, and references what
// consumers read. It does no I/O.
//
// For each compared credential's primary and rendered stores, a store in
// no scope is unobserved; in a scope but not observed, missing (unless the
// credential is tagged optional); observed with no created, rotated or
// deployed event, unrecorded; set more than Grace before the latest
// created or rotated event, stale; set more than Grace after the latest
// created, rotated or deployed event, changed; and otherwise present.
//
// An observed name no credential stores is unlisted, as is one only a
// retired credential stores. A reference to a name no credential stores is
// unregistered; a GitHub Actions reference is also satisfied by an
// notRequired reports whether a credential may be absent from its stores
// without being missing: one that is optional, by tag or by need, or one
// that exists only while another credential rotates, such as a
// verification secret kept beside a new HMAC secret.
func notRequired(c credspec.Credential) bool {
	return slices.Contains(c.Tags, "optional") || c.Need == credspec.NeedOptional || c.Need == credspec.NeedRotation
}

// organization secret, a store whose account is the repository's owner.
func Compare(reg *credspec.Registry, log *credspec.Log, scopes []Scope, observations []Observation, references []Reference, o Options) Report {
	observed := map[Key]Observation{}
	for _, ob := range observations {
		observed[ob.Key] = ob
	}
	// registered are the keys a credential in use stores; retired, the
	// keys only a retired credential stores.
	registered := map[Key]bool{}
	retired := map[Key]string{}
	for _, c := range reg.Credentials {
		for _, s := range c.Stores {
			k := KeyOf(s)
			if c.Status == credspec.StatusRetired {
				if !registered[k] {
					retired[k] = c.ID
				}
				continue
			}
			registered[k] = true
			delete(retired, k)
		}
	}

	rep := Report{Scopes: slices.Clone(scopes), Findings: []Finding{}}
	inScope := func(k Key) bool {
		return slices.ContainsFunc(scopes, func(s Scope) bool { return s.Contains(k) })
	}
	for _, c := range reg.Credentials {
		if !compared(c, o) {
			continue
		}
		rec := log.Record(c.ID)
		for _, s := range c.Stores {
			if s.Role != credspec.RolePrimary && s.Role != credspec.RoleRendered {
				continue
			}
			k := KeyOf(s)
			f := Finding{Credential: c.ID, Store: k}
			ob, seen := observed[k]
			switch {
			case !inScope(k):
				f.State = StateUnobserved
				f.Detail = "no listing covers this store"
			case !seen:
				if notRequired(c) {
					continue
				}
				f.State = StateMissing
				f.Detail = "the store does not hold it"
			default:
				m := ob.Modified
				f.Modified = &m
				f.State, f.Detail = judge(m, rec, o.Grace)
			}
			rep.Findings = append(rep.Findings, f)
		}
	}

	for _, ob := range observations {
		if registered[ob.Key] {
			continue
		}
		m := ob.Modified
		f := Finding{State: StateUnlisted, Store: ob.Key, Modified: &m, Detail: "no credential stores this name"}
		if id, ok := retired[ob.Key]; ok {
			f.Credential = id
			f.Detail = "only a retired credential stores this name"
		}
		rep.Findings = append(rep.Findings, f)
	}

	unregistered := map[Key][]string{}
	for _, r := range references {
		if registered[r.Key] || registered[orgKey(r.Key)] {
			continue
		}
		if !slices.Contains(unregistered[r.Key], r.Source) {
			unregistered[r.Key] = append(unregistered[r.Key], r.Source)
		}
	}
	for k, sources := range unregistered {
		slices.Sort(sources)
		rep.Findings = append(rep.Findings, Finding{
			State: StateUnregistered, Store: k, Source: strings.Join(sources, ", "),
			Detail: "a consumer reads this name, and no credential stores it here",
		})
	}

	order := map[State]int{}
	for i, s := range States() {
		order[s] = i
	}
	slices.SortStableFunc(rep.Findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(order[a.State], order[b.State]),
			strings.Compare(a.Credential, b.Credential),
			strings.Compare(a.Store.String(), b.Store.String()),
		)
	})
	return rep
}

// compared reports whether c is compared under o.
func compared(c credspec.Credential, o Options) bool {
	switch c.Status {
	case credspec.StatusActive:
	case credspec.StatusPlanned:
		if !o.IncludePlanned {
			return false
		}
	default:
		return false
	}
	return o.Only == nil || o.Only(c)
}

// judge places a store set at m against the log's record.
func judge(m time.Time, rec credspec.Record, grace time.Duration) (State, string) {
	made := rec.Changed()
	latest := made
	if rec.Deployed != nil && (latest == nil || rec.Deployed.After(*latest)) {
		latest = rec.Deployed
	}
	switch {
	case latest == nil:
		return StateUnrecorded, fmt.Sprintf("set %s; the log has no event for it", day(m))
	case made != nil && m.Before(made.Add(-grace)):
		return StateStale, fmt.Sprintf("set %s, before the current value was made on %s", day(m), day(*made))
	case m.After(latest.Add(grace)):
		return StateChanged, fmt.Sprintf("set %s, after the log's latest event on %s", day(m), day(*latest))
	default:
		return StatePresent, "set " + day(m)
	}
}

// orgKey is the key of the GitHub organization secret that would satisfy
// a reference in a repository; the zero Key for anything else.
func orgKey(k Key) Key {
	owner, _, ok := strings.Cut(k.Account, "/")
	if k.Type != StoreGitHubActions || !ok {
		return Key{}
	}
	return Key{Type: k.Type, Account: owner, Path: k.Path}
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }
