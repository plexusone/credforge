// Package credforge compares a credential registry with the stores and
// consumers it names, without reading any value.
//
// The registry and its event log are systemspec-credential's (package
// credspec): they say what should exist and what happened to it. credforge
// observes what does exist, such as a repository's Actions secret names and
// when each was set, or a parameter store's names and when each last
// changed, and reports where the two disagree. Observers list names and
// dates only; no type in this package has a field for a value.
package credforge

import (
	"context"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"
)

// Key names one place a value is kept: a store type, an account at that
// store, such as a repository or a cloud account, and a path, such as a
// secret's or a parameter's name. It matches credspec.Store's Type, Account
// and Path.
type Key struct {
	Type    string `json:"type"`
	Account string `json:"account,omitempty"`
	Path    string `json:"path"`
}

// KeyOf returns the key of a registry store.
func KeyOf(s credspec.Store) Key {
	return Key{Type: s.Type, Account: s.Account, Path: s.Path}
}

// String is the key as type:account:path.
func (k Key) String() string {
	return k.Type + ":" + k.Account + ":" + k.Path
}

// Scope is one listing: the names in one account of one store type, either
// all of them (an empty Dir) or those directly in the directory Dir.
type Scope struct {
	Type    string `json:"type"`
	Account string `json:"account,omitempty"`
	// Dir, when not empty, limits the scope to names whose parent
	// directory is Dir, such as "/app/prod" for "/app/prod/DB_PASSWORD".
	Dir string `json:"dir,omitempty"`
}

// Contains reports whether the scope lists k.
func (s Scope) Contains(k Key) bool {
	if k.Type != s.Type || k.Account != s.Account {
		return false
	}
	return s.Dir == "" || path.Dir(k.Path) == s.Dir
}

// String is the scope as type:account[:dir].
func (s Scope) String() string {
	if s.Dir == "" {
		return s.Type + ":" + s.Account
	}
	return s.Type + ":" + s.Account + ":" + s.Dir
}

// Observation is one name a store reported, with when it was last set. It
// never carries a value.
type Observation struct {
	Key
	// Modified is when the store last set the value.
	Modified time.Time `json:"modified"`
}

// Reference is a consumer naming a value it reads, such as a workflow's
// secrets.NAME. Key is where the consumer expects the value.
type Reference struct {
	Key
	// Source is the consumer, such as a workflow file's path.
	Source string `json:"source"`
}

// Observer lists the names in one scope of one store type.
type Observer interface {
	Observe(ctx context.Context, s Scope) ([]Observation, error)
}

// Scoper is an Observer that lists less than a whole account at a time. It
// returns the scope that lists k, for example its parent directory.
type Scoper interface {
	Scope(k Key) Scope
}

// ReferenceFinder lists the references the consumers in one account make,
// such as the secrets a repository's workflows read.
type ReferenceFinder interface {
	References(ctx context.Context, account string) ([]Reference, error)
}

// State is what a comparison found.
type State string

// States, from the most to the least urgent.
const (
	// StateMissing is a store the registry lists, in a listed scope, that
	// does not hold the credential.
	StateMissing State = "missing"
	// StateStale is a store last set before the credential's current value
	// was made: it holds an earlier value.
	StateStale State = "stale"
	// StateUnregistered is a consumer reading a name the registry stores
	// nowhere it can be read from.
	StateUnregistered State = "unregistered"
	// StateChanged is a store set after the log's latest event for the
	// credential, with nothing recorded.
	StateChanged State = "changed"
	// StateUnrecorded is a store holding a credential the log has no
	// event for.
	StateUnrecorded State = "unrecorded"
	// StateUnlisted is a name in a listed scope that no credential names,
	// or that only a retired credential names.
	StateUnlisted State = "unlisted"
	// StateUnobserved is a store in no listed scope: nothing is known.
	StateUnobserved State = "unobserved"
	// StatePresent is a store that holds the credential as recorded.
	StatePresent State = "present"
)

// States lists every State, from the most to the least urgent.
func States() []State {
	return []State{
		StateMissing, StateStale, StateUnregistered, StateChanged,
		StateUnrecorded, StateUnlisted, StateUnobserved, StatePresent,
	}
}

// Finding is one result of a comparison.
type Finding struct {
	State State `json:"state"`
	// Credential is the credential's ID; empty for a name no credential
	// names.
	Credential string `json:"credential,omitempty"`
	// Store is where it was looked for, observed or referenced.
	Store Key `json:"store"`
	// Modified is when the store last set it, when observed.
	Modified *time.Time `json:"modified,omitempty"`
	// Source is the consumer, for an unregistered reference.
	Source string `json:"source,omitempty"`
	// Detail explains the finding in a sentence.
	Detail string `json:"detail,omitempty"`
}

// Report is a comparison's result.
type Report struct {
	// Scopes are the listings observed.
	Scopes []Scope `json:"scopes"`
	// Findings are in State order, then by credential and store.
	Findings []Finding `json:"findings"`
}

// Count returns how many findings are in state s.
func (r Report) Count(s State) int {
	n := 0
	for _, f := range r.Findings {
		if f.State == s {
			n++
		}
	}
	return n
}

// In returns the findings in any of states.
func (r Report) In(states ...State) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if slices.Contains(states, f.State) {
			out = append(out, f)
		}
	}
	return out
}

// ParseStates parses a comma-separated list of states.
func ParseStates(s string) ([]State, error) {
	var out []State
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		st := State(part)
		if !slices.Contains(States(), st) {
			return nil, &UnknownStateError{State: part}
		}
		out = append(out, st)
	}
	return out, nil
}

// UnknownStateError is a state name ParseStates does not know.
type UnknownStateError struct{ State string }

func (e *UnknownStateError) Error() string {
	names := make([]string, 0, len(States()))
	for _, s := range States() {
		names = append(names, string(s))
	}
	return "credforge: unknown state " + e.State + "; use " + strings.Join(names, ", ")
}
