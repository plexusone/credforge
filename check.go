package credforge

import (
	"context"
	"fmt"
	"slices"

	"github.com/plexusone/systemspec-credential/credspec"
)

// Connector reaches the stores of one type in one account. Observer
// returns nil when the account is not bound, so its stores are unobserved.
// References may be nil when the store type has no consumers to read.
type Connector interface {
	Observer(storeType, account string) (Observer, error)
	References(storeType, account string) (ReferenceFinder, error)
}

// Checker observes the stores a registry names and compares them with it.
type Checker struct {
	Connector Connector
	// Extra are accounts to list and read references from beyond those the
	// registry names, by store type, such as repositories whose workflows
	// may read secrets the registry does not know about.
	Extra map[string][]string
}

// Check lists every scope that holds a compared credential's primary or
// rendered store, plus the extra accounts, reads the references in each
// account listed, and compares. An observer's error stops the check: a
// partial report is never returned as complete.
func (c *Checker) Check(ctx context.Context, reg *credspec.Registry, log *credspec.Log, o Options) (Report, error) {
	type acct struct{ typ, account string }
	var scopes []Scope
	observers := map[Scope]Observer{}
	var accounts []acct
	addScope := func(s Scope, ob Observer) {
		if _, ok := observers[s]; ok {
			return
		}
		observers[s] = ob
		scopes = append(scopes, s)
		a := acct{s.Type, s.Account}
		if !slices.Contains(accounts, a) {
			accounts = append(accounts, a)
		}
	}
	observerFor := func(typ, account string) (Observer, error) {
		ob, err := c.Connector.Observer(typ, account)
		if err != nil {
			return nil, fmt.Errorf("credforge: connecting to %s:%s: %w", typ, account, err)
		}
		return ob, nil
	}

	for _, cred := range reg.Credentials {
		if !compared(cred, o) {
			continue
		}
		for _, s := range cred.Stores {
			if s.Role != credspec.RolePrimary && s.Role != credspec.RoleRendered {
				continue
			}
			ob, err := observerFor(s.Type, s.Account)
			if err != nil {
				return Report{}, err
			}
			if ob == nil {
				continue
			}
			k := KeyOf(s)
			sc := Scope{Type: k.Type, Account: k.Account}
			if sp, ok := ob.(Scoper); ok {
				sc = sp.Scope(k)
			}
			addScope(sc, ob)
		}
	}
	extraTypes := make([]string, 0, len(c.Extra))
	for typ := range c.Extra {
		extraTypes = append(extraTypes, typ)
	}
	slices.Sort(extraTypes)
	for _, typ := range extraTypes {
		for _, account := range c.Extra[typ] {
			ob, err := observerFor(typ, account)
			if err != nil {
				return Report{}, err
			}
			if ob == nil {
				return Report{}, fmt.Errorf("credforge: %s:%s is to be scanned, and no binding reaches it", typ, account)
			}
			addScope(Scope{Type: typ, Account: account}, ob)
		}
	}

	var observations []Observation
	for _, s := range scopes {
		got, err := observers[s].Observe(ctx, s)
		if err != nil {
			return Report{}, fmt.Errorf("credforge: listing %s: %w", s, err)
		}
		observations = append(observations, got...)
	}

	var references []Reference
	for _, a := range accounts {
		rf, err := c.Connector.References(a.typ, a.account)
		if err != nil {
			return Report{}, fmt.Errorf("credforge: connecting to %s:%s: %w", a.typ, a.account, err)
		}
		if rf == nil {
			continue
		}
		got, err := rf.References(ctx, a.account)
		if err != nil {
			return Report{}, fmt.Errorf("credforge: reading references in %s:%s: %w", a.typ, a.account, err)
		}
		references = append(references, got...)
	}
	return Compare(reg, log, scopes, observations, references, o), nil
}
