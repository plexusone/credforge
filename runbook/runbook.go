// Package runbook turns a credential registry into a runbook, in
// systemspec-runbook's format, for setting up one system's credentials:
// what is set up at issuers first, what tools make, and what a person gets
// from an issuer and installs. Every action comes from the registry, so the
// runbook says no more and no less than the registry does, and each step
// is checked by credforge's check, which reads names and never values.
package runbook

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/plexusone/systemspec-credential/credspec"
	rb "github.com/plexusone/systemspec-runbook/runbookspec"

	"github.com/plexusone/credforge"
)

// Options choose the credentials and how the runbook's commands are run.
type Options struct {
	// System is the system whose credentials are set up (required).
	System string
	// Environment, when set, keeps that environment's credentials and
	// those that serve every environment.
	Environment string
	// Needs are the needs to include; launch when empty. Credentials
	// needed only during a rotation are never included.
	Needs []credspec.Need
	// Tool is how credforge's commands are run, such as ["credforge"] or
	// a host tool's ["bin/infra", "credentials"]; ["credforge"] when empty.
	// The registry, event log and targets flags are the tool's defaults.
	Tool []string
	// Done reports credentials already set up, which are left out and
	// listed in the summary; nil leaves none out.
	Done func(id string) bool
	// Writable reports whether install and generate reach a store; nil
	// counts GitHub repository secrets and SSM parameters.
	Writable func(s credspec.Store) bool
}

// Build returns the runbook. It fails when nothing is left to set up.
func Build(reg *credspec.Registry, o Options) (*rb.Runbook, error) {
	if o.System == "" {
		return nil, errors.New("runbook: a system is required")
	}
	if len(o.Needs) == 0 {
		o.Needs = []credspec.Need{credspec.NeedLaunch}
	}
	if len(o.Tool) == 0 {
		o.Tool = []string{"credforge"}
	}
	if o.Writable == nil {
		o.Writable = defaultWritable
	}
	order, err := reg.SetupOrder()
	if err != nil {
		return nil, fmt.Errorf("runbook: %w", err)
	}
	b := &builder{reg: reg, o: o, stepOf: map[string]string{}}
	creds, done := b.selectCredentials()
	prereqs := b.selectPrerequisites(creds)
	b.needOf = map[string]credspec.Need{}
	for id := range creds {
		c, _ := reg.Find(id)
		b.needOf[id] = cmp.Or(c.Need, credspec.NeedLaunch)
	}
	for id, need := range prereqs {
		b.needOf[id] = need
	}
	if len(creds)+len(prereqs) == 0 {
		return nil, fmt.Errorf("runbook: %s has nothing left to set up for %s", b.scope(), needList(o.Needs))
	}

	for _, st := range order {
		switch {
		case st.Prerequisite && prereqs[st.ID] != "":
			p, _ := reg.FindPrerequisite(st.ID)
			b.add(b.needOf[st.ID], b.prerequisite(p), []string{st.ID}, p.Requires)
		case !st.Prerequisite && creds[st.ID]:
			c, _ := reg.Find(st.ID)
			b.credential(c)
		}
	}
	return b.runbook(done)
}

func defaultWritable(s credspec.Store) bool {
	switch s.Type {
	case credspec.StoreAWSSSM:
		return strings.HasPrefix(s.Path, "/")
	case credspec.StoreGitHubActions:
		return strings.Contains(s.Account, "/")
	}
	return false
}

type builder struct {
	reg *credspec.Registry
	o   Options
	// phases holds each phase's steps, by need.
	phases map[credspec.Need][]rb.Step
	// needOf is each chosen entry's need, which names its phase.
	needOf map[string]credspec.Need
	// stepOf maps each credential or prerequisite to the step setting it
	// up, for dependencies.
	stepOf map[string]string
	// groups are the step of each provisioner command and of generate,
	// added to as their credentials come.
	groups map[string]*group
	// requires are each step's entries to depend on, resolved at the end.
	requires map[string][]string
}

type group struct {
	phase credspec.Need
	index int
}

func (b *builder) scope() string {
	if b.o.Environment == "" {
		return b.o.System
	}
	return b.o.System + " " + b.o.Environment
}

// selectCredentials are the credentials to set up, and those left out as
// done.
func (b *builder) selectCredentials() (map[string]bool, []string) {
	out := map[string]bool{}
	var done []string
	for _, c := range b.reg.Credentials {
		if !b.inScope(c.System, c.Environment) || c.Status == credspec.StatusRetired {
			continue
		}
		need := cmp.Or(c.Need, credspec.NeedLaunch)
		if need == credspec.NeedRotation || !slices.Contains(b.o.Needs, need) {
			continue
		}
		if b.o.Done != nil && b.o.Done(c.ID) {
			done = append(done, c.ID)
			continue
		}
		out[c.ID] = true
	}
	return out, done
}

func (b *builder) inScope(system, env string) bool {
	return system == b.o.System && (b.o.Environment == "" || env == "" || env == b.o.Environment)
}

// selectPrerequisites are the prerequisites the credentials require, and
// what those require, still planned, each with the soonest need of what
// requires it.
func (b *builder) selectPrerequisites(creds map[string]bool) map[string]credspec.Need {
	out := map[string]credspec.Need{}
	sooner := func(a, c credspec.Need) bool {
		return slices.Index(credspec.Needs(), a) < slices.Index(credspec.Needs(), c)
	}
	var visit func(ids []string, need credspec.Need)
	visit = func(ids []string, need credspec.Need) {
		for _, id := range ids {
			p, ok := b.reg.FindPrerequisite(id)
			if !ok || p.Status != credspec.StatusPlanned {
				continue
			}
			if prev, seen := out[id]; seen && !sooner(need, prev) {
				continue
			}
			out[id] = need
			visit(p.Requires, need)
		}
	}
	for _, c := range b.reg.Credentials {
		if creds[c.ID] {
			visit(c.Requires, cmp.Or(c.Need, credspec.NeedLaunch))
		}
	}
	return out
}

// add appends a step to a phase, numbering it, and notes the entries it
// sets up and requires.
func (b *builder) add(phase credspec.Need, s rb.Step, sets, requires []string) {
	if b.phases == nil {
		b.phases, b.groups, b.requires = map[credspec.Need][]rb.Step{}, map[string]*group{}, map[string][]string{}
	}
	// Steps are numbered once the phases are known.
	s.ID = string(phase) + "." + strconv.Itoa(len(b.phases[phase])+1)
	b.phases[phase] = append(b.phases[phase], s)
	for _, id := range sets {
		b.stepOf[id] = s.ID
	}
	b.requires[s.ID] = append(b.requires[s.ID], requires...)
}

// join adds a credential to the step of its group, making the step when
// it is the group's first.
func (b *builder) join(key string, phase credspec.Need, first func() rb.Step, more func(*rb.Step), c credspec.Credential) {
	if b.groups == nil {
		b.phases, b.groups, b.requires = map[credspec.Need][]rb.Step{}, map[string]*group{}, map[string][]string{}
	}
	key += "@" + string(phase)
	if g, ok := b.groups[key]; ok {
		s := &b.phases[g.phase][g.index]
		more(s)
		b.stepOf[c.ID] = s.ID
		b.requires[s.ID] = append(b.requires[s.ID], requirements(c)...)
		return
	}
	b.add(phase, first(), []string{c.ID}, requirements(c))
	b.groups[key] = &group{phase: phase, index: len(b.phases[phase]) - 1}
}

func requirements(c credspec.Credential) []string {
	return append(slices.Clone(c.Requires), c.DependsOn...)
}

// credential places a credential's step: with its provisioner's command,
// with generate, or on its own.
func (b *builder) credential(c credspec.Credential) {
	p := c.Generation.Provisioner
	need := b.needOf[c.ID]
	switch {
	case credforge.Generates(c):
		b.join("generate", need, func() rb.Step { return b.generateStep(c) }, func(s *rb.Step) { b.addGenerate(s, c) }, c)
	case p != nil && p.Stores:
		b.join("tool:"+p.Command, need, func() rb.Step { return b.toolStep(c) }, func(s *rb.Step) { b.addToTool(s, c) }, c)
	default:
		b.add(need, b.issuedStep(c), []string{c.ID}, requirements(c))
	}
}

// setupArgs are the setup command's arguments for this runbook.
func (b *builder) setupArgs(args ...string) []string {
	out := []string{"setup", "--system", b.o.System}
	if b.o.Environment != "" {
		out = append(out, "--env", b.o.Environment)
	}
	return append(out, args...)
}

func (b *builder) cmd(args ...string) []string {
	return append(slices.Clone(b.o.Tool), args...)
}

// checks prove a credential is in every primary store: credforge's check,
// failing on a missing or stale store.
func (b *builder) check(c credspec.Credential) rb.Check {
	return rb.Check{
		ID: checkID(c.ID), Description: c.Name + " is in every primary store",
		Kind:    rb.KindCommand,
		Command: &rb.CommandCheck{Args: b.cmd("check", "--only", c.ID, "--include-planned", "--fail-on", "missing,stale")},
	}
}

func checkID(id string) string {
	return "stored-" + strings.NewReplacer("/", "-", ".", "-", "_", "-").Replace(strings.ToLower(id))
}

func (b *builder) generateStep(c credspec.Credential) rb.Step {
	s := rb.Step{
		Title: "Generate the random values and keys", Owner: rb.OwnerBoth,
		Summary: "credforge makes each value in memory and writes it only where no store holds one, so running it " +
			"again changes nothing. No value is shown.",
		Done: "Every value below is in its stores, recorded as created.",
	}
	b.addGenerate(&s, c)
	return s
}

func (b *builder) addGenerate(s *rb.Step, c credspec.Credential) {
	s.Actions = append(s.Actions, rb.Action{
		Owner: rb.OwnerOperator,
		Text:  fmt.Sprintf("Generate %s (%s) in %s.", code(c.ID), c.Generation.Format, storeList(c.Primary())),
		Exec:  []rb.Exec{{Args: b.cmd("generate", "--only", c.ID, "--include-planned", "--yes")}},
	})
	s.Checks = append(s.Checks, b.check(c))
	s.Credentials = append(s.Credentials, c.ID)
}

func (b *builder) toolStep(c credspec.Credential) rb.Step {
	p := c.Generation.Provisioner
	s := rb.Step{
		Title: "Run " + p.Tool, Owner: owner(p.RunBy),
		Actions: []rb.Action{{
			Owner:   owner(p.RunBy),
			Text:    "Run the command, filling in what is in angle brackets. It makes each value below and stores it; there is nothing to install by hand.",
			Command: p.Command,
		}},
		Done: "Every credential below is in its stores.",
	}
	b.addToTool(&s, c)
	return s
}

func (b *builder) addToTool(s *rb.Step, c credspec.Credential) {
	s.Notes = append(s.Notes, fmt.Sprintf("%s: %s, in %s.", code(c.ID), c.Name, storeList(c.Primary())))
	s.Checks = append(s.Checks, b.check(c))
	s.Credentials = append(s.Credentials, c.ID)
}

// issuedStep is a credential a person makes or gets from an issuer, then
// installs.
func (b *builder) issuedStep(c credspec.Credential) rb.Step {
	g := c.Generation
	who := owner(c.SetUpBy())
	s := rb.Step{Title: c.Name, Owner: who, Summary: c.Description, Credentials: []string{c.ID}}
	add := func(a rb.Action) { s.Actions = append(s.Actions, a) }
	if c.Issuer.Console != "" {
		add(rb.Action{Owner: who, Text: "Open the issuer's console.", Link: &rb.Link{Text: c.Issuer.Console, Href: c.Issuer.Console}})
	}
	if g.Where != "" && g.Where != c.Issuer.Console {
		add(rb.Action{Owner: who, Text: "Where: " + g.Where + "."})
	}
	for _, st := range g.Steps {
		add(rb.Action{Owner: who, Text: st})
	}
	if g.Command != "" {
		add(rb.Action{Owner: who, Text: "Make the value:", Command: g.Command})
	}
	if len(c.Entitlements) > 0 {
		var lines []string
		for _, e := range c.Entitlements {
			l := "- " + e.Resource + ": " + e.Access
			if e.GrantedBy != "" {
				l += " (granted by " + e.GrantedBy + ")"
			}
			lines = append(lines, l)
		}
		add(rb.Action{Owner: who, Text: "Give it exactly this access, and no more:\n\n" + strings.Join(lines, "\n")})
	}
	var writable, byHand []credspec.Store
	for _, st := range c.Primary() {
		if b.o.Writable(st) {
			writable = append(writable, st)
		} else {
			byHand = append(byHand, st)
		}
	}
	if names := credforge.ValueNames(c.Primary()); len(names) > 1 {
		add(rb.Action{Owner: rb.OwnerAgent, Text: fmt.Sprintf("Fix the registry first: the primary stores hold %d different values (%s), "+
			"so install cannot write one value to all of them. Give each value its own credential.", len(names), codeList(names))})
		writable = nil
	}
	if len(writable) > 0 {
		add(rb.Action{
			Owner: rb.OwnerOperator,
			Text: fmt.Sprintf("Install it in %s. credforge checks the value first where it can, asks for it hidden, "+
				"writes it and records it; the value is never an argument or shown.", storeList(writable)),
			Exec: []rb.Exec{{Args: b.cmd("install", c.ID)}},
		})
	}
	for _, st := range byHand {
		add(rb.Action{Owner: rb.OwnerOperator, Text: fmt.Sprintf("Put it in %s: %s", storeName(st), cmp.Or(st.Install, "by hand"))})
	}
	for _, ch := range c.ConfigChanges {
		add(rb.Action{Owner: rb.OwnerAgent, Text: "Configuration: " + ch})
	}
	for _, st := range c.Stores {
		if st.Role == credspec.RoleRendered {
			s.Notes = append(s.Notes, fmt.Sprintf("The deploy writes it to %s from the primary store.", storeName(st)))
		}
	}
	if len(c.Primary()) > 0 {
		s.Checks = []rb.Check{b.check(c)}
	}
	s.Done = fmt.Sprintf("%s is in every primary store, recorded as created.", c.Name)
	return s
}

func (b *builder) prerequisite(p credspec.Prerequisite) rb.Step {
	s := rb.Step{Title: p.Name, Owner: rb.OwnerOperator, Summary: p.Description, Done: cmp.Or(p.Done, p.Name+" is set up.")}
	if p.Issuer.Console != "" {
		s.Actions = append(s.Actions, rb.Action{Text: "Open the issuer's console.", Link: &rb.Link{Text: p.Issuer.Console, Href: p.Issuer.Console}})
	}
	for _, st := range p.Steps {
		s.Actions = append(s.Actions, rb.Action{Text: st})
	}
	if p.Command != "" {
		s.Actions = append(s.Actions, rb.Action{Text: "Set it up:", Command: p.Command})
	}
	for _, l := range p.Links {
		s.Notes = append(s.Notes, fmt.Sprintf("[%s](%s)", l.Title, l.URL))
	}
	return s
}

// runbook assembles the phases, resolving dependencies to earlier steps.
func (b *builder) runbook(done []string) (*rb.Runbook, error) {
	titles := map[credspec.Need][2]string{
		credspec.NeedLaunch:   {"For launch", "what the system needs before it first runs"},
		credspec.NeedLater:    {"Later", "what is needed after launch"},
		credspec.NeedOptional: {"Optional", "what an optional part needs once it is turned on"},
	}
	r := &rb.Runbook{
		ID:      "credentials-" + strings.ReplaceAll(b.scope(), " ", "-"),
		Title:   b.scope() + " credentials",
		Summary: b.summary(done),
		Usage: fmt.Sprintf("Run a step with %s, or follow it by hand. Each step is checked with %s, "+
			"which reads names and never values. install and generate record what they set; record anything set by hand.",
			code(strings.Join(b.cmd(b.setupArgs("run", "<step>")...), " ")), code(strings.Join(b.cmd("check"), " "))),
	}
	// Phases are numbered in the order of the needs asked for, and their
	// steps renumbered to match.
	order := map[string]int{}
	renamed := map[string]string{}
	n := 0
	for _, need := range b.o.Needs {
		steps := b.phases[need]
		if len(steps) == 0 {
			continue
		}
		id := strconv.Itoa(len(r.Phases) + 1)
		for i := range steps {
			renamed[steps[i].ID] = id + "." + strconv.Itoa(i+1)
			steps[i].ID = renamed[steps[i].ID]
			order[steps[i].ID] = n
			n++
		}
		t := titles[need]
		r.Phases = append(r.Phases, rb.Phase{ID: id, Title: t[0], Gives: t[1], Steps: steps})
	}
	for k, v := range b.stepOf {
		b.stepOf[k] = renamed[v]
	}
	requires := map[string][]string{}
	for k, v := range b.requires {
		requires[renamed[k]] = v
	}
	b.requires = requires
	for _, s := range r.Steps() {
		var deps []string
		for _, id := range b.requires[s.ID] {
			d, ok := b.stepOf[id]
			if !ok || d == s.ID || slices.Contains(deps, d) {
				continue
			}
			if order[d] > order[s.ID] {
				return nil, fmt.Errorf("runbook: step %s needs %s, which comes later: something needed sooner requires something needed later", s.ID, d)
			}
			deps = append(deps, d)
		}
		slices.Sort(deps)
		s.DependsOn = deps
	}
	if err := r.Validate(rb.ValidateOptions{KnownCredential: func(id string) bool { _, ok := b.reg.Find(id); return ok }}); err != nil {
		return nil, fmt.Errorf("runbook: %w", err)
	}
	return r, nil
}

func (b *builder) summary(done []string) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("The credentials %s needs for %s, from the credential registry, in the order they are set up.",
		b.scope(), needList(b.o.Needs)))
	if len(done) > 0 {
		lines = append(lines, fmt.Sprintf("Already set up, so left out: %s.", codeList(done)))
	}
	return strings.Join(lines, "\n\n")
}

func owner(a credspec.Actor) rb.Owner {
	switch a {
	case credspec.ActorAgent:
		return rb.OwnerAgent
	case credspec.ActorSystem:
		return rb.OwnerBoth
	}
	return rb.OwnerOperator
}

func storeName(s credspec.Store) string {
	name := s.Type
	if s.Account != "" {
		name += " " + s.Account
	}
	if s.Path != "" {
		name += " " + code(s.Path)
	}
	return name
}

func storeList(ss []credspec.Store) string {
	names := make([]string, len(ss))
	for i, s := range ss {
		names[i] = storeName(s)
	}
	return strings.Join(names, ", ")
}

func needList(ns []credspec.Need) string {
	names := make([]string, len(ns))
	for i, n := range ns {
		names[i] = string(n)
	}
	return strings.Join(names, ", ")
}

func code(s string) string { return "`" + s + "`" }

func codeList(ids []string) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = code(id)
	}
	return strings.Join(out, ", ")
}
