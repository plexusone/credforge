# CredForge

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Docs][docs-mkdoc-svg]][docs-mkdoc-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/plexusone/credforge/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/plexusone/credforge/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/plexusone/credforge/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/plexusone/credforge/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/plexusone/credforge/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/plexusone/credforge/actions/workflows/go-sast-codeql.yaml
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/plexusone/credforge
 [docs-godoc-url]: https://pkg.go.dev/github.com/plexusone/credforge
 [docs-mkdoc-svg]: https://img.shields.io/badge/Go-dev%20guide-blue.svg
 [docs-mkdoc-url]: https://plexusone.github.io/credforge
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/plexusone/credforge/blob/main/LICENSE

Check a credential registry against the places it describes, without
reading a single value.

A registry such as
[systemspec-credential](https://github.com/plexusone/systemspec-credential)
says which credentials should exist, where each is stored, who uses it and
how it rotates. credforge observes the stores and consumers themselves (a
repository's Actions secrets and the secrets its workflows read, a
parameter store's names) and reports where they disagree with the registry
and its event log: the secret a workflow needs that was never set, the token
regenerated at the issuer but never updated in one repository, the value
changed with nothing recorded.

> **Status:** credforge checks, records, serves a review page, installs a
> value you supply after checking it works, generates random values and
> keys where they are missing, and turns the registry into a runbook for
> setting a system's credentials up. Pushing values from and
> rotating them through [OmniVault](https://github.com/plexusone/omnivault)
> providers follows. See the
> [roadmap](docs/specs/initiatives/INIT-CREDFORGE-001/ROADMAP.md).

## What it reports

| State | Meaning |
|---|---|
| `missing` | A listed store does not hold the credential |
| `stale` | A store was set before the credential's current value was made |
| `unregistered` | A workflow reads a secret the registry stores nowhere it can be read |
| `changed` | A store was set after the log's latest event, with nothing recorded |
| `unrecorded` | A store holds a credential the log has no event for |
| `unlisted` | A store holds a name no credential in use names |
| `unobserved` | No binding reaches the store |
| `present` | As recorded |

## Install

```bash
go install github.com/plexusone/credforge/cmd/credforge@latest
```

## Use

Beside the registry and its event log, write a targets file that says how
each store is reached. It holds no secrets:

```json
{
  "formatVersion": "1",
  "bindings": [
    { "store": "github-actions", "account": "example-org/*", "github": {} },
    { "store": "aws-ssm", "account": "hosting", "aws": { "profile": "hosting", "region": "us-west-2" } }
  ],
  "scan": { "githubRepositories": ["example-org/web", "example-org/api"] }
}
```

Then check:

```bash
export GITHUB_TOKEN=$(gh auth token)
credforge check --registry credentials.json --events events.json --targets targets.json
```

```text
listed 3 scope(s): 0 missing, 1 stale, 1 unregistered, 0 changed, 1 unrecorded, 1 unlisted, 1 unobserved, 0 present
stale         app/ci/deploy  github-actions:example-org/web:DEPLOY_TOKEN  set 2026-03-01, before the current value was made on 2026-03-11
unregistered  -              github-actions:example-org/api:DEPLOY_TOKEN  a consumer reads this name, and no credential stores it here (.github/workflows/ci.yaml)
unrecorded    app/prod/DB    aws-ssm:hosting:/app/prod/DB                 set 2026-03-01; the log has no event for it
unlisted      -              aws-ssm:hosting:/app/prod/OLD                no credential stores this name
```

| Flag | What it does |
|---|---|
| `--record` | Logs unrecorded stores as `created` and changed ones as `deployed` |
| `--fail-on` | States that make the exit status 1; default `missing,stale,unregistered` |
| `--include-planned` | Also compares planned credentials |
| `--only` | Compares only credentials whose ID matches a pattern, such as `'app/prod/*'` |
| `--grace` | How far a store's change and the log's event may differ; default `24h` |
| `--format` | `text` or `json` |
| `--all` | Lists present and unobserved stores, not only their counts |

The exit status is 0 when nothing is in a `--fail-on` state, 1 when
something is, and 2 on an error.

## Review

`credforge review` serves a page on this machine for reviewing every
credential: its stores, consumers, entitlements, rotation and events, with
filters for system, environment, status, store, sensitivity, log state,
live state and decision. **Run live check** adds each store's state from
the check, and lists the stores no credential names.

```bash
export GITHUB_TOKEN=$(gh auth token)
credforge review --registry credentials.json --events events.json --targets targets.json
# reviewing at http://127.0.0.1:8484/
```

On each credential, or each store no credential names, record a decision
(approved, change with a note, or remove) and log events such as
`verified`. Decisions are saved in `reviews.json`, events in the event log;
the registry is never written, so a change decision is applied to the
registry's source and reviewed as a normal change. Both files hold no
values and are meant to be committed.

**To set up by hand** opens the **Setup list**: each credential left to
set up, grouped by system and environment, with where to get it (the
issuer, console, command or steps), what it may do (its entitlements)
and where to put it (each store, with its install command and live
state). After a live check it leaves out what is already in place. It
prints cleanly.

The list follows the registry's setup guidance. What is needed for launch
comes before what is needed later or optionally, and each item comes after
what it requires. Prerequisites at issuers, such as a cloud project or a
consent screen, appear with their steps and how to tell they are done.
When a tool makes several credentials, its command appears once, as **Run
once**, before the first credential it makes. Each card names what to set
up first and the configuration changes the credential needs. The
**Needed** filter picks launch, later or optional credentials, and the
registry's advice opens from the summary.

The **Handled by** column shows who generates, distributes and rotates
each credential, in that order: a **human operator**, an **agent
operator** (an AI agent acting for an operator) or a **program** (a
deterministic tool such as a deploy tool or a CI workflow). The filter
matches a credential when any of its stages is handled that way.

The page answers only on a loopback address and to same-origin requests.
Without a targets file it works without the live check.

### Access for the live check

The live check reads names and dates, never values:

| Store | Credentials | Access needed |
|---|---|---|
| GitHub Actions secrets | `GITHUB_TOKEN` or `GH_TOKEN`; `$(gh auth token)` uses your GitHub CLI login | Admin on each repository (GitHub requires it to list secrets) and the `repo` scope; for a fine-grained token, Secrets: read and Contents: read on those repositories |
| AWS SSM Parameter Store | The AWS SDK's default credentials, such as `AWS_PROFILE` | `ssm:DescribeParameters` in the region the targets file names |

A store the check cannot reach makes the check fail with the reason; the
rest of the page still works.

## Install a value

`credforge install` sets one credential's value in every store the
registry lists for it, then records it. It replaces running
`gh secret set` once per repository and recording the change afterwards.

```bash
export GITHUB_TOKEN=$(gh auth token)
credforge install app/ci/deploy --registry credentials.json --events events.json --targets targets.json
```

```text
install app/ci/deploy: a new value (rotated), replacing the one made 2026-03-11
  check  the value against its entitlements before writing
  write  github-actions:example-org/web:DEPLOY_TOKEN
  write  github-actions:example-org/api:DEPLOY_TOKEN
Write 2 store(s)? [y/N] y
Value of app/ci/deploy (hidden):
checked  the token reads github.com/example-org/lib (contents: read)
wrote    github-actions:example-org/web:DEPLOY_TOKEN
wrote    github-actions:example-org/api:DEPLOY_TOKEN
recorded rotated in events.json, expires 2027-03-11
recorded verified in events.json
```

- **The writes come first.** It lists each store and asks before it reads
  the value. `--dry-run` lists them and stops. Stores no binding reaches,
  such as a password manager, are listed for you to set.
- **The value is read once.** It is read hidden from the terminal, or from
  standard input with `--stdin --yes`. It is never an argument, never
  written to disk and never printed. GitHub receives it sealed with the
  repository's public key.
- **The value is checked before anything is written.** A token GitHub
  issues must read each `github.com/<owner>/<repo>` its entitlements name.
  A missing repository, an organization's approval still pending or an
  expired token stops the install with the reason. `--no-probe` skips the
  check.
- **It is recorded.** The event is `created`, or `rotated` when the log
  already has a value. It carries the expiry from `--expires`, or else the
  expiry GitHub reports for the token. A `verified` event lists the checks
  that passed.
- **Refusals.** A credential that a provisioner makes and stores is refused,
  with the provisioner's command to run instead, and so is a retired
  credential.

Writing needs more access than checking:

| Store | Access needed to write |
|---|---|
| GitHub Actions secrets | The `repo` scope, or for a fine-grained token Secrets: read and write on each repository |
| AWS SSM Parameter Store | `ssm:PutParameter`, and `kms:Encrypt` on the parameters' key |

## Generate random values and keys

`credforge generate` makes the values the registry says a tool can make:
a credential whose `generation.format` is set (`hex32`, `base64url32`,
`p256-pem`, `ed25519-pem` or `rsa3072-pem`) and whose provisioner is
`credforge generate`, or none.

```bash
credforge generate --only 'app/prod/*' --dry-run
```

```text
make   app/prod/SESSION_KEY (hex32) in aws-ssm:hosting:/app/prod/SESSION_KEY
leave  app/prod/SIGNING_KEY: every store holds a value
```

- **Only where missing.** It finds what is missing with a check, which
  reads names and never values. A credential is made only when none of
  its primary stores holds a value. A parameter is created only if it
  still does not exist when written, so a value is never replaced.
- **Never shown.** The value is made in memory with `crypto/rand`,
  written to each primary store and recorded as `created`. It is never
  printed.
- **Asks first.** It lists what it will make; `--yes` skips the question
  and `--dry-run` stops after the list.

## Set up a system's credentials

`credforge setup` builds a runbook, in
[systemspec-runbook](https://github.com/plexusone/systemspec-runbook)'s
format, from the registry for one system's credentials, and runs it step
by step:

```bash
credforge setup --system example-app --env prod list
credforge setup --system example-app --env prod show 1.3
credforge setup --system example-app --env prod run 1.3
credforge setup --system example-app --env prod verify
credforge setup --system example-app --env prod doc --html -o example-app-prod.html
```

- **Everything comes from the registry.** Phases follow the needs
  (launch, then later and optional with `--need`), and steps the setup
  order: a prerequisite at an issuer, with its steps and how to tell it
  is done; one step for each tool's command and one for every value
  `generate` makes; and for each credential from an issuer, its console,
  its steps, the exact access to give it, `credforge install`, and the
  configuration it needs.
- **Each step is checked** with `credforge check --only <credential>`,
  which reads names and never values.
- **A run** asks before each command, waits while you do the issuer's
  part, then checks and records the step in its own progress log
  (`setup-<system>-<env>.json` beside the event log).
- `export` writes the runbook as JSON, for `runbookspec` or another tool.
- A credential whose primary stores are named for different values, such
  as an OAuth client's secret and its ID, is not offered an install: the
  step says to give each value its own credential, and `install` refuses
  it.

## Connectors

| Store | What is listed | Never called |
|---|---|---|
| GitHub Actions secrets (`github-actions`) | Repository secret names and when each was set; workflow files' `secrets.NAME`; `install` writes a repository secret, sealed | Secret values cannot be read through GitHub's API |
| AWS Systems Manager Parameter Store (`aws-ssm`) | Parameter names and last change, one directory level at a time; `install` writes a `SecureString` | `GetParameter`, `GetParameters` |

## In Go

The comparison is a pure function, and the commands mount in a host tool
that builds its registry in Go: `cli.New` as a command tree of its own, or
`cli.Check`, `cli.Generate`, `cli.Install`, `cli.Review` and `cli.Setup` as commands beside the host's, such as
systemspec-credential's:

```go
cmd := cli.New(cli.Options{
    Use:      "observe",
    Registry: buildRegistry,                       // func() (*credspec.Registry, error)
    Targets:  func() (*targets.File, error) { return myTargets, nil },
})

opts := cli.Options{Registry: buildRegistry, Targets: buildTargets, ReviewsPath: "reviews.json"}
credentials.AddCommand(cli.Check(opts), cli.Generate(opts), cli.Install(opts), cli.Review(opts), cli.Setup(opts))
```

```go
rep := credforge.Compare(reg, log, scopes, observations, references, credforge.Options{
    Grace: credforge.DefaultGrace,
})
events, err := credforge.Record(reg, log, rep, credforge.DefaultGrace)
```

## Documentation

- [Getting started](docs/getting-started.md)
- [Specifications](docs/specs/initiatives/INIT-CREDFORGE-001/PRD.md)
- [Releases](docs/releases/v0.9.0.md)

## License

[MIT](LICENSE)
