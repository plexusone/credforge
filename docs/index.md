# credforge

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
> [roadmap](specs/initiatives/INIT-CREDFORGE-001/ROADMAP.md).

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

The comparison is a pure function, and the command tree mounts in a host
tool that builds its registry in Go:

```go
cmd := cli.New(cli.Options{
    Use:      "observe",
    Registry: buildRegistry,                       // func() (*credspec.Registry, error)
    Targets:  func() (*targets.File, error) { return myTargets, nil },
})
```

```go
rep := credforge.Compare(reg, log, scopes, observations, references, credforge.Options{
    Grace: credforge.DefaultGrace,
})
events, err := credforge.Record(reg, log, rep, credforge.DefaultGrace)
```

## Documentation

- [Getting started](getting-started.md)
- [Specifications](specs/initiatives/INIT-CREDFORGE-001/PRD.md)
- [Releases](releases/v0.8.0.md)

## License

[MIT](https://github.com/plexusone/credforge/blob/main/LICENSE)
