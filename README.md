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

> **Status:** v0.5.0 checks, records and serves a review page; it never
> writes a value. Installing
> and rotating values through [OmniVault](https://github.com/plexusone/omnivault)
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

## Connectors

| Store | What is listed | Never called |
|---|---|---|
| GitHub Actions secrets (`github-actions`) | Repository secret names and when each was set; workflow files' `secrets.NAME` | Secret values cannot be read through GitHub's API |
| AWS Systems Manager Parameter Store (`aws-ssm`) | Parameter names and last change, one directory level at a time | `GetParameter`, `GetParameters` |

## In Go

The comparison is a pure function, and the commands mount in a host tool
that builds its registry in Go: `cli.New` as a command tree of its own, or
`cli.Check` and `cli.Review` as commands beside the host's, such as
systemspec-credential's:

```go
cmd := cli.New(cli.Options{
    Use:      "observe",
    Registry: buildRegistry,                       // func() (*credspec.Registry, error)
    Targets:  func() (*targets.File, error) { return myTargets, nil },
})

opts := cli.Options{Registry: buildRegistry, Targets: buildTargets, ReviewsPath: "reviews.json"}
credentials.AddCommand(cli.Check(opts), cli.Review(opts))
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
- [Releases](docs/releases/v0.5.0.md)

## License

[MIT](LICENSE)
