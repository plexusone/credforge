# credforge

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

> **Status:** v0.1.0 checks and records; it never writes a value. Installing
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

## Connectors

| Store | What is listed | Never called |
|---|---|---|
| GitHub Actions secrets (`github-actions`) | Repository secret names and when each was set; workflow files' `secrets.NAME` | Secret values cannot be read through GitHub's API |
| AWS Systems Manager Parameter Store (`aws-ssm`) | Parameter names and last change, one directory level at a time | `GetParameter`, `GetParameters` |

## In Go

The comparison is a pure function, and the commands mount in a host tool
that builds its registry in Go: `cli.New` as a command tree of its own, or
`cli.Check` as one command beside the host's, such as systemspec-credential's:

```go
cmd := cli.New(cli.Options{
    Use:      "observe",
    Registry: buildRegistry,                       // func() (*credspec.Registry, error)
    Targets:  func() (*targets.File, error) { return myTargets, nil },
})

credentials.AddCommand(cli.Check(cli.Options{Registry: buildRegistry, Targets: buildTargets}))
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
- [Releases](docs/releases/v0.1.0.md)

## License

[MIT](LICENSE)
