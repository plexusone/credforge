# TRD: credforge — check and act on a credential registry

**Initiative:** INIT-CREDFORGE-001
**Status:** proposed

## Boundaries

| Concern | Owner |
|---|---|
| Registry, event log, lifecycle state, reports | `github.com/plexusone/systemspec-credential` (`credspec`) |
| Observing stores, issuers and consumers; comparing; recording; later writing values | **credforge** |
| Reading and writing values in vaults | `github.com/plexusone/omnivault` and its provider modules |
| Encryption key lifecycle inside an app | `github.com/plexusone/keyforge` |

credforge imports `credspec` and never redefines its types. It adds no field
for a value to any type, as `credspec` does not.

## Packages

```
credforge/            core: keys, scopes, observations, references, findings, Compare, Check
credforge/targets     the targets file: binding store types and accounts to connections
credforge/github      observers for GitHub Actions secrets and workflow references
credforge/awsssm      observer for AWS Systems Manager Parameter Store
credforge/cli         the embeddable Cobra command tree
cmd/credforge         the standalone binary
```

The core package depends on the standard library and `credspec` only.
Connectors live in their own packages so the core stays small; they may move
to separate modules if their dependencies grow.

## Core model

```go
// Key names one place a value is kept: a store type, an account at that
// store (a repository, an AWS account) and a path (a secret name, a
// parameter name). It matches credspec.Store's Type, Account and Path.
type Key struct{ Type, Account, Path string }

// Scope is a listing: every name under Prefix in one account of one store
// type. An empty Prefix is the whole account.
type Scope struct{ Type, Account, Prefix string }

// Observation is one name a store reported, with when it was last set.
// It never carries a value.
type Observation struct {
    Key
    Modified time.Time
}

// Reference is a consumer naming a value it reads, such as a workflow's
// `secrets.NAME`: Key is where the consumer expects it.
type Reference struct {
    Key
    Source string // the file or component that reads it
}

// Observer lists one store type's names in a scope.
type Observer interface {
    Observe(ctx context.Context, s Scope) ([]Observation, error)
}

// ReferenceFinder lists the references consumers in one account make.
type ReferenceFinder interface {
    References(ctx context.Context, account string) ([]Reference, error)
}
```

### Findings

```go
type State string // present, missing, stale, changed, unrecorded, unlisted, unregistered, unobserved

type Finding struct {
    State      State
    Credential string       // empty for unlisted
    Store      Key
    Modified   *time.Time   // when the store last set it, when observed
    Source     string       // the consumer, for unregistered
    Detail     string
}
```

`Compare(reg, log, scopes, observations, references, opts) Report` is a pure
function: it does no I/O, so every rule is unit-tested with fixtures.

Rules, for each credential whose `status` is `active` (and `planned` with
`IncludePlanned`), and each store whose role is `primary` or `rendered`:

1. The store's key is in no observed scope: `unobserved`. Nothing is
   inferred about it.
2. The key is in an observed scope and not observed: `missing`, unless the
   credential is tagged `optional`.
3. Observed, and the log has no `created`, `rotated` or `deployed` event
   for the credential: `unrecorded`.
4. Observed, and `Modified` is earlier than the latest `created` or
   `rotated` event by more than `Grace` (default 24 hours): `stale`. The
   store holds a value made before the current one.
5. Observed, and `Modified` is later than the latest `created`, `rotated`
   or `deployed` event by more than `Grace`: `changed`.
6. Otherwise `present`.

Then, for every observed name no credential's store names: `unlisted`. For
every reference whose key no credential's store names: `unregistered`. A
GitHub reference is also satisfied by a `github-actions` store whose
account is the repository's owner (an organization secret).

`Grace` absorbs the order operators work in: regenerate, install, then
record, which puts the event a little after the store's change.

### Recording

`Record(reg, log, report, now) ([]credspec.Event, error)` appends, for each
`unrecorded` finding, a `created` event, and for each `changed` finding a
`deployed` event, at the store's `Modified` time, `by: credforge`, with a
note naming the store. It never edits the registry. The caller saves the log.

### Check

```go
type Checker struct {
    Observers  map[string]Observer        // by store type
    References map[string]ReferenceFinder // by store type
    Targets    *targets.File
}

func (c *Checker) Check(ctx context.Context, reg *credspec.Registry, log *credspec.Log, opts Options) (Report, error)
```

`Check` derives the scopes from the registry and the targets file, calls the
observers, and passes everything to `Compare`:

- `github-actions`: one scope per distinct account (`owner/repo`) among the
  registry's stores, plus each repository the targets file lists for
  scanning. Workflow references are read for the same repositories.
- `aws-ssm`: one scope per directory of each stored parameter name (the
  path up to its last `/`), listed one level deep, so a parameter beside a
  registered one and not in the registry is `unlisted`.

A store type or account without a binding produces no scope, so its stores
are `unobserved`. An observer's error is returned with the scope it was
listing; a partial report is never presented as complete.

## Targets file

A small JSON file (camelCase, schema generated from the Go types) beside the
registry. It holds no secrets: only how to reach each store.

```json
{
  "formatVersion": "1",
  "bindings": [
    { "store": "github-actions", "account": "*", "github": { "tokenEnv": "GITHUB_TOKEN" } },
    { "store": "aws-ssm", "account": "hosting (us-west-2)", "aws": { "profile": "hosting", "region": "us-west-2" } }
  ],
  "scan": { "githubRepositories": ["example-org/web-app", "example-org/api"] }
}
```

`account` matches a store's account exactly or as a `path.Match` pattern;
the first match wins. A host tool may build the file in Go instead.

## Connectors

### GitHub (`credforge/github`)

- **Actions secrets:** `GET /repos/{owner}/{repo}/actions/secrets`, paged.
  It returns each secret's name, `created_at` and `updated_at`, never a
  value. `Modified` is `updated_at`.
- **Workflow references:** `GET /repos/{owner}/{repo}/contents/.github/workflows`
  and each `.yml` or `.yaml` file's raw content from the default branch.
  References are `secrets.NAME` and `secrets['NAME']`; `GITHUB_TOKEN` is
  skipped. `secrets: inherit` into a reusable workflow is noted, not
  followed, in Phase 1.
- Plain `net/http` with a token from the binding's environment variable
  (default `GITHUB_TOKEN`, then `GH_TOKEN`), and a configurable base URL for
  tests and GitHub Enterprise Server. The token needs read access to the
  repositories' Actions secrets and contents.

### AWS SSM (`credforge/awsssm`)

- `DescribeParameters` with a `Path` filter, `OneLevel`, paged. It returns
  names and `LastModifiedDate`, never values. `GetParameter` is never called.
- The binding names the profile and region; the AWS SDK's default chain
  supplies credentials.

## Command line

```
credforge check   --registry credentials.json --events events.json --targets targets.json
                  [--record] [--fail-on missing,stale,unregistered] [--include-planned]
                  [--grace 24h] [--only <id-pattern>] [--format text|json]
credforge schema  targets
```

Text output groups findings by state, worst first, one line each, naming the
credential, the store and the date; `--format json` writes the report. The
exit status is 1 when any finding is in a `--fail-on` state, 2 on a usage
or connection error.

`cli.New(cli.Options{...})` returns the tree; like `credspec`'s, its
`Options.Registry` lets a host tool supply a registry built in Go, and
`Options.Targets` a targets file built in Go.

## Phase 3 design notes (writes)

- `Writer` is the write side of a store type: `Write(ctx, Key, value)`.
  GitHub Actions secrets are written sealed with the repository's public key
  (libsodium sealed box); SSM parameters as `SecureString`, replacing the
  current value.
- `Installer.Plan` lists the writes for one credential: every store with a
  path that a binding reaches, except rendered stores, which a deploy
  writes. A credential whose provisioner stores it is refused, since the
  tool also sets it at the issuer. `Installer.Apply` runs the `Prober`, then
  each write in order, then appends `created` (or `rotated` when the log
  has a value) with the expiry and `verified` with the checks that passed.
  A failed probe writes nothing; a failed write records nothing and names
  the stores already written, so the install is run again.
- The GitHub prober uses the value itself as the token: it reads each
  `github.com/<owner>/<repo>` entitlement's repository, and its commits
  when the access names contents, and takes the expiry from GitHub's
  `GitHub-Authentication-Token-Expiration` header. A 404 means the token
  lacks the repository or the organization has not approved it; a 401
  means it is mistyped, expired or revoked.
- `Generator.Plan` runs a check limited to the credentials it makes (a
  `generation.format`, and no provisioner or `credforge generate`) and
  makes one only when every primary store is checked and missing; one some
  of whose stores hold a value is left, since nothing is read to copy it.
  `Generator.Apply` makes each value with `crypto/rand` and writes it
  through a `Creator` when the writer has one (SSM `PutParameter` without
  overwrite), so a value set after the check is never replaced.
- `install` reads the value hidden from a terminal, or from standard input
  with `--stdin --yes`; never from an argument. It confirms the plan before
  asking for the value.
- The master copy is named by an OmniVault URI on the credential (a tag or
  the targets file, not a value), read once into memory, written to each
  store, then zeroed where the language allows.
- Every write is a plan first. Nothing writes without `--apply` and a
  confirmation, or `--yes` in CI.

## Security

- No value is ever read from a store. Tests assert no observer calls a
  value-returning endpoint (`GetParameter`, `GetSecretValue`, secret
  contents).
- A value is read only by `install`, from the terminal or standard input,
  held in memory for the writes, and never printed, logged or saved; tests
  assert it is in no output and that the request to GitHub holds it only
  sealed.
- Tokens are read from the environment, never from flags, and never printed
  or logged; HTTP errors are reported without request headers.
- The targets file and reports contain names, accounts and dates. They are
  as sensitive as the registry and belong wherever it is kept.

## Testing

- `Compare` and `Record`: table tests for every rule, including grace edges,
  optional and planned credentials, organization secrets and multiple
  stores per credential.
- Connectors: `httptest` servers for GitHub; an interface over the SSM
  client's `DescribeParameters` for AWS. No live calls in unit tests; an
  opt-in live test reads one repository when a token is set.
- CLI: golden output for text and JSON, exit codes, and `--record` writing
  the expected events.
